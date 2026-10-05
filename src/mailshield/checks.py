"""Deterministic phishing indicators with weights (0-100 points each)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .parser import ParsedEmail

BRANDS = {
    "paypal": "paypal.com", "microsoft": "microsoft.com", "office 365": "microsoft.com", "outlook": "microsoft.com",
    "apple": "apple.com", "amazon": "amazon.com", "netflix": "netflix.com", "dhl": "dhl.com",
    "docusign": "docusign.net", "google": "google.com", "bank of america": "bankofamerica.com",
    "linkedin": "linkedin.com", "dropbox": "dropbox.com", "fedex": "fedex.com",
}
RISKY_EXTENSIONS = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".iso", ".img", ".lnk",
                    ".html", ".htm", ".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z", ".one")
URGENCY = re.compile(
    r"\b(urgent|immediately|within 24 hours|suspend(ed)?|verify your|confirm your|unusual (sign-in|activity)|"
    r"final notice|account (will be )?(locked|closed)|action required|password (expires|expired))\b", re.I)


@dataclass
class Finding:
    id: str
    severity: str   # low | medium | high
    points: int
    detail: str


def _domain(addr_or_url: str) -> str:
    if "://" in addr_or_url:
        return (urlsplit(addr_or_url).hostname or "").lower()
    return addr_or_url.rpartition("@")[2].lower()


def _registered(domain: str) -> str:
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def run_checks(e: ParsedEmail) -> list[Finding]:
    f: list[Finding] = []
    auth = e.auth
    if auth.get("dmarc") == "fail":
        f.append(Finding("dmarc_fail", "high", 30, "DMARC failed: sender domain is likely spoofed"))
    if auth.get("spf") in {"fail", "softfail"}:
        f.append(Finding("spf_fail", "medium", 15, f"SPF {auth['spf']}: sending server not authorised"))
    if auth.get("dkim") == "fail":
        f.append(Finding("dkim_fail", "medium", 15, "DKIM signature invalid"))
    if all(auth.get(k) in {None, "none"} for k in ("spf", "dkim", "dmarc")):
        f.append(Finding("no_auth", "low", 5, "no SPF/DKIM/DMARC results recorded"))

    if e.reply_to and _registered(_domain(e.reply_to)) != _registered(e.from_domain):
        f.append(Finding("reply_to_mismatch", "medium", 20,
                         f"Reply-To ({e.reply_to}) differs from From domain ({e.from_domain})"))
    if e.return_path and _registered(_domain(e.return_path)) != _registered(e.from_domain):
        f.append(Finding("return_path_mismatch", "low", 8, "Return-Path domain differs from From domain"))

    display = e.from_name.lower()
    for brand, official in BRANDS.items():
        if brand in display and not e.from_domain.endswith(official):
            f.append(Finding("display_name_spoof", "high", 25,
                             f"display name claims '{brand}' but mail comes from {e.from_domain}"))
            break

    for link in e.links:
        href_dom = _registered(_domain(link.href))
        shown = re.search(r"(https?://)?([a-z0-9.-]+\.[a-z]{2,})", link.text.lower())
        if href_dom and shown and _registered(shown.group(2)) != href_dom:
            f.append(Finding("deceptive_link", "high", 25,
                             f"link text shows '{shown.group(2)}' but points to '{href_dom}'"))
            break
    hosts = {_domain(link.href) for link in e.links if link.href.startswith("http")}
    if any(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", h) for h in hosts):
        f.append(Finding("ip_link", "high", 20, "link points to a raw IP address"))
    if any(link.href.lower().startswith("http://") for link in e.links):
        f.append(Finding("insecure_link", "low", 5, "contains non-HTTPS links"))

    for a in e.attachments:
        name = a.filename.lower()
        if name.endswith(RISKY_EXTENSIONS):
            f.append(Finding("risky_attachment", "high", 30, f"risky attachment: {a.filename}"))
            break
        if re.search(r"\.(pdf|docx?|xlsx?|jpg)\.(exe|js|scr|html?)$", name):
            f.append(Finding("double_extension", "high", 35, f"double extension: {a.filename}"))
            break

    hits = {m.group(0).lower() for m in URGENCY.finditer(f"{e.subject} {e.text}")}
    if hits:
        f.append(Finding("urgency", "medium" if len(hits) > 1 else "low", min(10 * len(hits), 25),
                         "pressure language: " + ", ".join(sorted(hits)[:4])))
    if len(e.to) > 20:
        f.append(Finding("mass_recipients", "low", 5, f"{len(e.to)} visible recipients"))
    return f
