"""Parse a raw RFC 5322 message into the fields the analyzer needs."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser

URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.I)


@dataclass
class Link:
    href: str
    text: str = ""


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int


@dataclass
class ParsedEmail:
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: list[str] = field(default_factory=list)
    auth: dict[str, str] = field(default_factory=dict)   # spf/dkim/dmarc -> pass|fail|softfail|none|...
    received_hops: int = 0
    text: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)

    @property
    def from_domain(self) -> str:
        return self.from_addr.rpartition("@")[2].lower()


class _LinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[Link] = []
        self.text_parts: list[str] = []
        self._href: str | None = None
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._buf = []

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append(Link(self._href.strip(), " ".join("".join(self._buf).split())))
            self._href = None

    def handle_data(self, data):
        self.text_parts.append(data)
        if self._href is not None:
            self._buf.append(data)


def _auth_results(msg: EmailMessage) -> dict[str, str]:
    raw = " ".join(str(v) for v in msg.get_all("Authentication-Results", []))
    out = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", raw, re.I)
        out[mech] = m.group(1).lower() if m else "none"
    if out["spf"] == "none":
        spf = str(msg.get("Received-SPF", ""))
        if spf:
            out["spf"] = spf.split()[0].lower()
    return out


def parse_bytes(raw: bytes) -> ParsedEmail:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
    name, addr = parseaddr(str(msg.get("From", "")))
    p = ParsedEmail(
        subject=str(msg.get("Subject", "")),
        from_name=name,
        from_addr=addr.lower(),
        reply_to=parseaddr(str(msg.get("Reply-To", "")))[1].lower(),
        return_path=parseaddr(str(msg.get("Return-Path", "")))[1].lower(),
        to=[a.lower() for _, a in getaddresses(msg.get_all("To", []) + msg.get_all("Cc", []))],
        auth=_auth_results(msg),
        received_hops=len(msg.get_all("Received", [])),
    )
    texts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        ctype = part.get_content_type()
        if filename or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            p.attachments.append(Attachment(filename or "unnamed", ctype, len(payload)))
            continue
        if ctype == "text/html":
            collector = _LinkCollector()
            collector.feed(part.get_content())
            p.links += collector.links
            texts.append(" ".join(collector.text_parts))
        elif ctype == "text/plain":
            body = part.get_content()
            texts.append(body)
            known = {link.href for link in p.links}
            p.links += [Link(u) for u in URL_RE.findall(body) if u not in known]
    p.text = " ".join(" ".join(texts).split())
    return p


def parse_file(path: str) -> ParsedEmail:
    with open(path, "rb") as f:
        return parse_bytes(f.read())
