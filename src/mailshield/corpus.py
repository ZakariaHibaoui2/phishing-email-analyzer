"""Synthetic labelled email corpus (raw .eml bytes) for training and tests.

Ham covers newsletters, receipts, meeting threads and *legitimate* security notices (the hard
negatives). Phishing covers credential lures, invoice/payment fraud, delivery scams and
CEO-fraud (BEC) - with and without obvious technical indicators.
"""
from __future__ import annotations

import random
from email.message import EmailMessage

ORG = "example.org"
NAMES = ["Sara", "Youssef", "Lina", "Omar", "Maya", "Adam", "Nora", "Karim", "Ines", "Samir"]

HAM_SUBJECTS = [
    "Weekly team sync notes", "Your order #{n} has shipped", "Invoice {n} from Acme Hosting (paid)",
    "Re: project timeline", "Lunch on Thursday?", "Newsletter: 5 Python tips this week",
    "Your monthly statement is available", "New sign-in to your account from Chrome on Windows",
    "Password changed successfully", "Reminder: quarterly review meeting", "Conference schedule {n}",
]
HAM_HARD_SUBJECTS = ["Action required: confirm your email to join the newsletter", "Your password expires in 7 days",
                     "Invoice {n} - payment due next week", "Security notice: please review your sign-in settings"]
HAM_BODIES = [
    "Hi {name}, attached are the notes from today's sync. Action items are listed at the end. Thanks!",
    "Good news! Your order is on its way and should arrive on Friday. You can view the order in your account.",
    "Thanks for your payment. This invoice has been paid in full; no action is needed.",
    "Following up on the timeline - can we move the review to next Tuesday afternoon?",
    "This week: f-strings, dataclasses, pathlib, typing and pytest fixtures. Happy coding!",
    "We noticed a new sign-in to your account. If this was you, you can ignore this message. "
    "If not, review your security settings from the official app.",
    "Your password was changed. If you made this change, no further action is needed.",
    "Please find the agenda for our quarterly review. Slides are in the shared drive as usual.",
    "Please confirm your email address to finish signing up. If you did not request this, ignore this email.",
    "Reminder: your company password expires in 7 days. Change it from the IT portal as usual.",
]
PHISH_SUBJECTS = [
    "URGENT: Your account will be suspended", "Action required: verify your mailbox within 24 hours",
    "Unusual sign-in activity detected", "Invoice #{n} overdue - final notice", "DHL: your parcel is on hold",
    "Payment declined - update your billing information", "Shared document: Q4 bonus plan.pdf",
    "Wire transfer needed today", "Your password expires today", "Security alert: confirm your identity",
]
PHISH_BODIES = [
    "Dear customer, we detected unusual activity. Verify your account immediately or it will be locked.",
    "Your mailbox storage is full. Confirm your password within 24 hours to avoid losing emails.",
    "Your parcel could not be delivered. Pay the customs fee of 1.99 EUR to release it: click below.",
    "Final notice: invoice attached is overdue. Open the attached file to review and pay immediately.",
    "Hi, are you available? I need you to process an urgent wire transfer today. Keep this confidential.",
    "Your payment method was declined. Update your billing information now to keep your subscription.",
    "A document has been shared with you. Sign in with your email password to view the document.",
    "Your password expires today. Click here to keep your current password.",
]
BRAND_SENDERS = [("PayPal", "paypal.com"), ("Microsoft 365", "microsoft.com"), ("Netflix", "netflix.com"),
                 ("DHL Express", "dhl.com"), ("Apple", "apple.com"), ("DocuSign", "docusign.net")]
BAD_DOMAINS = ["secure-mail-alerts.top", "account-verify.xyz", "notice-center.info", "mailbox-help.click",
               "billing-update.online", "parcel-track.live"]


def _auth(r: random.Random, good: bool) -> str:
    if good:
        return f"mx.{ORG}; spf=pass smtp.mailfrom=x; dkim=pass header.d=x; dmarc=pass"
    return r.choice([
        f"mx.{ORG}; spf=fail; dkim=none; dmarc=fail",
        f"mx.{ORG}; spf=softfail; dkim=fail; dmarc=fail",
        f"mx.{ORG}; spf=pass; dkim=pass; dmarc=pass",      # attacker's own domain passes SPF/DKIM
        f"mx.{ORG}; spf=none; dkim=none; dmarc=none",
    ])


def make_ham(r: random.Random) -> bytes:
    m = EmailMessage()
    brand, dom = r.choice(BRAND_SENDERS + [(r.choice(NAMES), ORG)] * 4)
    n = r.randint(1000, 99999)
    m["From"] = f"{brand} <no-reply@{dom}>"
    m["To"] = f"{r.choice(NAMES).lower()}@{ORG}"
    m["Subject"] = r.choice(HAM_HARD_SUBJECTS if r.random() < 0.2 else HAM_SUBJECTS).format(n=n)
    # forwarders and mailing lists legitimately break SPF; helpdesks use a different Reply-To
    m["Authentication-Results"] = (f"mx.{ORG}; spf=softfail; dkim=pass; dmarc=pass" if r.random() < 0.08
                                   else _auth(r, True))
    if r.random() < 0.10:
        m["Reply-To"] = f"support@{r.choice(['zendesk.com', 'freshdesk.com', 'helpscout.net'])}"
    for _ in range(r.randint(2, 4)):
        m["Received"] = f"from mail.{dom} by mx.{ORG}"
    body = r.choice(HAM_BODIES).format(name=r.choice(NAMES))
    url = f"{'http' if r.random() < 0.1 else 'https'}://www.{dom}/{r.choice(['account', 'orders', 'docs', 'blog'])}"
    m.set_content(f"{body}\n\n{url}\n")
    m.add_alternative(f"<p>{body}</p><p><a href='{url}'>www.{dom}</a></p>", subtype="html")
    if r.random() < 0.15:
        name = r.choice([f"report-{n}.pdf", f"photos-{n}.zip", "agenda.docx"])
        m.add_attachment(b"%PDF-1.4 report", maintype="application", subtype="octet-stream", filename=name)
    return bytes(m)


def make_polished_phish(r: random.Random) -> bytes:
    """Low-indicator phishing: attacker-owned domain with valid SPF/DKIM, no attachment, calm wording."""
    m = EmailMessage()
    dom = r.choice(["docs-share-portal.com", "hr-benefits-center.com", "payroll-review.net", "sharepoint-files.net"])
    m["From"] = f"{r.choice(NAMES)} <{r.choice(['hr', 'it', 'payroll', 'docs'])}@{dom}>"
    m["To"] = f"{r.choice(NAMES).lower()}@{ORG}"
    subjects = HAM_SUBJECTS + ["Updated benefits enrolment", "Document shared with you"]
    m["Subject"] = r.choice(subjects).format(n=r.randint(1, 999))
    m["Authentication-Results"] = f"mx.{ORG}; spf=pass; dkim=pass; dmarc=pass"
    body = r.choice([
        "Hello, please review the updated benefits document and sign in with your work account to acknowledge it.",
        "Hi, the file you requested is ready. Sign in with your email credentials to view it.",
        "Please review and approve the attached payroll changes by end of day using the secure portal.",
    ])
    href = f"https://{dom}/{r.choice(['view', 'portal', 's'])}/{r.randint(100, 999)}"
    m.set_content(f"{body}\n\n{href}\n")
    m.add_alternative(f"<p>{body}</p><p><a href='{href}'>Open document</a></p>", subtype="html")
    return bytes(m)


def make_phish(r: random.Random) -> bytes:
    m = EmailMessage()
    brand, real = r.choice(BRAND_SENDERS)
    bad = r.choice(BAD_DOMAINS)
    n = r.randint(1000, 99999)
    style = r.random()
    if style < 0.6:
        m["From"] = f"{brand} Support <no-reply@{bad}>"
    elif style < 0.8:   # spoofed real domain (DMARC should catch it)
        m["From"] = f"{brand} <security@{real}>"
    else:               # BEC: plausible colleague name, look-alike internal domain
        m["From"] = f"{r.choice(NAMES)} (CEO) <ceo@{ORG.replace('.', '-')}.co>"
    if r.random() < 0.5:
        m["Reply-To"] = f"help@{r.choice(BAD_DOMAINS)}"
    m["To"] = f"{r.choice(NAMES).lower()}@{ORG}"
    m["Subject"] = r.choice(HAM_SUBJECTS if r.random() < 0.15 else PHISH_SUBJECTS).format(n=n)
    m["Authentication-Results"] = _auth(r, False)
    m["Received"] = f"from unknown ({r.randint(1, 223)}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)})"
    body = r.choice(PHISH_BODIES)
    href = r.choice([f"http://{bad}/login", f"https://{brand.split()[0].lower()}.{bad}/verify",
                     f"http://{r.randint(11, 223)}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}/x"])
    shown = r.choice([f"https://www.{real}/account", "Verify now", "View document"])
    m.set_content(f"{body}\n\n{href}\n")
    m.add_alternative(f"<p>{body}</p><p><a href='{href}'>{shown}</a></p>", subtype="html")
    if r.random() < 0.3:
        name = r.choice(["invoice.html", f"Invoice_{n}.pdf.exe", "document.iso", "payment.js", "scan.zip"])
        m.add_attachment(b"MZ fake", maintype="application", subtype="octet-stream", filename=name)
    return bytes(m)


def generate(n: int = 2_000, phish_share: float = 0.4, seed: int = 21) -> tuple[list[bytes], list[int]]:
    r = random.Random(seed)
    msgs, labels = [], []
    for _ in range(n):
        is_p = r.random() < phish_share
        if is_p:
            msgs.append(make_polished_phish(r) if r.random() < 0.25 else make_phish(r))
        else:
            msgs.append(make_ham(r))
        labels.append(int(is_p))
    return msgs, labels
