# MailShield — Phishing Email Analyzer

> Analyzes raw `.eml` messages the way a SOC analyst would. It checks sender authentication (SPF/DKIM/DMARC), spoofing, deceptive links, and dangerous attachments, then adds an NLP model for social-engineering language. The result is a 0–100 risk score with every finding explained.

[![CI](https://github.com/ZakariaHibaoui2/phishing-email-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/ZakariaHibaoui2/phishing-email-analyzer/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?logo=scikitlearn&logoColor=white)
![Email](https://img.shields.io/badge/RFC%205322-parsing-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Demo

```text
$ mailshield analyze examples/phish_0.eml
PHISHING  risk 100/100   NLP p=0.99
  From   : no-reply@secure-mail-alerts.top
  Subject: Security alert: confirm your identity
  [high  ] +30  DMARC failed: sender domain is likely spoofed
  [high  ] +25  display name claims 'microsoft' but mail comes from secure-mail-alerts.top
  [high  ] +25  link text shows 'www.microsoft.com' but points to 'secure-mail-alerts.top'
  [medium] +20  Reply-To (help@billing-update.online) differs from From domain
  [medium] +15  SPF softfail: sending server not authorised
  [medium] +15  DKIM signature invalid
  [low   ] +10  pressure language: confirm your

$ mailshield analyze examples/phish_polished.eml       # valid SPF/DKIM/DMARC, no attachment
SUSPICIOUS  risk 40/100   NLP p=0.99
  From   : docs@hr-benefits-center.com
  lure terms: document, benefits, updated benefits, review updated
```

The second example is why there are two layers. A well-prepared attacker who owns their domain passes every technical check, and only the **language model** notices the credential lure.

## Detection layers

| Layer | Checks |
|---|---|
| **Authentication** | `Authentication-Results` / `Received-SPF`: DMARC fail, SPF fail/softfail, DKIM fail, missing auth |
| **Identity** | Reply-To and Return-Path domain mismatch, display-name brand spoofing (`"PayPal" <x@evil.top>`) |
| **Links** | visible text vs real `href` mismatch, raw-IP links, plain-HTTP links |
| **Attachments** | executables/scripts/ISO/HTML/macro documents, double extensions (`invoice.pdf.exe`) |
| **Language** | urgency and pressure patterns (regex) + **TF-IDF + logistic regression** classifier with top contributing terms |

`risk = 0.8 × rule points + 40 × P_nlp` (capped at 100) → **phishing** ≥ 60 (or ≥ 45 with a high-severity finding), **suspicious** ≥ 30, otherwise **clean**.

## Results

`mailshield evaluate -n 3000`: trained on one synthetic corpus and tested on a **different** one (different seed):

| | Precision | Recall | F1 |
|---|---|---|---|
| Ham | 1.000 | 0.965 | 0.982 |
| Phishing | 0.953 | **1.000** | 0.976 |

ROC-AUC of the risk score: **0.998**.

The corpus is intentionally messy:
- **Legitimate mail** includes helpdesk Reply-To domains, forwarders that break SPF, `.zip` attachments, real "confirm your email" and password-expiry notices.
- **Phishing** includes BEC (CEO fraud) and *polished* campaigns that pass SPF/DKIM/DMARC and borrow ordinary subjects.

The 3.5% ham false-positive rate comes mostly from those hard legitimate cases.

## Usage

```bash
pip install -e ".[dev]"
mailshield analyze suspicious.eml                 # human-readable report (exit code 2 if phishing)
mailshield analyze --json *.eml > report.jsonl    # machine-readable
mailshield samples ./examples                     # generate sample messages
mailshield evaluate                               # metrics
```

Use it as a library:

```python
from mailshield.analyzer import Analyzer
report = Analyzer().analyze(open("mail.eml", "rb").read())
print(report.verdict, report.risk, [f.detail for f in report.findings])
```

Export a message from Outlook/Gmail as `.eml` ("Download message" / "Show original") to analyze it.

## Project structure

```
src/mailshield/
├── parser.py     # MIME parsing: headers, auth results, HTML link text vs href, attachments
├── checks.py     # weighted indicators (auth, identity, links, attachments, urgency)
├── analyzer.py   # NLP model + score fusion + report
├── corpus.py     # synthetic labelled .eml generator (ham, phishing, BEC, polished phishing)
└── cli.py
examples/         # sample .eml files (all fictional, example domains)
tests/            # 13 tests
```

## License

[MIT](LICENSE)
