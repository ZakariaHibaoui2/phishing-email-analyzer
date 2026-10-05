import random
from email.message import EmailMessage

import pytest

from mailshield.analyzer import Analyzer, TextModel
from mailshield.checks import run_checks
from mailshield.cli import main
from mailshield.corpus import generate, make_ham, make_phish
from mailshield.parser import parse_bytes


def _msg(**kw) -> bytes:
    m = EmailMessage()
    m["From"] = kw.get("sender", "Alice <alice@example.org>")
    m["To"] = "bob@example.org"
    m["Subject"] = kw.get("subject", "Hello")
    if "reply_to" in kw:
        m["Reply-To"] = kw["reply_to"]
    m["Authentication-Results"] = kw.get("auth", "mx; spf=pass; dkim=pass; dmarc=pass")
    m.set_content(kw.get("text", "See you tomorrow."))
    if "html" in kw:
        m.add_alternative(kw["html"], subtype="html")
    if "attachment" in kw:
        m.add_attachment(b"x", maintype="application", subtype="octet-stream", filename=kw["attachment"])
    return bytes(m)


@pytest.fixture(scope="module")
def analyzer():
    msgs, y = generate(1200, seed=4)
    return Analyzer(TextModel().fit([parse_bytes(m) for m in msgs], y))


def ids(raw):
    return {f.id for f in run_checks(parse_bytes(raw))}


def test_parser_extracts_fields():
    raw = _msg(html="<p>Hi <a href='https://evil.top/x'>https://www.paypal.com</a></p>", attachment="a.pdf")
    e = parse_bytes(raw)
    assert e.from_addr == "alice@example.org" and e.from_domain == "example.org"
    assert e.auth == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert any(link.href == "https://evil.top/x" and "paypal" in link.text for link in e.links)
    assert e.attachments[0].filename == "a.pdf"


def test_clean_message_has_no_high_findings():
    assert not {f for f in run_checks(parse_bytes(_msg())) if f.severity == "high"}


def test_auth_failures():
    assert {"dmarc_fail", "spf_fail", "dkim_fail"} <= ids(_msg(auth="mx; spf=fail; dkim=fail; dmarc=fail"))


def test_reply_to_mismatch():
    assert "reply_to_mismatch" in ids(_msg(reply_to="x@other.top"))


def test_display_name_spoof():
    assert "display_name_spoof" in ids(_msg(sender="PayPal Service <service@pp-alerts.top>"))
    assert "display_name_spoof" not in ids(_msg(sender="PayPal <service@paypal.com>"))


def test_deceptive_link():
    html = "<a href='http://login-check.top/a'>https://www.microsoft.com/account</a>"
    assert "deceptive_link" in ids(_msg(html=html))


@pytest.mark.parametrize("name,check", [("invoice.pdf.exe", "risky_attachment"), ("scan.html", "risky_attachment"),
                                        ("payroll.docm", "risky_attachment")])
def test_risky_attachments(name, check):
    assert check in ids(_msg(attachment=name))


def test_urgency():
    assert "urgency" in ids(_msg(subject="URGENT action required", text="Verify your account immediately"))


def test_end_to_end_verdicts(analyzer):
    r = random.Random(99)
    assert analyzer.analyze(make_phish(r)).verdict in {"phishing", "suspicious"}
    assert analyzer.analyze(make_ham(r)).verdict == "clean"


def test_detection_quality(analyzer):
    msgs, y = generate(600, seed=77)
    pred = [int(analyzer.analyze(m).verdict != "clean") for m in msgs]
    tp = sum(p and t for p, t in zip(pred, y))
    fp = sum(p and not t for p, t in zip(pred, y))
    recall = tp / sum(y)
    fpr = fp / (len(y) - sum(y))
    assert recall > 0.95 and fpr < 0.05


def test_cli(tmp_path, capsys):
    main(["samples", str(tmp_path)])
    with pytest.raises(SystemExit):
        main(["analyze", "--no-color", str(tmp_path / "phish_0.eml"), str(tmp_path / "ham_0.eml")])
    out = capsys.readouterr().out
    assert "risk" in out and "From" in out
