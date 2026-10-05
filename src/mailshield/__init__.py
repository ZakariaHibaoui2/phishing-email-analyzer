"""Phishing email analyzer: parses raw .eml, checks SPF/DKIM/DMARC, spoofing, deceptive links and risky
attachments, and combines them with an NLP classifier into an explained risk score.
"""

__version__ = "1.0.0"
