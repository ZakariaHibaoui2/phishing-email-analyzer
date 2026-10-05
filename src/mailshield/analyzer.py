"""Combine header/link/attachment indicators with an NLP text model into one risk score."""
from __future__ import annotations

from dataclasses import asdict, dataclass

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from .checks import Finding, run_checks
from .corpus import generate
from .parser import ParsedEmail, parse_bytes


@dataclass
class Report:
    subject: str
    sender: str
    risk: int                 # 0-100
    verdict: str              # phishing | suspicious | clean
    text_probability: float   # NLP model P(phishing)
    findings: list[Finding]
    lure_terms: list[str]

    def as_dict(self) -> dict:
        return asdict(self)


class TextModel:
    """TF-IDF (word 1-2 grams) + logistic regression over subject and body."""

    def __init__(self) -> None:
        self.pipe = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, stop_words="english")),
            ("lr", LogisticRegression(max_iter=1000, C=4.0, class_weight="balanced")),
        ])

    @staticmethod
    def doc(e: ParsedEmail) -> str:
        return f"{e.subject} {e.text}"

    def fit(self, emails: list[ParsedEmail], labels: list[int]) -> TextModel:
        self.pipe.fit([self.doc(e) for e in emails], labels)
        return self

    def proba(self, e: ParsedEmail) -> float:
        return float(self.pipe.predict_proba([self.doc(e)])[0, 1])

    def top_terms(self, e: ParsedEmail, k: int = 5) -> list[str]:
        tfidf, lr = self.pipe.named_steps["tfidf"], self.pipe.named_steps["lr"]
        vec = tfidf.transform([self.doc(e)])
        contrib = vec.multiply(lr.coef_[0]).toarray()[0]
        names = tfidf.get_feature_names_out()
        idx = np.argsort(contrib)[::-1][:k]
        return [names[i] for i in idx if contrib[i] > 0]


class Analyzer:
    def __init__(self, text_model: TextModel | None = None, text_weight: float = 40.0) -> None:
        self.text_model = text_model or default_text_model()
        self.text_weight = text_weight

    def analyze(self, raw: bytes) -> Report:
        e = parse_bytes(raw)
        findings = run_checks(e)
        p_text = self.text_model.proba(e)
        rule_points = sum(f.points for f in findings)
        risk = int(min(100, round(rule_points * 0.8 + p_text * self.text_weight)))
        high = any(f.severity == "high" for f in findings)
        verdict = "phishing" if risk >= 60 or (high and risk >= 45) else "suspicious" if risk >= 30 else "clean"
        return Report(e.subject, e.from_addr, risk, verdict, round(p_text, 3), findings,
                      self.text_model.top_terms(e) if p_text > 0.5 else [])


def default_text_model(n: int = 2_500, seed: int = 21) -> TextModel:
    msgs, labels = generate(n, seed=seed)
    return TextModel().fit([parse_bytes(m) for m in msgs], labels)
