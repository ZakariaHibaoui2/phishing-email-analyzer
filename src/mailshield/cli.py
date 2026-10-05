"""mailshield command line."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import Analyzer, TextModel
from .corpus import generate
from .parser import parse_bytes

COLORS = {"phishing": "\033[91m", "suspicious": "\033[93m", "clean": "\033[92m"}
RESET = "\033[0m"


def _print(report, color: bool) -> None:
    c, r = (COLORS[report.verdict], RESET) if color else ("", "")
    print(f"{c}{report.verdict.upper()}{r}  risk {report.risk}/100   NLP p={report.text_probability:.2f}")
    print(f"  From   : {report.sender}")
    print(f"  Subject: {report.subject}")
    for f in sorted(report.findings, key=lambda x: -x.points):
        print(f"  [{f.severity:<6}] +{f.points:<3} {f.detail}")
    if report.lure_terms:
        print(f"  lure terms: {', '.join(report.lure_terms)}")


def cmd_evaluate(n: int) -> None:
    from sklearn.metrics import classification_report, roc_auc_score

    train_msgs, train_y = generate(n, seed=1)
    test_msgs, test_y = generate(n // 2, seed=2)
    analyzer = Analyzer(TextModel().fit([parse_bytes(m) for m in train_msgs], train_y))
    reports = [analyzer.analyze(m) for m in test_msgs]
    pred = [int(rep.verdict != "clean") for rep in reports]
    print(classification_report(test_y, pred, target_names=["ham", "phishing"], digits=3))
    print(f"ROC-AUC (risk score): {roc_auc_score(test_y, [rep.risk for rep in reports]):.4f}")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="mailshield", description="Phishing email analyzer")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyze one or more .eml files")
    a.add_argument("files", nargs="+")
    a.add_argument("--json", action="store_true")
    a.add_argument("--no-color", action="store_true")
    e = sub.add_parser("evaluate", help="train on one synthetic corpus, test on another")
    e.add_argument("-n", type=int, default=3000)
    s = sub.add_parser("samples", help="write example .eml files to a folder")
    s.add_argument("folder")
    args = p.parse_args(argv)

    if args.cmd == "analyze":
        analyzer = Analyzer()
        worst = 0
        for path in args.files:
            report = analyzer.analyze(Path(path).read_bytes())
            worst = max(worst, report.risk)
            if args.json:
                print(json.dumps(report.as_dict(), default=str))
            else:
                print(f"== {path}")
                _print(report, color=not args.no_color and sys.stdout.isatty())
        sys.exit(2 if worst >= 60 else 0)
    elif args.cmd == "evaluate":
        cmd_evaluate(args.n)
    elif args.cmd == "samples":
        import random

        from .corpus import make_ham, make_phish

        out = Path(args.folder)
        out.mkdir(parents=True, exist_ok=True)
        r = random.Random(5)
        for i in range(3):
            (out / f"ham_{i}.eml").write_bytes(make_ham(r))
            (out / f"phish_{i}.eml").write_bytes(make_phish(r))
        print(f"wrote 6 samples to {out}")


if __name__ == "__main__":
    main()
