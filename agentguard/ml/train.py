"""Reproducible training + evaluation. Usage:  python -m agentguard.ml.train --out data/models"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, confusion_matrix

from . import corpus
from .model import FEATURE_SCHEMA, LinearModel, ctx_string, featurize

SEED = 1234


def dataset_hash(rows: list[dict]) -> str:
    return hashlib.sha256("\n".join(json.dumps(r, sort_keys=True) for r in rows).encode()).hexdigest()


def validate_dataset(rows: list[dict]) -> list[str]:
    problems, seen = [], set()
    for r in rows:
        if r.get("label") not in (0, 1) or not r.get("text") or not r.get("family"):
            problems.append(f"bad row {r.get('id')}")
        key = (r["text"].strip().lower())
        if key in seen:
            problems.append(f"duplicate text {r.get('id')}")
        seen.add(key)
    return problems


def group_split(rows: list[dict], seed: int = SEED, frac=(0.6, 0.2, 0.2)):
    """Split by FAMILY (scenario) so near-duplicate variants never straddle train/val/test; stratified by label."""
    rng = np.random.RandomState(seed)
    fams = {0: sorted({r["family"] for r in rows if r["label"] == 0}), 1: sorted({r["family"] for r in rows if r["label"] == 1})}
    assign: dict[str, str] = {}
    for lab, fs in fams.items():
        fs = list(fs); rng.shuffle(fs)
        n = len(fs); a, b = int(round(frac[0] * n)), int(round((frac[0] + frac[1]) * n))
        for i, f in enumerate(fs):
            assign[f] = "train" if i < a else "val" if i < b else "test"
    return {k: [r for r in rows if assign[r["family"]] == k] for k in ("train", "val", "test")}


def _X(rows):
    return featurize([r["text"] for r in rows], [ctx_string(r["source"], r["tool"]) for r in rows])


def metrics(y, p, thr, n_boot: int = 1000, seed: int = SEED) -> dict:
    y, p = np.asarray(y), np.asarray(p)
    def point(y_, p_):
        pred = p_ >= thr
        tp = int(((pred == 1) & (y_ == 1)).sum()); fp = int(((pred == 1) & (y_ == 0)).sum())
        fn = int(((pred == 0) & (y_ == 1)).sum()); tn = int(((pred == 0) & (y_ == 0)).sum())
        return {"precision": tp / (tp + fp) if tp + fp else float("nan"), "recall": tp / (tp + fn) if tp + fn else float("nan"),
                "fpr": fp / (fp + tn) if fp + tn else float("nan"), "tp": tp, "fp": fp, "fn": fn, "tn": tn}
    m = point(y, p)
    m["pr_auc"] = float(average_precision_score(y, p)) if y.sum() and (1 - y).sum() else float("nan")
    m["confusion_matrix"] = [[m["tn"], m["fp"]], [m["fn"], m["tp"]]]
    m["n"] = int(len(y))
    rng = np.random.RandomState(seed); cis: dict[str, list] = {k: [] for k in ("precision", "recall", "fpr")}
    for _ in range(n_boot):
        idx = rng.randint(0, len(y), len(y))
        pt = point(y[idx], p[idx])
        for k in cis:
            if not np.isnan(pt[k]):
                cis[k].append(pt[k])
    m["ci95"] = {k: ([float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] if len(v) > 20 else None) for k, v in cis.items()}
    return m


def pick_threshold(y, p, max_fpr: float = 0.02) -> float:
    """Highest-recall threshold on VALIDATION data subject to FPR <= max_fpr (a security-use-case choice)."""
    best, y, p = 1.0, np.asarray(y), np.asarray(p)
    for t in sorted(set(p.tolist()) | {0.5}):
        pred = p >= t
        fp = ((pred == 1) & (y == 0)).sum(); tn = ((pred == 0) & (y == 0)).sum()
        fpr = fp / max(1, fp + tn)
        if fpr <= max_fpr:
            best = min(best, t)
    return float(best)


def regex_baseline(rows: list[dict]) -> np.ndarray:
    from ..common import ContentItem
    from ..detection.base import DetectionInput, DetectorSuite
    from ..detection.patterns import PatternDetector
    from ..detection.structural import StructuralDetector
    suite = DetectorSuite([PatternDetector(), StructuralDetector()])
    out = []
    for r in rows:
        inp = DetectionInput(r["text"] if r["source"] == "user" else "", (ContentItem("c", r["text"]),) if r["source"] != "user" else (), {}, "x")
        out.append(max([s.severity for s in suite.run(inp)], default=0.0))
    return np.array(out)


def train(out_dir: Path, *, train_name="curated_train_v1", eval_name="adversarial_eval_v1", max_fpr=0.02, C=3.0) -> dict:
    rows, adv = corpus.load(train_name), corpus.load(eval_name)
    probs = validate_dataset(rows) + validate_dataset(adv)
    if probs:
        raise ValueError(f"dataset validation failed: {probs[:5]}")
    leak = {r["family"] for r in rows} & {r["family"] for r in adv}, {r["text"].lower() for r in rows} & {r["text"].lower() for r in adv}
    if leak[0] or leak[1]:
        raise ValueError(f"train/eval leakage: {leak}")
    sp = group_split(rows)
    clf = LogisticRegression(C=C, class_weight="balanced", max_iter=2000, random_state=SEED)
    clf.fit(_X(sp["train"]), [r["label"] for r in sp["train"]])
    w, b0 = np.asarray(clf.coef_[0]), float(clf.intercept_[0])
    # Platt calibration on the VALIDATION split only (never on train data)
    zv = _X(sp["val"]) @ w + b0
    cal = LogisticRegression(C=1e6, max_iter=1000).fit(zv.reshape(-1, 1), [r["label"] for r in sp["val"]])
    a, b = float(cal.coef_[0][0]), float(cal.intercept_[0])
    meta = {"feature_schema": FEATURE_SCHEMA, "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "seed": SEED,
            "train_dataset": train_name, "train_dataset_sha256": dataset_hash(rows), "eval_dataset": eval_name,
            "eval_dataset_sha256": dataset_hash(adv), "n_train": len(sp["train"]), "n_val": len(sp["val"]), "n_test": len(sp["test"]),
            "data_review_status": "UNREVIEWED (authored; not independently reviewed)", "target": "P(text is an injection/exfiltration attempt)"}
    m0 = LinearModel(meta, w, b0, a, b, 0.5)
    thr = pick_threshold([r["label"] for r in sp["val"]], m0.proba(_X(sp["val"])), max_fpr)
    model = LinearModel(meta, w, b0, a, b, thr)
    report: dict = {"threshold": thr, "threshold_rule": f"min threshold with validation FPR <= {max_fpr}"}
    for name, part in (("held_out_test_family_split", sp["test"]), ("adversarial_eval", adv)):
        y = [r["label"] for r in part]
        report[name] = {"ml": metrics(y, model.proba(_X(part)), thr),
                        "regex_baseline": metrics(y, regex_baseline(part), 0.4)}
    meta["version"] = "m-" + hashlib.sha256(model.to_json().encode()).hexdigest()[:12]
    model = LinearModel(meta, w, b0, a, b, thr)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{meta['version']}.json"
    path.write_text(model.to_json())
    (out_dir / f"{meta['version']}.report.json").write_text(json.dumps(report, indent=2, sort_keys=True))
    return {"version": meta["version"], "path": str(path), "report": report}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default="data/models"); a = ap.parse_args()
    res = train(Path(a.out))
    print(json.dumps({"version": res["version"], "path": res["path"]}, indent=2))
    for k in ("held_out_test_family_split", "adversarial_eval"):
        for who in ("ml", "regex_baseline"):
            m = res["report"][k][who]
            print(f"{k:28s} {who:15s} n={m['n']:3d} precision={m['precision']:.2f} recall={m['recall']:.2f} fpr={m['fpr']:.2f} prauc={m['pr_auc']:.2f} cm={m['confusion_matrix']}")
