"""Model lifecycle: CANDIDATE -> (gate) -> APPROVED by a human reviewer -> ACTIVE (with rollback).
Training NEVER activates anything, and nothing here runs per-request: the runtime only reads the
ACTIVE row. Production behaviour changes only through this explicit, audited workflow."""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import numpy as np

from ..clock import Clock
from ..common import Sensitivity
from ..db import Database
from ..errors import ModelUnavailable
from . import corpus
from .model import LinearModel, ctx_string, featurize, load_verified, sha256_file
from .train import _X, metrics

GATE = {"max_fpr_adversarial": 0.10, "max_fpr_heldout": 0.05, "max_recall_regression": 0.05, "max_prauc_regression": 0.05}


class ModelRegistry:
    def __init__(self, db: Database, clock: Clock, model_dir: Path):
        self.db, self.clock, self.dir = db, clock, Path(model_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    def register_candidate(self, artifact: Path) -> str:
        artifact = Path(artifact)
        model = load_verified(artifact, sha256_file(artifact))          # schema-validates before registering
        dest = self.dir / artifact.name
        if artifact.resolve() != dest.resolve():
            shutil.copy2(artifact, dest)
        with self.db.tx() as c:
            c.execute("INSERT INTO model_registry(version,sha256,path,status,created_at) VALUES(?,?,?,?,?)",
                      (model.version, sha256_file(dest), str(dest), "CANDIDATE", self.clock.now()))
        return model.version

    def _row(self, c, version):
        r = c.execute("SELECT * FROM model_registry WHERE version=?", (version,)).fetchone()
        if r is None:
            raise ModelUnavailable(f"unknown model {version}")
        return dict(r)

    def evaluate_gate(self, version: str) -> tuple[bool, dict]:
        """Recompute metrics from the artifact against the FIXED suites (never trust a stored report)."""
        with self.db.read() as c:
            row = self._row(c, version)
        model = load_verified(row["path"], row["sha256"])
        from .train import group_split
        thr = model.threshold
        adv = corpus.load("adversarial_eval_v1")
        held = group_split(corpus.load("curated_train_v1"))["test"]
        out = {}
        for k, rows in (("adversarial", adv), ("heldout", held)):
            out[k] = metrics([r["label"] for r in rows], model.proba(_X(rows)), thr, n_boot=200)
        reasons = []
        if out["adversarial"]["fpr"] > GATE["max_fpr_adversarial"]:
            reasons.append("false-positive rate on adversarial benign cases too high")
        if out["heldout"]["fpr"] > GATE["max_fpr_heldout"]:
            reasons.append("false-positive rate on held-out benign cases too high")
        with self.db.read() as c:
            act = c.execute("SELECT * FROM model_registry WHERE status='ACTIVE'").fetchone()
        if act is not None:
            try:
                prev = load_verified(act["path"], act["sha256"])
                pm = metrics([r["label"] for r in adv], prev.proba(_X(adv)), prev.threshold, n_boot=50)
                if out["adversarial"]["recall"] < pm["recall"] - GATE["max_recall_regression"]:
                    reasons.append("recall regression vs active model on adversarial suite")
                if out["adversarial"]["pr_auc"] < pm["pr_auc"] - GATE["max_prauc_regression"]:
                    reasons.append("PR-AUC regression vs active model on adversarial suite")
            except ModelUnavailable:
                pass
        passed = not reasons
        with self.db.tx() as c:
            c.execute("UPDATE model_registry SET status=?, metrics_json=? WHERE version=? AND status IN ('CANDIDATE','REJECTED')",
                      ("CANDIDATE" if passed else "REJECTED", json.dumps({"gate": out, "passed": passed, "reasons": reasons}), version))
        return passed, {"metrics": out, "reasons": reasons}

    def approve(self, version: str, reviewer_id: str) -> None:
        with self.db.tx() as c:
            row = self._row(c, version)
            m = json.loads(row["metrics_json"] or "{}")
            if row["status"] != "CANDIDATE" or not m.get("passed"):
                raise ModelUnavailable("only candidates that passed the gate can be approved")
            c.execute("UPDATE model_registry SET status='APPROVED', approved_by=? WHERE version=?", (reviewer_id, version))

    def activate(self, version: str) -> None:
        with self.db.tx() as c:
            row = self._row(c, version)
            if row["status"] != "APPROVED":
                raise ModelUnavailable("only APPROVED models can be activated")
            load_verified(row["path"], row["sha256"])                      # refuse to activate a corrupt artifact
            prev = c.execute("SELECT version FROM model_registry WHERE status='ACTIVE'").fetchone()
            if prev:
                c.execute("UPDATE model_registry SET status='RETIRED' WHERE version=?", (prev["version"],))
            c.execute("UPDATE model_registry SET status='ACTIVE', activated_at=?, previous_active=? WHERE version=?",
                      (self.clock.now(), prev["version"] if prev else None, version))

    def rollback(self) -> str:
        with self.db.tx() as c:
            cur = c.execute("SELECT * FROM model_registry WHERE status='ACTIVE'").fetchone()
            if cur is None or not cur["previous_active"]:
                raise ModelUnavailable("nothing to roll back to")
            prev = self._row(c, cur["previous_active"])
            load_verified(prev["path"], prev["sha256"])
            c.execute("UPDATE model_registry SET status='RETIRED' WHERE version=?", (cur["version"],))
            c.execute("UPDATE model_registry SET status='ACTIVE', activated_at=? WHERE version=?", (self.clock.now(), prev["version"]))
            return prev["version"]

    def list(self) -> list[dict]:
        with self.db.read() as c:
            return [dict(r) for r in c.execute("SELECT version,status,sha256,created_at,approved_by,activated_at,previous_active,metrics_json FROM model_registry ORDER BY created_at DESC")]


class RegistryAdvisor:
    """Runtime view of the ACTIVE model. Any problem (none active, hash mismatch, bad schema,
    inference error) => ModelUnavailable. It never returns a default score like the legacy 50."""
    def __init__(self, registry: ModelRegistry):
        self.reg = registry
        self._model: LinearModel | None = None
        self._stat: tuple | None = None

    def _current(self) -> LinearModel:
        with self.reg.db.read() as c:
            row = c.execute("SELECT version,sha256,path FROM model_registry WHERE status='ACTIVE'").fetchone()
        if row is None:
            self._model = None
            raise ModelUnavailable("no active model")
        p = Path(row["path"])
        try:
            st = (row["sha256"], p.stat().st_mtime_ns, p.stat().st_size)
        except OSError as e:
            self._model = None
            raise ModelUnavailable("model file missing") from e
        if self._model is None or st != self._stat:                        # re-verify whenever the file or row changes
            self._model = load_verified(p, row["sha256"])
            self._stat = st
        return self._model

    @property
    def available(self) -> bool:
        try:
            self._current(); return True
        except ModelUnavailable:
            return False

    @property
    def version(self) -> str | None:
        try:
            return self._current().version
        except ModelUnavailable:
            return None

    def score(self, text: str, *, tool: str, sensitivity: Sensitivity | int, source: str) -> float:
        m = self._current()
        try:
            p = m.predict_proba_text(text or "", source, tool)
        except Exception as e:  # noqa: BLE001
            raise ModelUnavailable("inference failed") from e
        if not (0.0 <= p <= 1.0) or p != p:
            raise ModelUnavailable("invalid score")
        return p
