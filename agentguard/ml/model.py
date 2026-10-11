"""Pickle-free model artifact: hashed char-n-gram logistic regression stored as JSON.

Why not joblib? Loading a pickle executes arbitrary code. The legacy project loaded
security_model.joblib at import time with no integrity check. Here the artifact is plain JSON
(schema-validated, size-limited, finite-number-checked) and its SHA-256 must match the registry row.
Feature extraction (sklearn HashingVectorizer) is stateless, so nothing but numbers is stored.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import HashingVectorizer

from ..errors import ModelUnavailable

SCHEMA = "agentguard-linear-1"
FEATURE_SCHEMA = "fs-1"       # char_wb 3-5grams (2^15) of text + word token (2^8) for content source
N_TEXT, N_CTX = 2 ** 15, 2 ** 8
MAX_ARTIFACT_BYTES = 5 * 1024 * 1024

_TEXT = HashingVectorizer(analyzer="char_wb", ngram_range=(3, 5), n_features=N_TEXT, alternate_sign=False, norm="l2", lowercase=True)
_CTX = HashingVectorizer(analyzer="word", token_pattern=r"\S+", n_features=N_CTX, alternate_sign=False, norm="l2", lowercase=True)


def featurize(texts: list[str], contexts: list[str]) -> sparse.csr_matrix:
    return sparse.hstack([_TEXT.transform(texts), _CTX.transform(contexts)], format="csr")


def ctx_string(source: str, tool: str) -> str:
    """Only the content *source* is used. `tool` is deliberately NOT a feature: in the authored corpus it
    correlated with the label (shortcut learning, caught by test_lifecycle...), and tool risk is handled
    deterministically by policy/risk, not by the model."""
    return f"src_{source}"


class LinearModel:
    def __init__(self, meta: dict[str, Any], w: np.ndarray, intercept: float, a: float, b: float, threshold: float):
        self.meta, self.w, self.intercept, self.a, self.b, self.threshold = meta, w, intercept, a, b, threshold

    @property
    def version(self) -> str:
        return self.meta["version"]

    def decision(self, X: sparse.csr_matrix) -> np.ndarray:
        return X @ self.w + self.intercept

    def proba(self, X: sparse.csr_matrix) -> np.ndarray:
        z = self.a * self.decision(X) + self.b                    # Platt scaling fit on a held-out validation split
        return 1.0 / (1.0 + np.exp(-np.clip(z, -30, 30)))

    def predict_proba_text(self, text: str, source: str, tool: str) -> float:
        return float(self.proba(featurize([text], [ctx_string(source, tool)]))[0])

    # ---- (de)serialisation ----
    def to_json(self) -> str:
        nz = np.nonzero(self.w)[0]
        doc = {"schema": SCHEMA, "feature_schema": FEATURE_SCHEMA, "meta": self.meta, "n_features": N_TEXT + N_CTX,
               "intercept": self.intercept, "calibration": {"a": self.a, "b": self.b}, "threshold": self.threshold,
               "weights": {str(int(i)): float(self.w[i]) for i in nz}}
        return json.dumps(doc, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> "LinearModel":
        try:
            d = json.loads(text)
            if d["schema"] != SCHEMA or d["feature_schema"] != FEATURE_SCHEMA or d["n_features"] != N_TEXT + N_CTX:
                raise ValueError("incompatible schema")
            w = np.zeros(N_TEXT + N_CTX)
            for k, v in d["weights"].items():
                i = int(k)
                if not (0 <= i < len(w)) or not isinstance(v, (int, float)) or not math.isfinite(v):
                    raise ValueError("bad weight")
                w[i] = v
            vals = [d["intercept"], d["calibration"]["a"], d["calibration"]["b"], d["threshold"]]
            if not all(isinstance(x, (int, float)) and math.isfinite(x) for x in vals):
                raise ValueError("non-finite parameter")
            if not isinstance(d["meta"].get("version"), str):
                raise ValueError("missing version")
            return cls(d["meta"], w, float(d["intercept"]), float(d["calibration"]["a"]), float(d["calibration"]["b"]), float(d["threshold"]))
        except ModelUnavailable:
            raise
        except Exception as e:  # noqa: BLE001
            raise ModelUnavailable(f"corrupt or incompatible model artifact: {type(e).__name__}") from e


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_verified(path: str | Path, expected_sha256: str) -> LinearModel:
    """Load only if size-limited AND the hash matches the registry. Never unpickles anything."""
    p = Path(path)
    try:
        if not p.is_file() or p.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ModelUnavailable("model artifact missing or too large")
        raw = p.read_bytes()
    except OSError as e:
        raise ModelUnavailable("model artifact unreadable") from e
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ModelUnavailable("model artifact hash mismatch (tampered, stale or corrupted)")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as e:                    # binary blobs (e.g. pickles) are rejected, never parsed
        raise ModelUnavailable("model artifact is not valid UTF-8 JSON") from e
    return LinearModel.from_json(text)
