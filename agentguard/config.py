"""Validated configuration. No secrets live in source; the HMAC key comes from the environment."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ConfigError


@dataclass(frozen=True)
class Settings:
    env: str = "dev"                       # dev | test | prod
    data_dir: Path = Path("data")
    hmac_key: bytes = b""                  # >=32 bytes; signs approvals + audit chain
    session_ttl_s: int = 8 * 3600
    approval_ttl_s: int = 900
    scrypt_n: int = 2 ** 14
    min_password_len: int = 12
    lockout_threshold: int = 5
    lockout_window_s: int = 900
    rate_limit_per_min: int = 30
    internal_email_domains: tuple[str, ...] = ("corp.example",)
    max_output_bytes: int = 65536
    ml_required_for_protected: bool = True  # fail-safe: protected calls escalate if the model is unusable
    approval_score_threshold: float = 50.0
    deny_injection_threshold: float = 0.8
    store_excerpts: bool = True
    clock_skew_s: int = 300
    extra: dict = field(default_factory=dict)

    @property
    def security_db(self) -> Path:
        return self.data_dir / "security.db"

    @property
    def sandbox_dir(self) -> Path:
        return self.data_dir / "sandbox"

    @property
    def model_dir(self) -> Path:
        return self.data_dir / "models"

    def validate(self) -> "Settings":
        if self.env not in {"dev", "test", "prod"}:
            raise ConfigError("env must be dev|test|prod")
        if len(self.hmac_key) < 32:
            raise ConfigError("hmac_key must be at least 32 bytes (set AGENTGUARD_HMAC_KEY to 64 hex chars)")
        if self.session_ttl_s <= 0 or self.approval_ttl_s <= 0:
            raise ConfigError("TTLs must be positive")
        if self.min_password_len < 12:
            raise ConfigError("min_password_len must be >= 12")
        if not (0 < self.approval_score_threshold <= 100):
            raise ConfigError("approval_score_threshold must be in (0,100]")
        if not (0 < self.deny_injection_threshold <= 1):
            raise ConfigError("deny_injection_threshold must be in (0,1]")
        if self.env == "prod" and self.scrypt_n < 2 ** 14:
            raise ConfigError("scrypt_n too low for prod")
        if self.rate_limit_per_min < 1:
            raise ConfigError("rate_limit_per_min must be >= 1")
        return self

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ.get("AGENTGUARD_ENV", "dev")
        data_dir = Path(os.environ.get("AGENTGUARD_DATA_DIR", "data"))
        key_hex = os.environ.get("AGENTGUARD_HMAC_KEY", "")
        if key_hex:
            try:
                key = bytes.fromhex(key_hex)
            except ValueError as e:
                raise ConfigError("AGENTGUARD_HMAC_KEY must be hex") from e
        elif env == "dev":
            data_dir.mkdir(parents=True, exist_ok=True)
            kf = data_dir / "dev_hmac.key"
            if not kf.exists():
                kf.write_text(secrets.token_hex(32))
                os.chmod(kf, 0o600)
            key = bytes.fromhex(kf.read_text().strip())
        else:
            raise ConfigError("AGENTGUARD_HMAC_KEY is required outside dev")
        domains = tuple(d.strip().lower() for d in os.environ.get(
            "AGENTGUARD_INTERNAL_EMAIL_DOMAINS", "corp.example").split(",") if d.strip())
        return cls(
            env=env, data_dir=data_dir, hmac_key=key,
            rate_limit_per_min=int(os.environ.get("AGENTGUARD_RATE_LIMIT_PER_MIN", 30)),
            approval_ttl_s=int(os.environ.get("AGENTGUARD_APPROVAL_TTL_S", 900)),
            internal_email_domains=domains,
            ml_required_for_protected=os.environ.get("AGENTGUARD_ML_REQUIRED", "1") == "1",
        ).validate()
