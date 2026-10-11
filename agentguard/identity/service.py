"""Authentication and session identity.

* Identity is an immutable internal `user_id` (UUID4). Usernames/display names are labels only.
* Roles live in the server-side `users` table and are re-read from it on EVERY resolve(), so a role
  change or account disable takes effect immediately and nothing client-supplied is ever trusted.
* Passwords use scrypt (stdlib, memory-hard) with per-user salts; comparison is constant-time.
* Session tokens are 256-bit random values; only their SHA-256 is stored.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import dataclass

from ..clock import Clock
from ..config import Settings
from ..db import Database
from ..errors import AuthError
from ..common import Reason, sha256_hex

ROLES = ("student", "employee", "manager", "admin", "reviewer")


@dataclass(frozen=True)
class Principal:
    user_id: str
    username: str
    display_name: str
    role: str
    session_id: str
    created_at: float


class IdentityService:
    def __init__(self, db: Database, clock: Clock, settings: Settings):
        self.db, self.clock, self.s = db, clock, settings
        # dummy salt so unknown-user logins cost the same as real ones (no user enumeration by timing)
        self._dummy_salt = secrets.token_bytes(16)

    def _kdf(self, password: str, salt: bytes, n: int) -> bytes:
        return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=8, p=1, dklen=32,
                              maxmem=128 * 1024 * 1024)

    # ---- provisioning (server-side / admin tooling only; there is no self-service signup) ---
    def create_user(self, username: str, password: str, role: str, display_name: str | None = None) -> str:
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}")
        if len(password) < self.s.min_password_len:
            raise ValueError(f"password must be >= {self.s.min_password_len} characters")
        if (not username or len(username) > 64
                or not username.replace("_", "").replace("-", "").replace(".", "").isalnum()):
            raise ValueError("username must be 1-64 chars of [A-Za-z0-9_.-]")
        uid = str(uuid.uuid4())
        salt = secrets.token_bytes(16)
        n = self.s.scrypt_n
        with self.db.tx() as c:
            c.execute("INSERT INTO users(user_id,username,display_name,role,pw_salt,pw_hash,pw_params,created_at)"
                      " VALUES(?,?,?,?,?,?,?,?)",
                      (uid, username, display_name or username, role, salt, self._kdf(password, salt, n),
                       json.dumps({"alg": "scrypt", "n": n, "r": 8, "p": 1}), self.clock.now()))
        return uid

    def set_display_name(self, user_id: str, display_name: str) -> None:
        """Cosmetic only. Trust history is keyed by user_id so this cannot reset anything."""
        with self.db.tx() as c:
            c.execute("UPDATE users SET display_name=? WHERE user_id=?", (display_name[:80], user_id))

    def rename_username(self, user_id: str, new_username: str) -> None:
        with self.db.tx() as c:
            c.execute("UPDATE users SET username=? WHERE user_id=?", (new_username, user_id))

    def set_role(self, user_id: str, role: str) -> None:
        if role not in ROLES:
            raise ValueError("unknown role")
        with self.db.tx() as c:
            c.execute("UPDATE users SET role=? WHERE user_id=?", (role, user_id))

    def disable_user(self, user_id: str) -> None:
        with self.db.tx() as c:
            c.execute("UPDATE users SET disabled=1 WHERE user_id=?", (user_id,))
            c.execute("UPDATE sessions SET revoked=1 WHERE user_id=?", (user_id,))

    # ---- authentication --------------------------------------------------------------------
    def authenticate(self, username: str, password: str) -> tuple[str, str]:
        """Returns (session_token, user_id). On failure raises AuthError carrying `.user_id`
        (None when the username does not exist) so callers can attribute the failure."""
        now = self.clock.now()
        uname = (username or "").strip().lower()[:64]
        with self.db.tx() as c:
            fails = c.execute("SELECT COUNT(*) FROM login_attempts WHERE username=? AND success=0 AND ts>?",
                              (uname, now - self.s.lockout_window_s)).fetchone()[0]
            row = c.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (uname,)).fetchone()
            locked = fails >= self.s.lockout_threshold
            if row is None:
                self._kdf(password or "", self._dummy_salt, self.s.scrypt_n)   # equalise timing
                c.execute("INSERT INTO login_attempts(username,ts,success) VALUES(?,?,0)", (uname, now))
                e = AuthError(Reason.AUTH_LOCKED_OUT if locked else Reason.AUTH_BAD_CREDENTIALS)
                e.user_id = None
                c.execute("COMMIT"); c.execute("BEGIN IMMEDIATE")  # persist the attempt before raising
                raise e
            params = json.loads(row["pw_params"])
            ok = hmac.compare_digest(self._kdf(password or "", row["pw_salt"], int(params["n"])), row["pw_hash"])
            if locked or not ok or row["disabled"]:
                c.execute("INSERT INTO login_attempts(username,ts,success) VALUES(?,?,0)", (uname, now))
                reason = (Reason.AUTH_LOCKED_OUT if locked else
                          Reason.AUTH_ACCOUNT_DISABLED if (ok and row["disabled"]) else Reason.AUTH_BAD_CREDENTIALS)
                e = AuthError(reason)
                e.user_id = row["user_id"]
                c.execute("COMMIT"); c.execute("BEGIN IMMEDIATE")  # persist the attempt before raising
                raise e
            token = secrets.token_urlsafe(32)
            c.execute("INSERT INTO sessions(token_hash,session_id,user_id,created_at,expires_at) VALUES(?,?,?,?,?)",
                      (sha256_hex(token), str(uuid.uuid4()), row["user_id"], now, now + self.s.session_ttl_s))
            c.execute("INSERT INTO login_attempts(username,ts,success) VALUES(?,?,1)", (uname, now))
            return token, row["user_id"]

    def resolve(self, token: str | None) -> Principal:
        """Token -> Principal, re-reading role/disabled from the DB. Fail closed on anything odd."""
        if not token or not isinstance(token, str) or len(token) > 256:
            raise AuthError(Reason.AUTH_INVALID_SESSION)
        try:
            with self.db.read() as c:
                row = c.execute(
                    "SELECT s.session_id,s.expires_at,s.revoked,u.* FROM sessions s JOIN users u USING(user_id)"
                    " WHERE s.token_hash=?", (sha256_hex(token),)).fetchone()
        except Exception as e:  # storage failure must never become an implicit allow
            raise AuthError(Reason.AUTH_INVALID_SESSION, "identity store unavailable") from e
        if row is None or row["revoked"]:
            raise AuthError(Reason.AUTH_INVALID_SESSION)
        if row["expires_at"] <= self.clock.now():
            raise AuthError(Reason.AUTH_SESSION_EXPIRED)
        if row["disabled"]:
            raise AuthError(Reason.AUTH_ACCOUNT_DISABLED)
        return Principal(row["user_id"], row["username"], row["display_name"], row["role"],
                         row["session_id"], row["created_at"])

    def revoke(self, token: str) -> None:
        with self.db.tx() as c:
            c.execute("UPDATE sessions SET revoked=1 WHERE token_hash=?", (sha256_hex(token),))

    def get_user(self, user_id: str) -> dict | None:
        with self.db.read() as c:
            r = c.execute("SELECT user_id,username,display_name,role,created_at,disabled FROM users WHERE user_id=?",
                          (user_id,)).fetchone()
        return dict(r) if r else None
