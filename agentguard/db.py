"""SQLite access with explicit transactions, WAL, busy timeouts and versioned migrations.

SQLite is the local-development backend. The schema uses only portable SQL so it can move to
PostgreSQL (see docs/ARCHITECTURE.md, "Migration path").
"""
from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

MIGRATIONS: list[tuple[int, str]] = [
    (1, """
CREATE TABLE users(
  user_id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('student','employee','manager','admin','reviewer')),
  pw_salt BLOB NOT NULL, pw_hash BLOB NOT NULL, pw_params TEXT NOT NULL,
  created_at REAL NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0);
CREATE TABLE sessions(
  token_hash TEXT PRIMARY KEY, session_id TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL REFERENCES users(user_id),
  created_at REAL NOT NULL, expires_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE login_attempts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, ts REAL NOT NULL, success INTEGER NOT NULL);
CREATE INDEX idx_login_attempts ON login_attempts(username, ts);

CREATE TABLE trust_events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE, dedupe_key TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL, event_type TEXT NOT NULL, ts REAL NOT NULL,
  severity REAL NOT NULL, verified INTEGER NOT NULL DEFAULT 0,
  negates TEXT, request_id TEXT, detail TEXT);
CREATE INDEX idx_trust_user ON trust_events(user_id, ts);

CREATE TABLE seen_requests(
  principal_id TEXT NOT NULL, request_id TEXT NOT NULL, ts REAL NOT NULL,
  PRIMARY KEY(principal_id, request_id));
CREATE INDEX idx_seen_ts ON seen_requests(principal_id, ts);

CREATE TABLE approvals(
  approval_id TEXT PRIMARY KEY, request_id TEXT NOT NULL, requester_id TEXT NOT NULL,
  tool TEXT NOT NULL, action TEXT NOT NULL, resource TEXT NOT NULL, args_hash TEXT NOT NULL,
  policy_version TEXT NOT NULL, binding_hash TEXT NOT NULL,
  created_at REAL NOT NULL, expires_at REAL NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('PENDING','APPROVED','REJECTED','EXPIRED','CONSUMED')),
  approver_id TEXT, decided_at REAL, comment TEXT,
  risk_flags TEXT NOT NULL DEFAULT '[]', signature TEXT NOT NULL);

CREATE TABLE audit_events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE, ts REAL NOT NULL, event_type TEXT NOT NULL,
  principal_id TEXT, session_id TEXT, request_id TEXT, tool TEXT, action TEXT, resource_class TEXT,
  outcome TEXT, outcome_class TEXT, approval_status TEXT, exec_status TEXT,
  payload_json TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE INDEX idx_audit_ts ON audit_events(ts);
CREATE INDEX idx_audit_principal ON audit_events(principal_id, ts);
CREATE INDEX idx_audit_request ON audit_events(request_id);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events
  BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events
  BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER trust_no_update BEFORE UPDATE ON trust_events
  BEGIN SELECT RAISE(ABORT, 'trust_events is append-only'); END;
CREATE TRIGGER trust_no_delete BEFORE DELETE ON trust_events
  BEGIN SELECT RAISE(ABORT, 'trust_events is append-only'); END;

CREATE TABLE labels(
  label_id TEXT PRIMARY KEY, subject_event_id TEXT, text_sha256 TEXT NOT NULL, text_excerpt TEXT,
  label INTEGER NOT NULL CHECK(label IN (0,1)),
  source TEXT NOT NULL CHECK(source IN ('human_review','curated')),
  reviewer_id TEXT NOT NULL, evidence TEXT NOT NULL, created_at REAL NOT NULL, supersedes TEXT);
CREATE TABLE candidate_examples(
  example_id TEXT PRIMARY KEY, event_id TEXT, text_sha256 TEXT NOT NULL, text_excerpt TEXT,
  model_score REAL, created_at REAL NOT NULL);

CREATE TABLE model_registry(
  version TEXT PRIMARY KEY, sha256 TEXT NOT NULL, path TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('CANDIDATE','REJECTED','APPROVED','ACTIVE','RETIRED')),
  created_at REAL NOT NULL, metrics_json TEXT NOT NULL DEFAULT '{}',
  approved_by TEXT, activated_at REAL, previous_active TEXT);
"""),
]


class Database:
    def __init__(self, path: Path | str):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Write transaction. BEGIN IMMEDIATE takes the write lock up front so concurrent
        writers serialise instead of failing mid-transaction."""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")
        finally:
            conn.close()

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()

    def migrate(self) -> int:
        with self.tx() as c:
            c.execute("CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY, applied_at REAL)")
            cur = c.execute("SELECT COALESCE(MAX(version),0) FROM schema_version").fetchone()[0]
            for ver, sql in MIGRATIONS:
                if ver > cur:
                    for stmt in _split_sql(sql):
                        c.execute(stmt)
                    c.execute("INSERT INTO schema_version VALUES(?,?)", (ver, time.time()))
                    cur = ver
            return cur


def _split_sql(script: str) -> list[str]:
    """Split on ';' but keep CREATE TRIGGER ... BEGIN ... END; blocks intact."""
    out, buf, in_trigger = [], [], False
    for line in script.splitlines():
        s = line.strip()
        if not s:
            continue
        buf.append(line)
        if s.upper().startswith("CREATE TRIGGER"):
            in_trigger = True
        if in_trigger:
            if s.endswith("END;"):
                out.append("\n".join(buf)); buf = []; in_trigger = False
        elif s.endswith(";"):
            out.append("\n".join(buf)); buf = []
    if buf:
        out.append("\n".join(buf))
    return out
