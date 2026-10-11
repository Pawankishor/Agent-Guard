"""Demonstration tools. ALL are simulated/sandboxed: no real email, no real deletion, and
`command.run` NEVER spawns a process. To add a tool see docs/DEVELOPER_GUIDE.md."""
from __future__ import annotations

import hashlib
import re
import sqlite3
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from ..errors import PathViolation, ToolError, UnsupportedOperation
from ..common import Resource, RiskClass, Sensitivity
from .base import Field, ToolEnv, ToolSpec

S = Sensitivity
_PATH_RE = r"[A-Za-z0-9_./-]{1,200}"
_ALLOWED_EXT = {".txt", ".md", ".csv"}
_MAX_FILE_BYTES = 64 * 1024


# ---- path safety -------------------------------------------------------------------------------
def safe_relpath(root: Path, raw: str) -> str:
    """Return the sandbox-relative POSIX path of the *fully resolved* target, or raise PathViolation.
    Symlinks are resolved first, so a link from public/ to confidential/ is classified as confidential."""
    if "\x00" in raw or "\\" in raw or raw.startswith(("/", "~")):
        raise PathViolation("absolute or malformed path")
    parts = PurePosixPath(raw).parts
    if not parts or any(p == ".." for p in parts):
        raise PathViolation("path traversal")
    root_res = root.resolve()
    target = (root_res / PurePosixPath(*parts)).resolve()
    try:
        rel = target.relative_to(root_res)
    except ValueError as e:
        raise PathViolation("path escapes sandbox") from e
    return rel.as_posix()


_DIR_SENS = {"public": S.PUBLIC, "internal": S.INTERNAL, "confidential": S.CONFIDENTIAL, "secrets": S.CRITICAL}


# ---- weather.get -------------------------------------------------------------------------------
def _weather_resolve(a: Mapping[str, Any], env: ToolEnv) -> Resource:
    return Resource("city", "city:" + a["city"].strip().lower(), S.PUBLIC)


def _weather_run(a: Mapping[str, Any], env: ToolEnv) -> Any:
    return env.weather.get(a["city"])


# ---- db.lookup (read-only, parameterised) -----------------------------------------------------
_TABLE_SENS = {"courses": S.PUBLIC, "employees": S.INTERNAL, "salaries": S.CONFIDENTIAL}
_LOOKUP_SQL = {   # table names come from this fixed map, never from user text
    "courses": "SELECT id,title,dept FROM courses WHERE title LIKE ? ESCAPE '\\' ORDER BY id LIMIT ?",
    "employees": "SELECT id,name,department FROM employees WHERE name LIKE ? ESCAPE '\\' AND deleted=0 ORDER BY id LIMIT ?",
    "salaries": ("SELECT e.id,e.name,s.amount FROM salaries s JOIN employees e ON e.id=s.employee_id "
                 "WHERE e.name LIKE ? ESCAPE '\\' AND e.deleted=0 ORDER BY e.id LIMIT ?"),
}


def _db_resolve(a, env) -> Resource:
    return Resource("table", a["table"], _TABLE_SENS[a["table"]])


def _db_run(a, env: ToolEnv) -> Any:
    needle = a.get("name_contains", "").replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    con = sqlite3.connect(f"file:{env.sandbox_db}?mode=ro", uri=True, timeout=5)
    try:
        rows = con.execute(_LOOKUP_SQL[a["table"]], (f"%{needle}%", a.get("limit", 10))).fetchall()
    finally:
        con.close()
    return {"table": a["table"], "rows": [list(r) for r in rows]}


# ---- file.read ---------------------------------------------------------------------------------
def _file_resolve(a, env: ToolEnv) -> Resource:
    rel = safe_relpath(env.sandbox_root, a["path"])
    top = rel.split("/", 1)[0]
    return Resource("file", rel, _DIR_SENS.get(top, S.CRITICAL))     # unknown directory => CRITICAL


def _file_run(a, env: ToolEnv) -> Any:
    rel = safe_relpath(env.sandbox_root, a["path"])                      # re-check at execution time (TOCTOU)
    p = (env.sandbox_root.resolve() / rel)
    if p.suffix.lower() not in _ALLOWED_EXT:
        raise UnsupportedOperation("file type not supported")
    if not p.is_file():
        raise ToolError("NOT_FOUND", "file not found")
    if p.stat().st_size > _MAX_FILE_BYTES:
        raise ToolError("TOO_LARGE", "file exceeds size limit")
    return {"path": rel, "content": p.read_text(errors="replace")}


# ---- email.send (simulated outbox) -------------------------------------------------------------
_EMAIL_RE = r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63}){1,4}"


def _email_resolve(a, env: ToolEnv) -> Resource:
    domain = a["to"].rsplit("@", 1)[1].lower()
    internal = domain in env.internal_domains
    return Resource("email", f"{'internal' if internal else 'external'}:{domain}",
                    S.INTERNAL if internal else S.CONFIDENTIAL)


def _email_run(a, env: ToolEnv) -> Any:
    con = sqlite3.connect(env.sandbox_db, timeout=5)
    try:
        con.execute("INSERT INTO outbox(ts,recipient,subject,body_sha256) VALUES(?,?,?,?)",
                    (env.clock.now(), a["to"], a["subject"], hashlib.sha256(a["body"].encode()).hexdigest()))
        con.commit()
    finally:
        con.close()
    return {"status": "SIMULATED_SENT", "to": a["to"], "note": "no real email was sent"}


# ---- record.update / record.delete (simulated, sandbox DB only) --------------------------------
def _rec_resolve(a, env) -> Resource:
    return Resource("employee", f"employee:{a['employee_id']}", S.CONFIDENTIAL)


_UPDATE_SQL = {"phone": "UPDATE employees SET phone=? WHERE id=? AND deleted=0",
               "department": "UPDATE employees SET department=? WHERE id=? AND deleted=0"}
_SELECT_OLD_SQL = {"phone": "SELECT phone FROM employees WHERE id=? AND deleted=0",
                   "department": "SELECT department FROM employees WHERE id=? AND deleted=0"}


def _update_run(a, env: ToolEnv) -> Any:
    if a["field"] not in _UPDATE_SQL:                      # defence in depth beyond enum validation
        raise UnsupportedOperation("field not updatable")
    con = sqlite3.connect(env.sandbox_db, timeout=5)
    try:
        old = con.execute(_SELECT_OLD_SQL[a["field"]], (a["employee_id"],)).fetchone()
        if old is None:
            raise ToolError("NOT_FOUND", "no such record")
        con.execute(_UPDATE_SQL[a["field"]], (a["value"], a["employee_id"]))
        con.commit()
    finally:
        con.close()
    return {"employee_id": a["employee_id"], "field": a["field"], "previous": old[0], "new": a["value"],
            "reversible": True}


def _delete_run(a, env: ToolEnv) -> Any:
    con = sqlite3.connect(env.sandbox_db, timeout=5)
    try:
        cur = con.execute("UPDATE employees SET deleted=1 WHERE id=? AND deleted=0", (a["employee_id"],))  # tombstone
        con.commit()
        if cur.rowcount != 1:
            raise ToolError("NOT_FOUND", "no such record")
    finally:
        con.close()
    return {"employee_id": a["employee_id"], "status": "SIMULATED_TOMBSTONED", "note": "soft-delete in sandbox only"}


# ---- command.run (NEVER executes anything) ------------------------------------------------------
_CANNED = {"disk_usage": "SIMULATED: /dev/sim0 42% used", "uptime": "SIMULATED: up 12 days",
           "list_processes": "SIMULATED: 3 processes"}
_CMD_RE = r"(disk_usage|uptime|list_processes)( [A-Za-z0-9_./=-]{1,64}){0,3}"   # allow-list at the schema layer


def _cmd_resolve(a, env) -> Resource:
    return Resource("command", "command:" + a["command"].split(" ", 1)[0], S.CRITICAL)


def _cmd_run(a, env: ToolEnv) -> Any:
    name = a["command"].split(" ", 1)[0]
    if name not in _CANNED:
        raise UnsupportedOperation(f"simulated command '{name}' is not supported")
    con = sqlite3.connect(env.sandbox_db, timeout=5)
    try:
        con.execute("INSERT INTO command_log(ts,command) VALUES(?,?)", (env.clock.now(), a["command"]))
        con.commit()
    finally:
        con.close()
    return {"output": _CANNED[name], "executed_on_host": False}


BUILTIN_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("weather.get", "Current weather for a named city (simulated by default).",
             (Field("city", "str", max_len=60, pattern=r"[A-Za-z][A-Za-z .'-]{0,59}"),),
             RiskClass.LOW, False, True, _weather_resolve, _weather_run),
    ToolSpec("db.lookup", "Read-only lookup over the synthetic database.",
             (Field("table", "enum", choices=("courses", "employees", "salaries")),
              Field("name_contains", "str", required=False, default="", max_len=40, pattern=r"[A-Za-z0-9 .'-]{0,40}"),
              Field("limit", "int", required=False, default=10, min=1, max=20)),
             RiskClass.LOW, False, True, _db_resolve, _db_run),
    ToolSpec("file.read", "Read an approved text file inside the sandbox directory.",
             (Field("path", "str", max_len=200, pattern=_PATH_RE),),
             RiskClass.LOW, False, True, _file_resolve, _file_run),
    ToolSpec("email.send", "Send an email (SIMULATED: writes to a sandbox outbox).",
             (Field("to", "str", max_len=254, pattern=_EMAIL_RE),
              Field("subject", "str", max_len=120), Field("body", "str", max_len=2000)),
             RiskClass.MEDIUM, True, False, _email_resolve, _email_run),
    ToolSpec("record.update", "Update an employee record (SIMULATED, sandbox DB).",
             (Field("employee_id", "int", min=1, max=10 ** 6),
              Field("field", "enum", choices=("phone", "department")),
              Field("value", "str", max_len=40, pattern=r"[A-Za-z0-9 +()-]{1,40}")),
             RiskClass.HIGH, True, True, _rec_resolve, _update_run),
    ToolSpec("record.delete", "Soft-delete an employee record (SIMULATED tombstone).",
             (Field("employee_id", "int", min=1, max=10 ** 6),),
             RiskClass.HIGH, True, False, _rec_resolve, _delete_run),
    ToolSpec("command.run", "Run an allow-listed *simulated* command; never touches the host.",
             (Field("command", "str", max_len=200, pattern=_CMD_RE),),
             RiskClass.CRITICAL, True, False, _cmd_resolve, _cmd_run),
)
