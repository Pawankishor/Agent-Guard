"""Natural-language -> *proposed* tool calls. Successor to legacy agent.py / classify_request().

The planner is UNTRUSTED: its output is just a proposal that goes through the gateway like any other
call. Unlike the legacy code it returns ALL matched intents (so 'read report.txt and delete everything'
cannot hide a delete behind a benign read) and never defaults an unknown city to Bengaluru."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_CITY = [re.compile(r"\b(?:in|at|for|of)\s+([a-z][a-z .'-]{1,40}?)(?:\s+(?:today|now|currently|right now)|[?.!,]|$)"),
         re.compile(r"\b([a-z][a-z .'-]{1,40})\s+(?:weather|temperature|forecast)\b")]
_STOP = {"the", "current", "today", "right", "my", "this", "that"}
_FILE = re.compile(r"\b([\w./-]+\.(?:txt|md|csv))\b", re.I)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_EMP = re.compile(r"\bemployee\s+#?(\d{1,6})\b", re.I)


@dataclass
class ProposedCall:
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    intent: str = ""


class KeywordPlanner:
    def plan(self, text: str) -> list[ProposedCall]:
        t = (text or "").lower()
        has = lambda ws: any(w in t for w in ws)  # noqa: E731
        calls: list[ProposedCall] = []
        if has(["weather", "temperature", "forecast", "will it rain", "humidity"]):
            city = None
            for rx in _CITY:
                m = rx.search(t)
                if m and m.group(1).strip(" .,!?'") not in _STOP:
                    city = m.group(1).strip(" .,!?'").title(); break
            calls.append(ProposedCall("weather.get", {"city": city} if city else {}, "weather"))
        m = _FILE.search(text or "")
        if has(["read", "open", "show", "view", "contents of"]) and m:
            calls.append(ProposedCall("file.read", {"path": m.group(1)}, "read file"))
        if has(["search the database", "look up", "find the employee", "find the student", "query the database"]):
            table = "salaries" if "salar" in t else "employees" if has(["employee", "staff"]) else "courses"
            calls.append(ProposedCall("db.lookup", {"table": table}, "db lookup"))
        e = _EMAIL.search(text or "")
        if has(["send an email", "send email", "email this", "send this report"]):
            calls.append(ProposedCall("email.send", {"to": e.group(0), "subject": "Message", "body": text[:500]} if e else {}, "email"))
        emp = _EMP.search(text or "")
        if has(["delete", "remove", "erase"]) and emp:
            calls.append(ProposedCall("record.delete", {"employee_id": int(emp.group(1))}, "delete record"))
        elif has(["delete", "remove", "erase", "wipe"]):
            calls.append(ProposedCall("record.delete", {}, "delete (target unclear)"))
        if has(["update the", "change the phone", "update employee", "modify"]) and emp:
            calls.append(ProposedCall("record.update", {"employee_id": int(emp.group(1))}, "update record"))
        if has(["run command", "execute command", "run a command", "shell command", "system command", "powershell", "rm -rf"]):
            calls.append(ProposedCall("command.run", {}, "command"))
        return calls
