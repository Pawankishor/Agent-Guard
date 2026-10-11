"""Layer 1: lightweight pattern detector for KNOWN indicators, with obfuscation folding and a
mention-vs-use heuristic. This is a cheap first filter, explicitly not a complete defence:
see docs/LIMITATIONS.md. Severity is evidence strength, not a verdict."""
from __future__ import annotations

import re
from typing import Sequence

from ..common import Signal
from .base import DetectionInput
from .normalize import views

_W = r"(?:\w+\W+)"
_NOUN = r"(?:instructions?|rules?|directions?|directives?|prompts?|guidelines?|polic(?:y|ies)|restrictions?|constraints?|guardrails?|safeguards?|programming|training)"

# (category, severity, regex). Applied to each normalised view.
_RULES: tuple[tuple[str, float, re.Pattern], ...] = tuple((c, s, re.compile(p)) for c, s, p in (
    ("override_instructions", 0.9,
     rf"\b(?:ignore|disregard|forget|override|overrule|discard|bypass|skip)\W+{_W}{{0,4}}?(?:previous|prior|above|earlier|preceding|former|all|any|every|your|the|these|those|system|developer)\W+{_W}{{0,3}}?{_NOUN}\b"),
    ("override_instructions", 0.9,
     r"\b(?:ignore|disregard|forget)\W+(?:everything|anything|all|what)\W+(?:\w+\W+){0,4}?(?:above|before|earlier|prior|previous|so far|told|said|instructed)\b"),
    ("role_hijack", 0.85,
     rf"\b(?:from now on|henceforth|starting now|you are now|you will now)\W+{_W}{{0,6}}?(?:no (?:limits|restrictions|rules|filters|boundaries)|unrestricted|unfiltered|jailbroken|without (?:limits|restrictions|rules)|obey me|answer to me|only (?:listen|obey)|developer mode|god mode)"),
    ("role_hijack", 0.85, r"\b(?:enable|enter|activate|switch to)\W+(?:developer|dan|god|jailbreak|debug)\W+mode\b|\bdo anything now\b|\bjailbreak(?:ed)?\b"),
    ("prompt_exfiltration", 0.85,
     rf"\b(?:reveal|show|print|display|output|repeat|leak|dump|tell me)\W+{_W}{{0,3}}?(?:your|the|hidden|secret|system|initial|original)\W+{_W}{{0,2}}?(?:system prompt|prompt|instructions|rules|configuration|guidelines)\b"),
    ("secret_request", 0.7,
     rf"\b(?:reveal|show|print|send|email|share|leak|dump|give me|tell me|export|exfiltrate)\W+{_W}{{0,4}}?(?:api[ _-]?keys?|passwords?|credentials?|secrets?|tokens?|private keys?|session cookies?|ssh keys?)\b"),
    ("bulk_data_request", 0.4,
     rf"\b(?:export|dump|send|email|exfiltrate|upload)\W+{_W}{{0,4}}?(?:users?|salary|salaries|employees?|customers?|all)\W+{_W}{{0,2}}?(?:table|data|records|database|list|file)s?\b"),
    ("policy_tamper", 0.45,
     rf"\b(?:disable|bypass|turn off|deactivate|circumvent|skip|remove|override)\W+{_W}{{0,2}}?(?:security|safety|guardrails?|filters?|protections?|restrictions?|monitoring|logging|audit|authorization|permissions?)\b(?!\W+(?:alerts?|notifications?|updates?|emails?|warnings?|cameras?))"),
    ("delimiter_spoof", 0.8,
     r"</?\s*(?:system|assistant|developer)\s*>|\[/?inst\]|<\|im_(?:start|end)\|>|^\s*#{2,}\s*system\b|begin system prompt|end system prompt"),
))
_AGENT_TARGET = re.compile(r"\b(?:you|your|yourself|assistant|agent|chatbot|ai|guardrails?)\b")
_MENTION_CUES = re.compile(
    r"\b(?:explain|what does|what do|meaning of|define|definition|example of|examples of|lecture|class|paper|article|"
    r"how do attackers|how do attacks|detect|defend|defence|defense|prevent|discuss|analy[sz]e|why is|is it true)\b")
_CONTINUATION = re.compile(r"\b(?:and|then|now)\b.{0,40}\b(?:do it|execute|run|delete|send|export|reveal|obey|comply)\b")
_QUOTES = "\"'“”‘’«»`"


def _sentence_around(text: str, start: int, end: int) -> tuple[str, str]:
    a = max(text.rfind(".", 0, start), text.rfind("?", 0, start), text.rfind("!", 0, start), text.rfind("\n", 0, start)) + 1
    ends = [i for i in (text.find(".", end), text.find("?", end), text.find("!", end), text.find("\n", end)) if i != -1]
    b = min(ends) if ends else len(text)
    return text[a:start], text[end:b]


class PatternDetector:
    name, version = "pattern", "2.0"

    def __init__(self, source_label: str = "user"):
        self.source_label = source_label

    def scan(self, text: str, source: str, *, allow_mention_downgrade: bool) -> list[Signal]:
        best: dict[str, Signal] = {}
        for view in views(text):
            for cat, sev, rx in _RULES:
                for m in rx.finditer(view):
                    before, after = _sentence_around(view, m.start(), m.end())
                    codes = [cat]
                    s = sev
                    if cat == "policy_tamper" and _AGENT_TARGET.search(before + " " + m.group(0) + " " + after):
                        s = 0.85; codes.append("TARGETS_AGENT")
                    if allow_mention_downgrade and cat != "delimiter_spoof":
                        lq, rq = before.rstrip()[-1:], after.lstrip()[:1]
                        quoted = bool(lq) and bool(rq) and lq in _QUOTES and rq in _QUOTES   # '' in str is True: guard
                        cue = bool(_MENTION_CUES.search(before + " " + after))
                        if (quoted or cue) and not _CONTINUATION.search(after):
                            s = min(s, 0.3); codes.append("MENTION_CONTEXT")
                    sig = Signal(f"pattern:{cat}", cat, s, source, self.name, self.version, tuple(codes), m.group(0)[:80])
                    if cat not in best or sig.severity > best[cat].severity:
                        best[cat] = sig
        return list(best.values())

    def detect(self, inp: DetectionInput) -> Sequence[Signal]:
        out = self.scan(inp.user_text or "", "user", allow_mention_downgrade=True)
        # Retrieved/tool content is untrusted: instruction-like text there is never downgraded.
        for item in inp.untrusted:
            for s in self.scan(item.text, "untrusted_content", allow_mention_downgrade=False):
                out.append(Signal(s.name, s.category, s.severity, "untrusted_content", s.detector, s.version,
                                  s.codes + ("INDIRECT",), s.excerpt))
        return out
