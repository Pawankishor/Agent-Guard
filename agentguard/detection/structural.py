"""Layer 2: structural inspection (hidden characters, encoded payloads, hidden markup, homoglyphs)
and untrusted-content heuristics (instructions addressed to the agent). Plus argument provenance."""
from __future__ import annotations

import base64
import re
import unicodedata
from typing import Sequence

from ..common import Signal
from .base import DetectionInput
from .normalize import invisible_count
from .patterns import PatternDetector

_B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HIDDEN_MARKUP = re.compile(r"<!--[\s\S]{0,2000}?-->|display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden|\[//\]: #", re.I)
_ADDRESSED = re.compile(
    r"(?im)^\s*(?:ai|assistant|agent|system|note to (?:the )?(?:ai|assistant|agent))\b[^\n]{0,20}[:,-]|"
    r"\b(?:when you (?:read|see|process) this|if you are an? (?:ai|assistant|language model|llm)|"
    r"as an? (?:ai|assistant|agent), you (?:must|should|will)|you must now|you should now|call the \w+ tool|use the \w+ tool to)\b")
_TOOL_IMPERATIVE = re.compile(r"\b(?:send|email|forward|delete|remove|execute|run|export|upload|transfer)\b.{0,60}\b(?:to|the|all|every)\b", re.I)


def _mixed_script(word: str) -> bool:
    scripts = set()
    for ch in word:
        if ch.isalpha():
            try:
                scripts.add(unicodedata.name(ch).split()[0])
            except ValueError:
                pass
    return len(scripts & {"LATIN", "CYRILLIC", "GREEK"}) > 1


class StructuralDetector:
    name, version = "structural", "1.0"

    def __init__(self) -> None:
        self._pat = PatternDetector()

    def _inspect(self, text: str, source: str) -> list[Signal]:
        out: list[Signal] = []
        inv = invisible_count(text)
        if inv >= 1:
            out.append(Signal("structural:invisible_chars", "hidden_text", min(0.5, 0.2 + 0.05 * inv), source,
                              self.name, self.version, ("INVISIBLE_CHARS",), f"{inv} invisible char(s)"))
        if _HIDDEN_MARKUP.search(text):
            out.append(Signal("structural:hidden_markup", "hidden_text", 0.45, source, self.name, self.version, ("HIDDEN_MARKUP",)))
        if any(_mixed_script(w) for w in re.findall(r"\w{4,}", text)[:200]):
            out.append(Signal("structural:homoglyph", "obfuscation", 0.4, source, self.name, self.version, ("MIXED_SCRIPT",)))
        for blob in _B64.findall(text)[:5]:
            try:
                dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False).decode("utf-8", "ignore")
            except Exception:  # noqa: BLE001
                continue
            if dec and sum(c.isprintable() for c in dec) / max(1, len(dec)) > 0.9:
                for s in self._pat.scan(dec, source, allow_mention_downgrade=False):
                    out.append(Signal("structural:encoded_payload", s.category, max(s.severity, 0.8), source, self.name,
                                      self.version, ("ENCODED_PAYLOAD", s.category), s.excerpt))
        if len(text) > 20000:
            out.append(Signal("structural:oversized_input", "volume", 0.3, source, self.name, self.version, ("OVERSIZED",)))
        return out

    def detect(self, inp: DetectionInput) -> Sequence[Signal]:
        out = self._inspect(inp.user_text or "", "user")
        for item in inp.untrusted:
            out += self._inspect(item.text, "untrusted_content")
            if _ADDRESSED.search(item.text) and _TOOL_IMPERATIVE.search(item.text):
                out.append(Signal("untrusted:instruction_in_content", "indirect_injection", 0.75, "untrusted_content",
                                  self.name, self.version, ("INSTRUCTION_ADDRESSED_TO_AGENT",), item.source[:60]))
        return out


class ProvenanceDetector:
    """Authority check independent of the agent's reasoning: did the *values* in the proposed tool call
    come from the human's request, or only from untrusted content the agent read? Content-derived
    arguments on side-effecting tools are the signature of indirect injection."""
    name, version = "provenance", "1.0"

    def detect(self, inp: DetectionInput) -> Sequence[Signal]:
        if not inp.untrusted:
            return []
        user = (inp.user_text or "").lower()
        out: list[Signal] = []
        for k, v in inp.arguments.items():
            if not isinstance(v, str) or len(v) < 4:
                continue
            needle = v.lower()
            if needle in user:
                continue
            for item in inp.untrusted:
                if needle in item.text.lower():
                    out.append(Signal("provenance:content_derived_argument", "indirect_injection",
                                      0.6 if inp.side_effect else 0.2, "arguments", self.name, self.version,
                                      ("ARG_FROM_UNTRUSTED_CONTENT", k), f"{k} <- {item.source[:40]}"))
                    break
        return out
