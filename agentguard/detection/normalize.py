"""Text normalisation that defeats trivial obfuscation before pattern matching."""
from __future__ import annotations

import re
import unicodedata

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
_SPACED = re.compile(r"\b(?:[a-z]\s){3,}[a-z]\b")
_INTRA = re.compile(r"(?<=[a-z])[-_.*'’·](?=[a-z])")
_WS = re.compile(r"\s+")


def invisible_count(text: str) -> int:
    return sum(1 for ch in text if unicodedata.category(ch) == "Cf" or 0xE0000 <= ord(ch) <= 0xE007F)


def views(text: str) -> list[str]:
    """Return normalised views: [plain, folded]. Patterns run on both and results are unioned."""
    t = unicodedata.normalize("NFKC", text)
    t = "".join(ch for ch in t if unicodedata.category(ch) != "Cf" and not (0xE0000 <= ord(ch) <= 0xE007F))
    plain = _WS.sub(" ", t.lower()).strip()
    folded = plain.translate(_LEET)
    folded = _SPACED.sub(lambda m: m.group(0).replace(" ", ""), folded)
    folded = _INTRA.sub("", folded)
    folded = _WS.sub(" ", folded)
    return [plain] if folded == plain else [plain, folded]
