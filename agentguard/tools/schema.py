"""Strict, dependency-free argument validation. Unknown keys, wrong types, control characters,
over-long values and pattern mismatches are all rejected. Validated args are NFC-normalised so the
canonical hash an approval binds to is stable."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping

from ..errors import ArgumentError


@dataclass(frozen=True)
class Field:
    name: str
    type: str                                  # "str" | "int" | "enum"
    required: bool = True
    max_len: int = 256
    pattern: str | None = None                 # must fullmatch
    choices: tuple[str, ...] | None = None
    min: int | None = None
    max: int | None = None
    default: Any = None


def validate(fields: tuple[Field, ...], args: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(args, Mapping):
        raise ArgumentError("arguments must be an object")
    known = {f.name: f for f in fields}
    extra = set(args) - set(known)
    if extra:
        raise ArgumentError(f"unknown argument(s): {sorted(map(str, extra))[:3]}", field=str(sorted(map(str, extra))[0]))
    out: dict[str, Any] = {}
    for f in fields:
        if f.name not in args:
            if f.required and f.default is None:
                raise ArgumentError(f"missing required argument '{f.name}'", f.name)
            if f.default is not None:
                out[f.name] = f.default
            continue
        v = args[f.name]
        if f.type in ("str", "enum"):
            if not isinstance(v, str):
                raise ArgumentError(f"'{f.name}' must be a string", f.name)
            v = unicodedata.normalize("NFC", v)
            if len(v) > f.max_len:
                raise ArgumentError(f"'{f.name}' too long", f.name)
            if any(unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn") for ch in v):
                raise ArgumentError(f"'{f.name}' contains control/format characters", f.name)
            if f.type == "enum" and v not in (f.choices or ()):
                raise ArgumentError(f"'{f.name}' not an allowed value", f.name)
            if f.pattern and not re.fullmatch(f.pattern, v):
                raise ArgumentError(f"'{f.name}' has invalid format", f.name)
        elif f.type == "int":
            if isinstance(v, bool) or not isinstance(v, int):
                raise ArgumentError(f"'{f.name}' must be an integer", f.name)
            if (f.min is not None and v < f.min) or (f.max is not None and v > f.max):
                raise ArgumentError(f"'{f.name}' out of range", f.name)
        else:  # pragma: no cover
            raise ArgumentError(f"unsupported field type {f.type}", f.name)
        out[f.name] = v
    return out
