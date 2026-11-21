from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import asdict, dataclass, replace
from typing import Iterable, List, Optional, Sequence, Tuple

from .detectors import DEFAULT_DETECTORS, Detector

CONTEXT_BOOST = 0.15
MAX_CONFIDENCE = 0.99
STYLES = ("tag", "mask", "partial", "hash")
_DIGIT_OR_AT = re.compile(r"[0-9@]")


@dataclass(frozen=True)
class Match:
    kind: str
    value: str
    start: int
    end: int
    confidence: float
    context: bool  # a keyword for this kind appeared nearby

    def to_dict(self) -> dict:
        return asdict(self)


class Scanner:
    """Finds Indian PII in text.

    >>> s = Scanner(min_confidence=0.7)
    >>> [m.kind for m in s.scan("PAN: ABCPE1234F")]
    ['pan']
    """

    def __init__(
        self,
        detectors: Sequence[Detector] = DEFAULT_DETECTORS,
        kinds: Optional[Iterable[str]] = None,
        min_confidence: float = 0.5,
        context_before: int = 40,
        context_after: int = 20,
        key: Optional[bytes] = None,
        ignore_case: bool = False,
    ) -> None:
        wanted = set(kinds) if kinds is not None else None
        if wanted is not None:
            known = {d.kind for d in detectors}
            unknown = wanted - known
            if unknown:
                raise ValueError(f"unknown kind(s): {', '.join(sorted(unknown))}")
        self.detectors = [d for d in detectors if wanted is None or d.kind in wanted]
        if ignore_case:
            # Official formats are uppercase; user-typed input often isn't.
            # Vehicle plates stay case-sensitive ("or 12 1234" is English).
            self.detectors = [
                replace(d, pattern=re.compile(d.pattern.pattern, d.pattern.flags | re.I))
                if d.case_insensitive_ok
                else d
                for d in self.detectors
            ]
        self.min_confidence = min_confidence
        self.context_before = context_before
        self.context_after = context_after
        # Key for style="hash". Random per Scanner unless given, so hashes
        # can't be reversed by brute force (Aadhaar has only ~10^11 values).
        self._key = key if key is not None else os.urandom(32)

    # -- scanning ---------------------------------------------------------

    def scan(self, text: str) -> List[Match]:
        candidates = []
        if not _DIGIT_OR_AT.search(text):
            return []  # every detector needs a digit or an '@'
        for prio, det in enumerate(self.detectors):
            if det.needs and det.needs not in text:
                continue
            for m in det.pattern.finditer(text):
                raw = m.group(0)
                conf = det.score(raw)
                if conf is None:
                    continue
                window = (
                    text[max(0, m.start() - self.context_before) : m.start()]
                    + " "
                    + text[m.end() : m.end() + self.context_after]
                )
                ctx = det.has_context(window)
                if det.requires_context and not ctx:
                    continue
                if ctx:
                    conf = min(MAX_CONFIDENCE, conf + CONTEXT_BOOST)
                conf = round(conf, 2)
                if conf < self.min_confidence:
                    continue
                candidates.append((Match(det.kind, raw, m.start(), m.end(), conf, ctx), prio))

        return _resolve_overlaps(candidates)

    def contains_pii(self, text: str) -> bool:
        return bool(self.scan(text))

    # -- redaction --------------------------------------------------------

    def redact(self, text: str, style: str = "tag", mask_char: str = "X") -> str:
        if style not in STYLES:
            raise ValueError(f"style must be one of {STYLES}")
        parts: List[str] = []
        pos = 0
        for m in self.scan(text):
            parts.append(text[pos : m.start])
            parts.append(self.replacement(m, style, mask_char))
            pos = m.end
        parts.append(text[pos:])
        return "".join(parts)

    def replacement(self, m: Match, style: str, mask_char: str = "X") -> str:
        if style == "tag":
            return f"[{m.kind.upper()}]"
        if style == "mask":
            return re.sub(r"[A-Za-z0-9]", mask_char, m.value)
        if style == "partial":
            return partial_mask(m.kind, m.value, mask_char)
        normalized = re.sub(r"[^A-Za-z0-9@._-]", "", m.value).upper()
        digest = hmac.new(self._key, normalized.encode(), hashlib.sha256).hexdigest()[:10]
        return f"[{m.kind.upper()}:{digest}]"


def _resolve_overlaps(candidates: List[Tuple[Match, int]]) -> List[Match]:
    """Keep non-overlapping matches: keyword nearby first, then highest
    confidence, then longest span, then detector order. Candidates are split into clusters of mutually
    overlapping spans first, so the greedy choice only runs on small groups.
    """
    candidates.sort(key=lambda c: c[0].start)
    out: List[Match] = []
    i = 0
    while i < len(candidates):
        cluster = [candidates[i]]
        cluster_end = candidates[i][0].end
        i += 1
        while i < len(candidates) and candidates[i][0].start < cluster_end:
            cluster.append(candidates[i])
            cluster_end = max(cluster_end, candidates[i][0].end)
            i += 1
        if len(cluster) == 1:
            out.append(cluster[0][0])
            continue
        # A match whose own keyword is nearby beats one without ("a/c" next
        # to a number that happens to pass Luhn is an account, not a card).
        cluster.sort(
            key=lambda c: (-c[0].context, -c[0].confidence, -(c[0].end - c[0].start), c[1])
        )
        kept: List[Match] = []
        for m, _ in cluster:
            if all(m.end <= k.start or m.start >= k.end for k in kept):
                kept.append(m)
        out.extend(sorted(kept, key=lambda m: m.start))
    return out


def partial_mask(kind: str, value: str, mask_char: str = "X") -> str:
    """Keep just enough to recognise the value, like UIDAI's masked Aadhaar.

    Emails and UPI IDs keep the first character and the domain/handle.
    Everything else keeps the last 4 alphanumerics.
    """
    if kind in ("email", "upi") and "@" in value:
        local, _, domain = value.rpartition("@")
        return local[:1] + mask_char * max(len(local) - 1, 3) + "@" + domain
    alnum_positions = [i for i, c in enumerate(value) if c.isalnum()]
    keep = set(alnum_positions[-4:]) if len(alnum_positions) > 4 else set()
    if kind == "phone":
        keep |= set(alnum_positions[:-10])  # +91 / 0 prefix is not sensitive
    return "".join(
        c if (not c.isalnum() or i in keep) else mask_char for i, c in enumerate(value)
    )


_default: Optional[Scanner] = None


def _scanner(kinds, min_confidence) -> Scanner:
    global _default
    if kinds is None and min_confidence == 0.5:
        if _default is None:
            _default = Scanner()
        return _default
    return Scanner(kinds=kinds, min_confidence=min_confidence)


def scan(text: str, kinds: Optional[Iterable[str]] = None, min_confidence: float = 0.5) -> List[Match]:
    """Return PII matches in ``text``, sorted by position."""
    return _scanner(kinds, min_confidence).scan(text)


def redact(
    text: str,
    style: str = "tag",
    kinds: Optional[Iterable[str]] = None,
    min_confidence: float = 0.5,
) -> str:
    """Return ``text`` with PII replaced. Styles: tag, mask, partial, hash."""
    return _scanner(kinds, min_confidence).redact(text, style=style)
