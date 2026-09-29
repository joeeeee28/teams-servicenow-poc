"""
app/knowledge/sanitize.py — Deterministic knowledge sanitization (DEMO-03).

Retrieved article text is UNTRUSTED DATA.  Before anything is shown, each
line is checked against fixed rules — this never relies on the LLM:

  * instruction-like text (prompt injection, tool/API commands) → the whole
    article is QUARANTINED: a compromised article is not shown at all;
  * secrets / credentials / tokens / auth headers → the line is dropped;
  * internal or private notes (work notes, internal comments) → dropped;
  * personal data (e-mail addresses, phone numbers) → dropped;
  * infrastructure details (IP addresses, internal hostnames, UNC paths) and
    URLs / markup → dropped.

Every line is first NORMALIZED (NFKC, zero-width / control / bidi characters
removed, markdown emphasis characters removed).  The checks run on that
normalized text and the displayed text is built from the same normalized
text, so formatting such as bold or backticked labels, zero-width characters
or fullwidth letters cannot hide content from the rules.

What remains is split into an optional summary line and numbered steps.
Output is plain text only; it is never executed, never sent to the LLM and
never used for routing, authorization, confirmation or tool selection.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Optional

from app.knowledge.models import KnowledgeArticle

MAX_STEPS = 8
MAX_LINE = 300

_I = re.IGNORECASE

INJECTION_PATTERNS = tuple(re.compile(p, _I) for p in (
    r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(instruction|prompt|polic|rule|guardrail|security)",
    r"\bsystem\s*prompt\b",
    r"\byou\s+are\s+now\b",
    r"\b(reveal|print|return|output|show|send|disclose|leak)\b.{0,40}\b(password|credential|token|secret|api\s*key|client[\s_-]*secret)",
    r"\b(call|invoke|execute)\b.{0,30}\b(servicenow|api|endpoint|tool|function|command|script)\b",
    r"\b(the|this|as\s+an?)\s+(ai|assistant|llm|chatbot|bot)\b.{0,20}\b(must|should|will|shall)\b",
    r"<\s*/?\s*(script|system|instruction|tool)",
    r"```",
))

SECRET_PATTERNS = tuple(re.compile(p, _I) for p in (
    r"\b(pass(word)?|passwd|pwd|secret|token|api[\s_-]*key|client[\s_-]*secret|credentials?)\s*[:=]",
    r"\b(pass(word)?|passwd|credentials?)\s+(is|are)\s*:",
    r"\b(the|shared|admin|service|default)\s+(account\s+)?password\s+(is|for)\b",
    r"\bbearer\s+[a-z0-9._~+/=-]{8,}",
    r"\bauthorization\s*:",
    r"-----begin",
    r"\bsk-[a-z0-9]{12,}",
    r"\beyj[a-z0-9_-]{8,}\.",
    r"\b(user\s*id|uid|server|data\s+source)\s*=",
))

INTERNAL_PATTERNS = tuple(re.compile(p, _I) for p in (
    r"^\s*[\[(]?\s*(internal|private|confidential|agent[\s-]*only|work\s*notes?|internal\s+comments?)\b",
    r"\b(work\s*notes?|internal\s+comments?|agent[\s-]*only|do\s+not\s+share)\b",
))

PII_PATTERNS = tuple(re.compile(p, _I) for p in (
    r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}",
    r"(?<!\w)\+?\d[\d\s().-]{7,}\d(?!\w)",
))

INFRA_PATTERNS = tuple(re.compile(p, _I) for p in (
    r"\b\d{1,3}(\.\d{1,3}){3}\b",
    r"\b[a-z0-9-]+(\.[a-z0-9-]+)*\.(corp|internal|local|lan|intra)\b",
    r"\\\\[a-z0-9._-]+\\",
    r"\bhttps?://|\bwww\.",
    r"<[a-z/!][^>]*>",
    r"\]\(",
))

_STEP_RE = re.compile(r"^\s*(\d{1,2})[.)]\s+(.+)$")


@dataclass(frozen=True)
class SanitizedArticle:
    summary: Optional[str]
    steps: tuple[str, ...]
    dropped_lines: int


class ArticleQuarantined(Exception):
    """The article contains instruction-like content and must not be shown."""


def _any(patterns, text: str) -> bool:
    return any(p.search(text) for p in patterns)


_EMPHASIS = str.maketrans("", "", "*_`~")


def _normalize(line: str) -> str:
    """
    The single representation that is both checked and displayed: NFKC
    (fullwidth -> ASCII), format / control characters removed (zero-width,
    soft hyphen, bidi overrides), markdown emphasis removed, whitespace
    collapsed.
    """
    line = unicodedata.normalize("NFKC", line.replace("\t", " "))
    line = "".join(ch for ch in line if unicodedata.category(ch) not in ("Cf", "Cc"))
    line = line.translate(_EMPHASIS)
    return re.sub(r"\s+", " ", line).strip()


def _clean(line: str) -> str:
    """Display form of an already-normalized, already-checked line."""
    line = line.strip().lstrip(">#").strip()
    return line if len(line) <= MAX_LINE else line[: MAX_LINE - 1].rstrip() + "…"


def contains_instructions(text: str) -> bool:
    """True if *text* (raw or normalized) contains instruction-like content."""
    return _any(INJECTION_PATTERNS, text) or _any(INJECTION_PATTERNS, _normalize(text))


def _unsafe(text: str) -> bool:
    return (_any(SECRET_PATTERNS, text) or _any(INTERNAL_PATTERNS, text)
            or _any(PII_PATTERNS, text) or _any(INFRA_PATTERNS, text))


def safe_text(text: str) -> Optional[str]:
    """
    Normalized display text for a single untrusted value, or None if it is
    instruction-like or contains secrets, internal notes, PII,
    infrastructure details or URLs.
    """
    if not isinstance(text, str) or contains_instructions(text):
        return None
    normalized = _normalize(text)
    if _unsafe(normalized):
        return None
    return _clean(normalized) or None


def sanitize_article(article: KnowledgeArticle) -> Optional[SanitizedArticle]:
    """
    Safe summary + steps, or ``None`` if nothing safe remains.
    Raises ``ArticleQuarantined`` if any part contains instruction-like text.
    """
    raw_lines = article.body.splitlines()
    lines = [_normalize(raw) for raw in raw_lines]
    # Injection is checked on the normalized text AND the original (code
    # fences / markup are themselves a signal that normalization removes).
    for text in (_normalize(article.title), article.title, *lines, *raw_lines):
        if _any(INJECTION_PATTERNS, text):
            raise ArticleQuarantined(article.article_id)

    summary: Optional[str] = None
    steps: list[str] = []
    dropped = 0
    for line in lines:
        if not line:
            continue
        match = _STEP_RE.match(line)
        # Check both the whole line and the step text ("2. [Internal] …").
        candidates = (line, match.group(2)) if match else (line,)
        if any(_unsafe(t) for t in candidates):
            dropped += 1
            continue
        if match:
            text = _clean(match.group(2))
            if text and len(steps) < MAX_STEPS:
                steps.append(text)
        elif summary is None:
            summary = _clean(line) or None

    if not steps and not summary:
        return None
    return SanitizedArticle(summary=summary, steps=tuple(steps), dropped_lines=dropped)


def safe_title(article: KnowledgeArticle) -> Optional[str]:
    """The title, or None if it is not safe to display."""
    title = _normalize(article.title)
    if _unsafe(title):
        return None
    return _clean(title) or None
