"""
app/history/service.py — Historical similar cases (DEMO-04).

``is_history_question`` deterministically recognises "have we seen this
before?"-style questions (without the LLM).  ``HistoricalCaseService.search``
retrieves ranked candidates through the repository, re-checks eligibility,
withholds cases whose free text looks like instructions, and returns
``CaseEvidence`` built from controlled fields only.  It never raises.

``format_history_answer`` summarizes the PATTERN across the retrieved cases
(which fixes resolved them, how often) using fixed labels, and cites each
case by its reference.  Case free text is never displayed, never copied and
never sent to the LLM; historical cases are evidence, not instructions, and
they never trigger any action.  No ServiceNow call, no state change.
"""

from __future__ import annotations

import logging
import re
from collections import Counter

from app.history.models import (
    CaseEvidence,
    CaseOutcome,
    CaseSearchRequest,
    CaseSearchResult,
    HistoricalCase,
    SymptomTag,
)
from app.history.repository import HistoricalCaseRepository
from app.knowledge.models import tokenize
from app.knowledge.sanitize import contains_instructions

logger = logging.getLogger(__name__)


# ===========================================================================
# Deterministic question detection
# ===========================================================================

_HISTORY_PATTERNS = tuple(re.compile(p) for p in (
    r"\bhave (we|you|others|people|anyone|anybody) (ever )?(seen|had|dealt with|encountered)\b",
    r"\b(seen|had) (this|that|it|something like (this|that)|this issue|this problem) before\b",
    r"\b(happened|occurred|come up) before\b",
    r"\bsimilar (cases|incidents|issues|tickets|problems)\b",
    r"\b(has|have) (anyone|anybody|someone|others) else\b",
    r"\b(past|previous|historical|earlier|prior) (cases|incidents|tickets|issues)\b",
    r"\bhow (was|were|has|have) (this|these|it|that|they) (been )?(fixed|resolved|solved) before\b",
    r"\bseen (\w+ ){0,4}before\b",
))

# A request to create/raise/log a ticket is never treated as a history question.
_CREATE_RE = re.compile(
    r"\b(create|raise|log|open|submit|file|report)\b.{0,30}\b(incident|ticket)\b")


def is_history_question(message: str) -> bool:
    if not isinstance(message, str):
        return False
    text = " ".join(message.casefold().split())[:500]
    if _CREATE_RE.search(text):
        return False
    return any(p.search(text) for p in _HISTORY_PATTERNS)


# ===========================================================================
# Service
# ===========================================================================

def _best_symptom(case: HistoricalCase, tokens: frozenset[str]) -> SymptomTag:
    """The case's symptom tag that best matches the query (stable order)."""
    return max(case.symptoms,
               key=lambda tag: (len(tokens & frozenset(tokenize(tag.keywords))),
                                -list(SymptomTag).index(tag)))


class HistoricalCaseService:

    def __init__(self, repository: HistoricalCaseRepository) -> None:
        if not isinstance(repository, HistoricalCaseRepository):
            raise TypeError("HistoricalCaseService requires a HistoricalCaseRepository")
        self._repository = repository

    async def search(self, request: CaseSearchRequest) -> CaseSearchResult:
        if not isinstance(request, CaseSearchRequest):
            raise TypeError("search requires a CaseSearchRequest")
        if request.empty:
            return CaseSearchResult(CaseOutcome.NEEDS_TOPIC)
        try:
            candidates = await self._repository.search(request)
        except Exception as exc:  # noqa: BLE001
            logger.warning("history: repository search failed (%s)", type(exc).__name__)
            return CaseSearchResult(CaseOutcome.UNAVAILABLE)

        tokens = frozenset(request.tokens)
        evidence: list[CaseEvidence] = []
        withheld = 0
        seen: set[str] = set()
        for candidate in candidates or ():
            if len(evidence) >= request.max_results:
                break
            case = getattr(candidate, "case", None)
            score = getattr(candidate, "score", None)
            if not isinstance(case, HistoricalCase) or not case.usable \
                    or case.case_ref in seen or not isinstance(score, int):
                continue
            seen.add(case.case_ref)
            if contains_instructions(case.description) \
                    or contains_instructions(case.resolution_notes):
                logger.warning("history: withheld case %s (instruction-like content)",
                               case.case_ref)
                withheld += 1
                continue
            evidence.append(CaseEvidence(
                case_ref=case.case_ref,
                category=case.category,
                symptom=_best_symptom(case, tokens),
                resolution=case.resolution,
                score=score,
            ))

        outcome = CaseOutcome.FOUND if evidence else CaseOutcome.NO_MATCH
        return CaseSearchResult(outcome, tuple(evidence), withheld)


# ===========================================================================
# Pattern summary (controlled vocabulary only)
# ===========================================================================

NEEDS_TOPIC_MESSAGE = (
    "Which issue do you mean? For example: \"Have we seen VPN disconnects before?\""
)
NO_MATCH_MESSAGE = (
    "I couldn't find a sufficiently similar resolved case.\n\n"
    "If you'd like the service desk to look into it, say **create an incident**."
)
UNAVAILABLE_MESSAGE = (
    "The historical case archive is temporarily unavailable, so I couldn't search it. "
    "No action was taken. Please try again shortly."
)
SOURCE = "Historical case archive (sanitized summaries)"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def format_history_answer(result: CaseSearchResult) -> str:
    if result.outcome is CaseOutcome.NEEDS_TOPIC:
        return NEEDS_TOPIC_MESSAGE
    if result.outcome is CaseOutcome.UNAVAILABLE:
        return UNAVAILABLE_MESSAGE
    if not result.cases:
        return NO_MATCH_MESSAGE

    cases = result.cases
    total = len(cases)
    fixes = Counter(c.resolution for c in cases)
    order = {c.resolution: i for i, c in reversed(list(enumerate(cases)))}
    ranked = sorted(fixes.items(), key=lambda kv: (-kv[1], order[kv[0]]))
    top, top_count = ranked[0]

    # Fixes sharing the highest count (in first-seen order).
    leaders = [fix for fix, count in ranked if count == top_count]

    lines = [f"🗂️ I found {_plural(total, 'similar resolved case')}.", ""]
    if top_count > 1 and len(leaders) > 1:
        labels = [fix.label for fix in leaders]
        joined = ", ".join(labels[:-1]) + " and " + labels[-1]
        lines.append(f"**Pattern:** the most common fixes were {joined} "
                     f"({top_count} each).")
    elif top_count > 1:
        lines.append(f"**Pattern:** most were resolved by {top.label} "
                     f"({top_count} of {total}).")
    else:
        leaders = [top]
        lines.append(f"**Pattern:** each case had a different fix; "
                     f"the closest match was resolved by {top.label}.")
    others = [f"{fix.label} ({count})" for fix, count in ranked if fix not in leaders]
    if others:
        lines.append("Also seen: " + "; ".join(others) + ".")
    lines += ["", "Cases:"]
    # Every case that contributes to the pattern is cited.
    for c in cases:
        lines.append(f"- {c.case_ref} — {c.category.label} · {c.symptom.label} · "
                     f"resolved by {c.resolution.label}")
    lines += [
        "",
        "These are past cases for reference, not a diagnosis of your issue. "
        "If it's still not working, say **create an incident**.",
        "",
        f"Source: {SOURCE}",
    ]
    return "\n".join(lines)


def cited_case_refs(answer: str, result: CaseSearchResult) -> tuple[str, ...]:
    return tuple(r for r in result.case_refs if r in answer)


__all__ = [
    "NEEDS_TOPIC_MESSAGE",
    "NO_MATCH_MESSAGE",
    "UNAVAILABLE_MESSAGE",
    "HistoricalCaseService",
    "format_history_answer",
    "is_history_question",
]
