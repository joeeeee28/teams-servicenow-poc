"""
app/catalog/service.py — Service catalog discovery (DEMO-05).

``CatalogService`` runs behind the Tool Gateway's ``SEARCH_CATALOG`` action.
It asks the repository for ranked candidates (or all available items when
browsing), re-checks that each item is active and approved, and converts
each into a display-safe ``CatalogEntry``: every piece of catalog text (name,
description, variable labels, choices) is untrusted and passes through the
DEMO-03 sanitizer; an item with any unsafe or instruction-like text is
withheld entirely.

``format_catalog_answer`` renders the reply: one match → name, purpose and
the information a request will need; several close matches → a clarification
question; none → an honest "no approved item" (no guessing).  Read-only:
nothing is requested, created or changed.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from app.catalog.models import (
    MAX_BROWSE,
    CatalogEntry,
    CatalogItem,
    CatalogOutcome,
    CatalogSearchRequest,
    CatalogSearchResult,
    VariableKind,
)
from app.catalog.repository import CatalogRepository
from app.knowledge.sanitize import contains_instructions, safe_text

logger = logging.getLogger(__name__)

# A single result is "found" only if it clearly beats the runner-up.
DOMINANCE = 2

# Explicit catalog-browsing questions / commands, recognised without the LLM.
# A bare mention of "service catalog" or "catalog items" is NOT browse intent
# (e.g. "the service catalog page is broken" is a problem report).
_BROWSE_PATTERNS = tuple(re.compile(p) for p in (
    r"\bwhat (else )?(can|could|may) i (request|order)\b",
    r"\bwhat( is|'s|\u2019s) (available )?(in|on) the (service )?catalog(ue)?\b",
    r"\b(show|list|browse|open|see) (me )?(the )?(service )?catalog(ue)?\b",
))
_CREATE_RE = re.compile(
    r"\b(create|raise|log|open|submit|file|report)\b.{0,30}\b(incident|ticket)\b")


def is_catalog_browse(message: str) -> bool:
    """True for an explicit "what can I request?" / catalog question."""
    if not isinstance(message, str):
        return False
    text = " ".join(message.casefold().split())[:500]
    if _CREATE_RE.search(text):
        return False
    return any(p.search(text) for p in _BROWSE_PATTERNS)


class CatalogUnavailableError(Exception):
    def __init__(self) -> None:
        super().__init__("service catalog unavailable")


def _join(choices: tuple[str, ...]) -> str:
    return choices[0] if len(choices) == 1 else ", ".join(choices[:-1]) + " or " + choices[-1]


def to_entry(item: CatalogItem, score: int = 0) -> Optional[CatalogEntry]:
    """Display-safe entry, or None if any displayed text is unsafe."""
    if not isinstance(item, CatalogItem) or not item.available:
        return None
    texts = [item.name, item.description] + [v.label for v in item.variables] \
        + [c for v in item.variables for c in v.choices]
    if any(contains_instructions(t) for t in texts):
        logger.warning("catalog: withheld item %s (instruction-like content)", item.item_ref)
        return None
    name, purpose = safe_text(item.name), safe_text(item.description)
    if name is None or purpose is None:
        return None
    required: list[str] = []
    for variable in item.variables:
        if not variable.required:
            continue
        label = safe_text(variable.label)
        choices = tuple(safe_text(c) for c in variable.choices)
        if label is None or None in choices:
            return None
        if variable.kind is VariableKind.CHOICE:
            label = f"{label} ({_join(choices)})"
        required.append(label)
    return CatalogEntry(item.item_ref, name, purpose, item.category, tuple(required), score)


class CatalogService:

    def __init__(self, repository: CatalogRepository) -> None:
        if not isinstance(repository, CatalogRepository):
            raise TypeError("CatalogService requires a CatalogRepository")
        self._repository = repository

    async def search(self, request: CatalogSearchRequest) -> CatalogSearchResult:
        """Raises ``CatalogUnavailableError`` if the repository fails."""
        if not isinstance(request, CatalogSearchRequest):
            raise TypeError("search requires a CatalogSearchRequest")
        try:
            if request.browse:
                items = await self._repository.list_available()
                ranked = [(item, 0) for item in items or ()]
            else:
                candidates = await self._repository.search(request)
                ranked = [(getattr(c, "item", None), getattr(c, "score", None))
                          for c in candidates or ()]
        except Exception as exc:  # noqa: BLE001
            logger.warning("catalog: repository failed (%s)", type(exc).__name__)
            raise CatalogUnavailableError() from None

        limit = MAX_BROWSE if request.browse else request.max_results
        entries: list[CatalogEntry] = []
        withheld = 0
        seen: set[str] = set()
        for item, score in ranked:
            if len(entries) >= limit:
                break
            if not isinstance(item, CatalogItem) or not isinstance(score, int) \
                    or not item.available or item.item_ref in seen:
                continue
            seen.add(item.item_ref)
            entry = to_entry(item, score)
            if entry is None:
                withheld += 1
                continue
            entries.append(entry)

        if request.browse:
            return CatalogSearchResult(CatalogOutcome.BROWSE, tuple(entries), withheld)
        if not entries:
            return CatalogSearchResult(CatalogOutcome.NO_MATCH, (), withheld)
        if len(entries) == 1 or entries[0].score >= DOMINANCE * entries[1].score:
            return CatalogSearchResult(CatalogOutcome.FOUND, entries[:1], withheld)
        return CatalogSearchResult(CatalogOutcome.AMBIGUOUS, tuple(entries), withheld)


# ===========================================================================
# Replies
# ===========================================================================

NO_MATCH_MESSAGE = (
    "I couldn't find an approved catalog item for that, and I won't guess one.\n\n"
    "Try different words, or ask **what can I request?** to see the catalog."
)
UNAVAILABLE_MESSAGE = (
    "The service catalog is temporarily unavailable, so I couldn't search it. "
    "No request was created. Please try again shortly."
)
EMPTY_CATALOG_MESSAGE = "There are no approved catalog items available right now."
READ_ONLY_NOTE = "This is catalog information only — no request has been created."


def _item_line(entry: CatalogEntry) -> str:
    return f"**{entry.name}** ({entry.item_ref}) · {entry.category.label}"


def format_catalog_answer(result: CatalogSearchResult) -> str:
    if result.outcome is CatalogOutcome.BROWSE:
        if not result.entries:
            return EMPTY_CATALOG_MESSAGE
        lines = ["🛒 Here's what you can request from the approved catalog:", ""]
        categories: dict = {}
        for entry in result.entries:
            categories.setdefault(entry.category, []).append(entry)
        for category, entries in categories.items():
            items = ", ".join(f"{e.name} ({e.item_ref})" for e in entries)
            lines.append(f"**{category.label}:** {items}")
        lines += ["", "Tell me which item you need to see what a request requires.",
                  READ_ONLY_NOTE]
        return "\n".join(lines)

    if result.outcome is CatalogOutcome.NO_MATCH:
        return NO_MATCH_MESSAGE

    if result.outcome is CatalogOutcome.AMBIGUOUS:
        lines = ["🛒 I found several approved catalog items that could match. "
                 "Which one do you mean?", ""]
        lines += [f"{i}. {_item_line(e)} — {e.purpose}"
                  for i, e in enumerate(result.entries, start=1)]
        lines += ["", "Reply with the item name.", READ_ONLY_NOTE]
        return "\n".join(lines)

    entry = result.entries[0]
    lines = ["🛒 I found an approved catalog item:", "", _item_line(entry), entry.purpose, ""]
    if entry.required_info:
        lines.append("To request it, you'll need:")
        lines += [f"- {label}" for label in entry.required_info]
    else:
        lines.append("No additional information is needed to request it.")
    lines += ["", READ_ONLY_NOTE]
    return "\n".join(lines)
