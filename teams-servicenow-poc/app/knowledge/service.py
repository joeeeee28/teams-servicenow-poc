"""
app/knowledge/service.py — Knowledge service and grounded answers (DEMO-03).

``KnowledgeService.search`` validates the request, asks the repository for
ranked candidates, re-checks approval (defence in depth), sanitizes every
candidate and returns a typed ``KnowledgeSearchResult`` with citations.  It
never raises: repository failures become ``UNAVAILABLE``.

``format_knowledge_answer`` builds the Teams reply *extractively* from the
sanitized steps of the retrieved articles, with a citation for each article
shown.  Nothing is generated: no procedure, command, URL, credential or
policy can appear unless it is in an approved, sanitized article, and no
citation can appear for an article that was not retrieved.  In this POC the
LLM never sees knowledge content at all.

The service has no ServiceNow, tool-gateway, persistence or LLM dependency,
and never changes state: a knowledge lookup has no side effects.
"""

from __future__ import annotations

import logging

from app.knowledge.models import (
    Citation,
    KnowledgeHit,
    KnowledgeOutcome,
    KnowledgeSearchRequest,
    KnowledgeSearchResult,
)
from app.knowledge.repository import KnowledgeRepository
from app.knowledge.sanitize import ArticleQuarantined, safe_title, sanitize_article

logger = logging.getLogger(__name__)


class KnowledgeService:

    def __init__(self, repository: KnowledgeRepository) -> None:
        if not isinstance(repository, KnowledgeRepository):
            raise TypeError("KnowledgeService requires a KnowledgeRepository")
        self._repository = repository

    async def search(self, request: KnowledgeSearchRequest) -> KnowledgeSearchResult:
        if not isinstance(request, KnowledgeSearchRequest):
            raise TypeError("search requires a KnowledgeSearchRequest")
        if request.empty:
            return KnowledgeSearchResult(KnowledgeOutcome.EMPTY_QUERY)
        try:
            candidates = await self._repository.search(request)
        except Exception as exc:  # noqa: BLE001 — never surface repository internals
            logger.warning("knowledge: repository search failed (%s)", type(exc).__name__)
            return KnowledgeSearchResult(KnowledgeOutcome.UNAVAILABLE)

        hits: list[KnowledgeHit] = []
        withheld = 0
        seen: set[str] = set()
        for candidate in candidates or ():
            if len(hits) >= request.max_results:
                break
            article = getattr(candidate, "article", None)
            score = getattr(candidate, "score", None)
            if article is None or not getattr(article, "approved", False) \
                    or article.article_id in seen or not isinstance(score, int):
                continue
            seen.add(article.article_id)
            try:
                sanitized = sanitize_article(article)
            except ArticleQuarantined:
                logger.warning("knowledge: quarantined article %s (instruction-like content)",
                               article.article_id)
                withheld += 1
                continue
            title = safe_title(article)
            if sanitized is None or title is None:
                withheld += 1
                continue
            hits.append(KnowledgeHit(
                citation=Citation(article.article_id, title, article.source),
                category=article.category,
                score=score,
                summary=sanitized.summary,
                steps=sanitized.steps,
            ))

        outcome = KnowledgeOutcome.FOUND if hits else KnowledgeOutcome.NO_MATCH
        return KnowledgeSearchResult(outcome, tuple(hits), withheld)


# ===========================================================================
# Grounded, extractive answer
# ===========================================================================

NO_MATCH_MESSAGE = (
    "I couldn't find an approved knowledge article for that.\n\n"
    "If you'd like the service desk to look into it, say **create an incident**."
)
EMPTY_QUERY_MESSAGE = (
    "Please describe the problem in a few words so I can search the knowledge base."
)
UNAVAILABLE_MESSAGE = (
    "The knowledge base is temporarily unavailable, so I couldn't search it. "
    "No action was taken. Please try again shortly."
)


def _citation_line(citation: Citation) -> str:
    return f"{citation.article_id} — {citation.title} ({citation.source})"


def format_knowledge_answer(result: KnowledgeSearchResult) -> str:
    if result.outcome is KnowledgeOutcome.EMPTY_QUERY:
        return EMPTY_QUERY_MESSAGE
    if result.outcome is KnowledgeOutcome.UNAVAILABLE:
        return UNAVAILABLE_MESSAGE
    if not result.hits:
        return NO_MATCH_MESSAGE

    best = result.hits[0]
    lines = ["📚 I found a relevant approved knowledge article:",
             f"**{best.citation.title}**", ""]
    if best.summary:
        lines += [best.summary, ""]
    if best.steps:
        lines.append("Try:")
        lines += [f"{i}. {step}" for i, step in enumerate(best.steps, start=1)]
        lines.append("")
    lines.append(f"Source: {_citation_line(best.citation)}")
    related = result.hits[1:]
    if related:
        lines += ["", "Related articles:"]
        lines += [f"- {_citation_line(hit.citation)}" for hit in related]
    return "\n".join(lines)


def cited_article_ids(answer: str, result: KnowledgeSearchResult) -> tuple[str, ...]:
    """Article ids cited in *answer* that were actually retrieved (for tests/audit)."""
    return tuple(a for a in result.article_ids if a in answer)


__all__ = [
    "EMPTY_QUERY_MESSAGE",
    "KnowledgeService",
    "NO_MATCH_MESSAGE",
    "UNAVAILABLE_MESSAGE",
    "cited_article_ids",
    "format_knowledge_answer",
]
