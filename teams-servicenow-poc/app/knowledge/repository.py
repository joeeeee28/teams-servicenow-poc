"""
app/knowledge/repository.py — Knowledge repository boundary (DEMO-03).

``KnowledgeRepository`` is the only way knowledge is read.  It takes a typed
``KnowledgeSearchRequest`` (search tokens, never raw text, table names,
queries or paths) and returns ranked candidate articles.

``LocalKnowledgeRepository`` is the POC implementation: an in-memory,
deterministic index built from Python records (``app.knowledge.fixture``).
It performs no file, database or network access.  A future
``ServiceNowKnowledgeRepository`` would implement the same interface through
a dedicated, allowlisted knowledge endpoint behind its own gateway — never the
generic Table API.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from app.knowledge.models import KnowledgeArticle, KnowledgeSearchRequest, tokenize

logger = logging.getLogger(__name__)

TITLE_WEIGHT = 3
KEYWORD_WEIGHT = 2
BODY_WEIGHT = 1
MIN_SCORE = 3


class KnowledgeRepositoryError(Exception):
    """The knowledge source could not be searched (fixed message)."""

    def __init__(self) -> None:
        super().__init__("knowledge repository unavailable")


@dataclass(frozen=True)
class RankedArticle:
    article: KnowledgeArticle
    score: int


class KnowledgeRepository(abc.ABC):
    """Read-only knowledge source."""

    @abc.abstractmethod
    async def search(self, request: KnowledgeSearchRequest) -> Sequence[RankedArticle]:
        """
        Ranked candidates for *request*, best first.  Implementations return
        only approved articles and raise ``KnowledgeRepositoryError`` if the
        source cannot be searched.
        """


@dataclass(frozen=True)
class _Indexed:
    article: KnowledgeArticle
    title: frozenset[str]
    keywords: frozenset[str]
    body: frozenset[str]


class LocalKnowledgeRepository(KnowledgeRepository):
    """
    Deterministic in-memory repository.  Score = 3 × title matches +
    2 × keyword matches + 1 × body matches (distinct query tokens); ties are
    broken by article id.  Candidates below ``MIN_SCORE`` are not returned.
    """

    def __init__(self, articles: Iterable[KnowledgeArticle]) -> None:
        index: dict[str, _Indexed] = {}
        for article in articles:
            if not isinstance(article, KnowledgeArticle):
                raise TypeError("LocalKnowledgeRepository accepts KnowledgeArticle only")
            if article.article_id in index:
                raise ValueError(f"duplicate knowledge article id {article.article_id}")
            index[article.article_id] = _Indexed(
                article=article,
                title=frozenset(tokenize(article.title)),
                keywords=frozenset(tokenize(article.metadata.get("keywords", ""))),
                body=frozenset(tokenize(article.body)),
            )
        self._index = tuple(index[k] for k in sorted(index))

    @classmethod
    def from_records(cls, records: Iterable[Mapping]) -> "LocalKnowledgeRepository":
        """Build from plain records, skipping (and logging) malformed ones."""
        articles = []
        for position, record in enumerate(records):
            try:
                articles.append(KnowledgeArticle.from_record(record))
            except ValueError:
                logger.warning("knowledge: skipped malformed record at position %d", position)
        return cls(articles)

    @classmethod
    def from_fixture(cls) -> "LocalKnowledgeRepository":
        from app.knowledge.fixture import KNOWLEDGE_RECORDS

        return cls.from_records(KNOWLEDGE_RECORDS)

    async def search(self, request: KnowledgeSearchRequest) -> Sequence[RankedArticle]:
        if not isinstance(request, KnowledgeSearchRequest):
            raise TypeError("search requires a KnowledgeSearchRequest")
        query = frozenset(request.tokens)
        ranked = []
        for entry in self._index:
            if not entry.article.approved:
                continue
            score = (TITLE_WEIGHT * len(query & entry.title)
                     + KEYWORD_WEIGHT * len(query & entry.keywords)
                     + BODY_WEIGHT * len(query & entry.body))
            if score >= MIN_SCORE:
                ranked.append(RankedArticle(entry.article, score))
        ranked.sort(key=lambda r: (-r.score, r.article.article_id))
        return tuple(ranked)
