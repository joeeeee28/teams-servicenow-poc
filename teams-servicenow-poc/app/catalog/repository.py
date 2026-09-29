"""
app/catalog/repository.py — Catalog repository boundary (DEMO-05).

``CatalogRepository`` is the catalog source behind the Tool Gateway's
``SEARCH_CATALOG`` action.  It takes a typed ``CatalogSearchRequest`` (search
tokens — never table names, queries or raw text) and returns ranked
candidates, or lists available items for browsing.

``LocalCatalogRepository`` is the POC implementation: the approved catalog
compiled in as Python records (``app.catalog.fixture``); no file, database or
network access.  A future ``ServiceNowCatalogRepository`` would read the
ServiceNow catalog through a fixed table / fixed fields / fixed query in the
ServiceNow adapter, filtered to the approved allowlist, and plug in here
without changing the gateway contract or the handler.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from app.catalog.models import CatalogItem, CatalogSearchRequest
from app.knowledge.models import tokenize

logger = logging.getLogger(__name__)

NAME_WEIGHT = 3
KEYWORD_WEIGHT = 2
DESCRIPTION_WEIGHT = 1
MIN_SCORE = 3


class CatalogRepositoryError(Exception):
    def __init__(self) -> None:
        super().__init__("catalog repository unavailable")


@dataclass(frozen=True)
class RankedItem:
    item: CatalogItem
    score: int


class CatalogRepository(abc.ABC):

    @abc.abstractmethod
    async def search(self, request: CatalogSearchRequest) -> Sequence[RankedItem]:
        """Ranked available items, best first."""

    @abc.abstractmethod
    async def list_available(self) -> Sequence[CatalogItem]:
        """All available items in a stable order (for browsing)."""


@dataclass(frozen=True)
class _Indexed:
    item: CatalogItem
    name: frozenset[str]
    keywords: frozenset[str]
    description: frozenset[str]


class LocalCatalogRepository(CatalogRepository):
    """
    Score = 3 × name matches + 2 × keyword matches + 1 × description matches
    (distinct query tokens); below 3 is not a match; ties by item reference.
    Only ``available`` (active and approved) items are ever returned.
    """

    def __init__(self, items: Iterable[CatalogItem]) -> None:
        index: dict[str, _Indexed] = {}
        for item in items:
            if not isinstance(item, CatalogItem):
                raise TypeError("LocalCatalogRepository accepts CatalogItem only")
            if item.item_ref in index:
                raise ValueError(f"duplicate catalog item {item.item_ref}")
            index[item.item_ref] = _Indexed(
                item=item,
                name=frozenset(tokenize(item.name)),
                keywords=frozenset(tokenize(item.keywords)),
                description=frozenset(tokenize(item.description)),
            )
        self._index = tuple(index[k] for k in sorted(index))

    @classmethod
    def from_records(cls, records: Iterable[Mapping]) -> "LocalCatalogRepository":
        items = []
        for position, record in enumerate(records):
            try:
                items.append(CatalogItem.from_record(record))
            except ValueError:
                logger.warning("catalog: skipped malformed record at position %d", position)
        return cls(items)

    @classmethod
    def from_fixture(cls) -> "LocalCatalogRepository":
        from app.catalog.fixture import CATALOG_RECORDS

        return cls.from_records(CATALOG_RECORDS)

    async def search(self, request: CatalogSearchRequest) -> Sequence[RankedItem]:
        if not isinstance(request, CatalogSearchRequest):
            raise TypeError("search requires a CatalogSearchRequest")
        query = frozenset(request.tokens)
        ranked = []
        for entry in self._index:
            if not entry.item.available:
                continue
            score = (NAME_WEIGHT * len(query & entry.name)
                     + KEYWORD_WEIGHT * len(query & entry.keywords)
                     + DESCRIPTION_WEIGHT * len(query & entry.description))
            if score >= MIN_SCORE:
                ranked.append(RankedItem(entry.item, score))
        ranked.sort(key=lambda r: (-r.score, r.item.item_ref))
        return tuple(ranked)

    async def list_available(self) -> Sequence[CatalogItem]:
        return tuple(e.item for e in self._index if e.item.available)

    def get_item_by_ref(self, item_ref: str) -> Optional[CatalogItem]:
        for entry in self._index:
            if entry.item.item_ref == item_ref and entry.item.available:
                return entry.item
        return None
