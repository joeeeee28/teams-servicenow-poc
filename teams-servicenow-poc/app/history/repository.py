"""
app/history/repository.py — Historical case repository boundary (DEMO-04).

``HistoricalCaseRepository`` is the only way historical cases are read.  It
takes a typed ``CaseSearchRequest`` and returns ranked candidates.

``LocalHistoricalCaseRepository`` is the POC implementation: an in-memory,
deterministic index built from Python records (``app.history.fixture``).  No
file, database or network access.  A future ServiceNow-backed repository
would read from a curated, pre-sanitized export or a dedicated allowlisted
endpoint — never the generic Table API — and implement the same interface.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from app.history.models import CaseSearchRequest, HistoricalCase
from app.knowledge.models import tokenize

logger = logging.getLogger(__name__)

SYMPTOM_WEIGHT = 3
DESCRIPTION_WEIGHT = 1
MIN_SCORE = 3


class HistoricalCaseRepositoryError(Exception):
    def __init__(self) -> None:
        super().__init__("historical case repository unavailable")


@dataclass(frozen=True)
class RankedCase:
    case: HistoricalCase
    score: int


class HistoricalCaseRepository(abc.ABC):

    @abc.abstractmethod
    async def search(self, request: CaseSearchRequest) -> Sequence[RankedCase]:
        """
        Ranked candidates, best first.  Implementations return only usable
        (resolved/closed, eligible, resolved-with-code) cases and raise
        ``HistoricalCaseRepositoryError`` if the source cannot be searched.
        """


@dataclass(frozen=True)
class _Indexed:
    case: HistoricalCase
    symptoms: frozenset[str]
    text: frozenset[str]


class LocalHistoricalCaseRepository(HistoricalCaseRepository):
    """
    Score = 3 × symptom-keyword matches + 1 × description/resolution-note
    matches (distinct query tokens).  A case must match at least one symptom
    keyword (score ≥ 3).  Ties broken by case reference.
    """

    def __init__(self, cases: Iterable[HistoricalCase]) -> None:
        index: dict[str, _Indexed] = {}
        for case in cases:
            if not isinstance(case, HistoricalCase):
                raise TypeError("LocalHistoricalCaseRepository accepts HistoricalCase only")
            if case.case_ref in index:
                raise ValueError(f"duplicate historical case {case.case_ref}")
            index[case.case_ref] = _Indexed(
                case=case,
                symptoms=frozenset(t for tag in case.symptoms for t in tokenize(tag.keywords)),
                text=frozenset(tokenize(f"{case.description} {case.resolution_notes}")),
            )
        self._index = tuple(index[k] for k in sorted(index))

    @classmethod
    def from_records(cls, records: Iterable[Mapping]) -> "LocalHistoricalCaseRepository":
        cases = []
        for position, record in enumerate(records):
            try:
                cases.append(HistoricalCase.from_record(record))
            except ValueError:
                logger.warning("history: skipped malformed record at position %d", position)
        return cls(cases)

    @classmethod
    def from_fixture(cls) -> "LocalHistoricalCaseRepository":
        from app.history.fixture import HISTORICAL_CASE_RECORDS

        return cls.from_records(HISTORICAL_CASE_RECORDS)

    async def search(self, request: CaseSearchRequest) -> Sequence[RankedCase]:
        if not isinstance(request, CaseSearchRequest):
            raise TypeError("search requires a CaseSearchRequest")
        query = frozenset(request.tokens)
        ranked = []
        for entry in self._index:
            if not entry.case.usable:
                continue
            symptom_hits = len(query & entry.symptoms)
            if not symptom_hits:
                continue
            score = SYMPTOM_WEIGHT * symptom_hits + DESCRIPTION_WEIGHT * len(query & entry.text)
            if score >= MIN_SCORE:
                ranked.append(RankedCase(entry.case, score))
        ranked.sort(key=lambda r: (-r.score, r.case.case_ref))
        return tuple(ranked)
