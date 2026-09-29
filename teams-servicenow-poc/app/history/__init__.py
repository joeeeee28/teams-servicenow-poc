"""
app.history — Historical similar cases (DEMO-04).

Read-only, side-effect-free search over sanitized, eligible, resolved cases.
Only controlled fields (case reference, category, symptom, resolution code)
are ever displayed; case free text is matching evidence only.
"""

from app.history.models import (
    CaseCategory,
    CaseEvidence,
    CaseOutcome,
    CaseSearchRequest,
    CaseSearchResult,
    CaseState,
    HistoricalCase,
    ResolutionCode,
    SymptomTag,
)
from app.history.repository import (
    HistoricalCaseRepository,
    HistoricalCaseRepositoryError,
    LocalHistoricalCaseRepository,
    RankedCase,
)
from app.history.service import (
    HistoricalCaseService,
    format_history_answer,
    is_history_question,
)

__all__ = [
    "CaseCategory",
    "CaseEvidence",
    "CaseOutcome",
    "CaseSearchRequest",
    "CaseSearchResult",
    "CaseState",
    "HistoricalCase",
    "HistoricalCaseRepository",
    "HistoricalCaseRepositoryError",
    "HistoricalCaseService",
    "LocalHistoricalCaseRepository",
    "RankedCase",
    "ResolutionCode",
    "SymptomTag",
    "format_history_answer",
    "is_history_question",
]
