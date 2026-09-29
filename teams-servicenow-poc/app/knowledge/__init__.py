"""
app.knowledge — Enterprise Knowledge (DEMO-03).

Read-only, side-effect-free knowledge retrieval: typed models, a repository
boundary, deterministic sanitization and grounded, cited answers.
"""

from app.knowledge.models import (
    Citation,
    KnowledgeArticle,
    KnowledgeCategory,
    KnowledgeHit,
    KnowledgeOutcome,
    KnowledgeSearchRequest,
    KnowledgeSearchResult,
    KnowledgeStatus,
)
from app.knowledge.repository import (
    KnowledgeRepository,
    KnowledgeRepositoryError,
    LocalKnowledgeRepository,
    RankedArticle,
)
from app.knowledge.service import KnowledgeService, format_knowledge_answer

__all__ = [
    "Citation",
    "KnowledgeArticle",
    "KnowledgeCategory",
    "KnowledgeHit",
    "KnowledgeOutcome",
    "KnowledgeRepository",
    "KnowledgeRepositoryError",
    "KnowledgeSearchRequest",
    "KnowledgeSearchResult",
    "KnowledgeService",
    "KnowledgeStatus",
    "LocalKnowledgeRepository",
    "RankedArticle",
    "format_knowledge_answer",
]
