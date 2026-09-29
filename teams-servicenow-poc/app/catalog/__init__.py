"""
app.catalog — Service catalog discovery (DEMO-05).

Read-only discovery of approved catalog items, served behind the Tool
Gateway's ``SEARCH_CATALOG`` action.  Nothing is requested or changed.
"""

from app.catalog.models import (
    CatalogCategory,
    CatalogEntry,
    CatalogItem,
    CatalogOutcome,
    CatalogSearchRequest,
    CatalogSearchResult,
    CatalogVariable,
    VariableKind,
)
from app.catalog.repository import (
    CatalogRepository,
    CatalogRepositoryError,
    LocalCatalogRepository,
    RankedItem,
)
from app.catalog.service import (
    CatalogService,
    CatalogUnavailableError,
    format_catalog_answer,
    is_catalog_browse,
)

__all__ = [
    "CatalogCategory",
    "CatalogEntry",
    "CatalogItem",
    "CatalogOutcome",
    "CatalogRepository",
    "CatalogRepositoryError",
    "CatalogSearchRequest",
    "CatalogSearchResult",
    "CatalogService",
    "CatalogUnavailableError",
    "CatalogVariable",
    "LocalCatalogRepository",
    "RankedItem",
    "VariableKind",
    "format_catalog_answer",
    "is_catalog_browse",
]
