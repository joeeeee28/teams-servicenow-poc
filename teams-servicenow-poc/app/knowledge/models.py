"""
app/knowledge/models.py — Typed knowledge models (DEMO-03).

Every value is validated on construction, so a malformed article can never
reach retrieval or a user reply.  Models are immutable.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Optional

ARTICLE_ID_RE = re.compile(r"^KB[0-9]{7}$")
MAX_TITLE = 120
MAX_BODY = 8000
MAX_QUERY_CHARS = 500
MAX_QUERY_TOKENS = 32
MAX_RESULTS = 5


class KnowledgeStatus(str, Enum):
    APPROVED = "approved"
    DRAFT = "draft"
    RETIRED = "retired"


class KnowledgeCategory(str, Enum):
    NETWORK = "network"
    IDENTITY = "identity"
    COLLABORATION = "collaboration"
    EMAIL = "email"
    SERVICE_DESK = "service_desk"


class KnowledgeOutcome(str, Enum):
    FOUND = "found"
    NO_MATCH = "no_match"
    EMPTY_QUERY = "empty_query"
    UNAVAILABLE = "unavailable"


def _text(value: Any, name: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"knowledge article {name} must be non-empty text")
    if len(value) > limit:
        raise ValueError(f"knowledge article {name} exceeds {limit} characters")
    return value


@dataclass(frozen=True)
class KnowledgeArticle:
    """
    One knowledge article.  ``metadata`` is internal: it is used for ranking
    (``keywords``) only and is never shown to users.
    """

    article_id: str
    title: str
    body: str
    category: KnowledgeCategory
    status: KnowledgeStatus
    source: str
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.article_id, str) or not ARTICLE_ID_RE.fullmatch(self.article_id):
            raise ValueError("knowledge article_id must be KB followed by 7 digits")
        _text(self.title, "title", MAX_TITLE)
        _text(self.body, "body", MAX_BODY)
        _text(self.source, "source", MAX_TITLE)
        if not isinstance(self.category, KnowledgeCategory):
            raise ValueError("knowledge article category must be a KnowledgeCategory")
        if not isinstance(self.status, KnowledgeStatus):
            raise ValueError("knowledge article status must be a KnowledgeStatus")
        if not isinstance(self.metadata, Mapping) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in self.metadata.items()
        ):
            raise ValueError("knowledge article metadata must map text to text")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    @property
    def approved(self) -> bool:
        return self.status is KnowledgeStatus.APPROVED

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "KnowledgeArticle":
        """Build from a plain record; raises ``ValueError`` if malformed."""
        if not isinstance(record, Mapping):
            raise ValueError("knowledge record must be a mapping")
        try:
            return cls(
                article_id=record["article_id"],
                title=record["title"],
                body=record["body"],
                category=KnowledgeCategory(record["category"]),
                status=KnowledgeStatus(record["status"]),
                source=record["source"],
                metadata=record.get("metadata") or {},
            )
        except (KeyError, TypeError) as exc:
            raise ValueError("knowledge record is missing or has invalid fields") from exc


_STOPWORDS = frozenset("""
a an and are as at be but by can could do does did for from have how i i'm in is it
its me my of on or our please should so that the their them there this to try was
we what when where which who why will with would you your not isn't doesn't don't
can't cannot won't keeps keep get getting help need want know tell any some
""".split())


def _stem(token: str) -> str:
    """Tiny deterministic suffix stripper (connecting → connect)."""
    for suffix, min_len in (("ing", 6), ("ed", 5), ("es", 5), ("s", 4)):
        if len(token) >= min_len and token.endswith(suffix) and not token.endswith("ss"):
            return token[: -len(suffix)]
    return token


def tokenize(text: str) -> tuple[str, ...]:
    """Normalized, stemmed, stopword-free tokens (deterministic)."""
    normalized = unicodedata.normalize("NFKC", text).casefold()
    words = re.findall(r"[a-z0-9]+", normalized)
    return tuple(_stem(w) for w in words if w not in _STOPWORDS and 2 <= len(w) <= 40)


@dataclass(frozen=True)
class KnowledgeSearchRequest:
    """A validated search: the user's text reduced to search tokens."""

    query: str
    max_results: int = 3
    tokens: tuple[str, ...] = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.query, str):
            raise ValueError("knowledge query must be text")
        if isinstance(self.max_results, bool) or not isinstance(self.max_results, int) \
                or not 1 <= self.max_results <= MAX_RESULTS:
            raise ValueError(f"max_results must be between 1 and {MAX_RESULTS}")
        tokens = tokenize(self.query[:MAX_QUERY_CHARS])
        object.__setattr__(self, "tokens", tuple(dict.fromkeys(tokens))[:MAX_QUERY_TOKENS])

    @property
    def empty(self) -> bool:
        return not self.tokens

    def __repr__(self) -> str:  # never echo user text into logs
        return f"KnowledgeSearchRequest(tokens={len(self.tokens)}, max_results={self.max_results})"


@dataclass(frozen=True)
class Citation:
    article_id: str
    title: str
    source: str


@dataclass(frozen=True)
class KnowledgeHit:
    """A sanitized, displayable article excerpt."""

    citation: Citation
    category: KnowledgeCategory
    score: int
    summary: Optional[str]
    steps: tuple[str, ...]


@dataclass(frozen=True)
class KnowledgeSearchResult:
    outcome: KnowledgeOutcome
    hits: tuple[KnowledgeHit, ...] = ()
    withheld: int = 0
    """Matching approved articles withheld by sanitization (quarantined)."""

    @property
    def citations(self) -> tuple[Citation, ...]:
        return tuple(hit.citation for hit in self.hits)

    @property
    def article_ids(self) -> tuple[str, ...]:
        return tuple(c.article_id for c in self.citations)
