"""
app/catalog/models.py — Typed service-catalog models (DEMO-05).

Every value is validated on construction.  ``sys_id`` is the ServiceNow
identifier kept for a later request step; it is never displayed or logged —
users see the stable ``item_ref`` (``CAT`` + 4 digits).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from app.knowledge.models import tokenize

ITEM_REF_RE = re.compile(r"^CAT[0-9]{4}$")
SYS_ID_RE = re.compile(r"^[0-9a-f]{32}$")
VARIABLE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,39}$")
MAX_NAME = 80
MAX_DESCRIPTION = 400
MAX_LABEL = 60
MAX_VARIABLES = 8
MAX_CHOICES = 10
MAX_RESULTS = 5
MAX_BROWSE = 10


class CatalogCategory(str, Enum):
    SOFTWARE = "software"
    ACCESS = "access"
    HARDWARE = "hardware"
    NETWORK = "network"

    @property
    def label(self) -> str:
        return self.value.capitalize()


class VariableKind(str, Enum):
    TEXT = "text"
    CHOICE = "choice"


def _text(value: Any, name: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"catalog {name} must be non-empty text of at most {limit} characters")
    return value


@dataclass(frozen=True)
class CatalogVariable:
    """Information a requester must provide (collected in a later step)."""

    name: str
    label: str
    required: bool = True
    kind: VariableKind = VariableKind.TEXT
    choices: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not VARIABLE_NAME_RE.fullmatch(self.name):
            raise ValueError("catalog variable name must be a lower-case identifier")
        _text(self.label, "variable label", MAX_LABEL)
        if not isinstance(self.required, bool):
            raise ValueError("catalog variable required must be a bool")
        if not isinstance(self.kind, VariableKind):
            raise ValueError("catalog variable kind must be a VariableKind")
        if not isinstance(self.choices, tuple) or len(self.choices) > MAX_CHOICES:
            raise ValueError("catalog variable choices must be a short tuple")
        for choice in self.choices:
            _text(choice, "variable choice", 40)
        if (self.kind is VariableKind.CHOICE) != bool(self.choices):
            raise ValueError("choice variables need choices; text variables must not have any")


@dataclass(frozen=True)
class CatalogItem:
    item_ref: str
    sys_id: str
    name: str
    description: str
    category: CatalogCategory
    active: bool
    approved: bool
    variables: tuple[CatalogVariable, ...] = ()
    keywords: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.item_ref, str) or not ITEM_REF_RE.fullmatch(self.item_ref):
            raise ValueError("catalog item_ref must be CAT followed by 4 digits")
        if not isinstance(self.sys_id, str) or not SYS_ID_RE.fullmatch(self.sys_id):
            raise ValueError("catalog sys_id must be 32 lower-case hex characters")
        _text(self.name, "name", MAX_NAME)
        _text(self.description, "description", MAX_DESCRIPTION)
        if not isinstance(self.category, CatalogCategory):
            raise ValueError("catalog category must be a CatalogCategory")
        if not isinstance(self.active, bool) or not isinstance(self.approved, bool):
            raise ValueError("catalog active / approved must be bools")
        if not isinstance(self.variables, tuple) or len(self.variables) > MAX_VARIABLES \
                or not all(isinstance(v, CatalogVariable) for v in self.variables):
            raise ValueError("catalog variables must be a short tuple of CatalogVariable")
        if len({v.name for v in self.variables}) != len(self.variables):
            raise ValueError("catalog variable names must be unique")
        if not isinstance(self.keywords, str) or len(self.keywords) > 300:
            raise ValueError("catalog keywords must be short text")

    @property
    def available(self) -> bool:
        """Only active AND approved items can ever be returned."""
        return self.active and self.approved

    def __repr__(self) -> str:
        return f"CatalogItem({self.item_ref}, available={self.available})"

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "CatalogItem":
        if not isinstance(record, Mapping):
            raise ValueError("catalog record must be a mapping")
        try:
            variables = tuple(
                CatalogVariable(
                    name=v["name"], label=v["label"], required=v.get("required", True),
                    kind=VariableKind(v.get("kind", "text")),
                    choices=tuple(v.get("choices", ())),
                )
                for v in record.get("variables", ())
            )
            return cls(
                item_ref=record["item_ref"], sys_id=record["sys_id"], name=record["name"],
                description=record["description"], category=CatalogCategory(record["category"]),
                active=record["active"], approved=record["approved"], variables=variables,
                keywords=record.get("keywords", ""),
            )
        except (KeyError, TypeError, AttributeError) as exc:
            raise ValueError("catalog record is missing or has invalid fields") from exc


# Words that ask for the catalog but say nothing about the item.
_REQUEST_WORDS = frozenset(tokenize(
    "need want would like request requesting order ordering get getting install "
    "installed new please can could what which available catalog catalogue item items "
    "service services give me some access to"
)) - {"access"}


@dataclass(frozen=True)
class CatalogSearchRequest:
    query: str
    max_results: int = MAX_RESULTS
    tokens: tuple[str, ...] = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.query, str):
            raise ValueError("catalog query must be text")
        if isinstance(self.max_results, bool) or not isinstance(self.max_results, int) \
                or not 1 <= self.max_results <= MAX_RESULTS:
            raise ValueError(f"max_results must be between 1 and {MAX_RESULTS}")
        tokens = [t for t in tokenize(self.query[:500]) if t not in _REQUEST_WORDS]
        object.__setattr__(self, "tokens", tuple(dict.fromkeys(tokens))[:32])

    @property
    def browse(self) -> bool:
        """No item words: the user is asking what can be requested."""
        return not self.tokens

    def __repr__(self) -> str:
        return f"CatalogSearchRequest(tokens={len(self.tokens)}, max_results={self.max_results})"


class CatalogOutcome(str, Enum):
    FOUND = "found"
    AMBIGUOUS = "ambiguous"
    NO_MATCH = "no_match"
    BROWSE = "browse"


@dataclass(frozen=True)
class CatalogEntry:
    """Display-safe view of an available item (sanitized text only)."""

    item_ref: str
    name: str
    purpose: str
    category: CatalogCategory
    required_info: tuple[str, ...]
    score: int = 0


@dataclass(frozen=True)
class CatalogSearchResult:
    outcome: CatalogOutcome
    entries: tuple[CatalogEntry, ...] = ()
    withheld: int = 0

    @property
    def item_refs(self) -> tuple[str, ...]:
        return tuple(e.item_ref for e in self.entries)


__all__ = [
    "CatalogCategory", "CatalogEntry", "CatalogItem", "CatalogOutcome", "CatalogSearchRequest",
    "CatalogSearchResult", "CatalogVariable", "VariableKind",
]
