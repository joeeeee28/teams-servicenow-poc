"""
app/history/models.py — Typed historical-case models (DEMO-04).

A ``HistoricalCase`` holds two kinds of data:

  * CONTROLLED fields (``case_ref``, category, symptom tags, resolution code)
    — the only things that can ever be shown to a user;
  * FREE-TEXT fields (description, resolution notes, work notes, caller) —
    untrusted evidence used for matching only, never displayed, never sent to
    the LLM, never interpreted as instructions.

Displayed wording comes from fixed labels on the controlled enums, so a
historical case's text can never be copied into a reply.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Optional

from app.knowledge.models import tokenize

CASE_REF_RE = re.compile(r"^HC[0-9]{5}$")
INCIDENT_RE = re.compile(r"^INC[0-9]{7,10}$")
MAX_TEXT = 4000
MAX_RESULTS = 5


class CaseState(str, Enum):
    NEW = "new"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    CANCELLED = "cancelled"


class CaseCategory(str, Enum):
    NETWORK = "network"
    IDENTITY = "identity"
    COLLABORATION = "collaboration"
    EMAIL = "email"
    HARDWARE = "hardware"

    @property
    def label(self) -> str:
        return _CATEGORY_LABELS[self]


_CATEGORY_LABELS = {
    CaseCategory.NETWORK: "Network",
    CaseCategory.IDENTITY: "Identity & access",
    CaseCategory.COLLABORATION: "Collaboration",
    CaseCategory.EMAIL: "Email",
    CaseCategory.HARDWARE: "Hardware",
}


class SymptomTag(str, Enum):
    VPN_DISCONNECTS = "vpn_disconnects"
    VPN_CANNOT_CONNECT = "vpn_cannot_connect"
    OUTLOOK_NOT_SYNCING = "outlook_not_syncing"
    TEAMS_NO_AUDIO = "teams_no_audio"
    TEAMS_SIGN_IN = "teams_sign_in"
    MFA_NO_PROMPT = "mfa_no_prompt"
    MFA_CODE_REJECTED = "mfa_code_rejected"
    ACCOUNT_LOCKED = "account_locked"
    PRINTER_OFFLINE = "printer_offline"

    @property
    def label(self) -> str:
        return _SYMPTOMS[self][0]

    @property
    def keywords(self) -> str:
        return _SYMPTOMS[self][1]


_SYMPTOMS = {
    SymptomTag.VPN_DISCONNECTS: ("VPN keeps disconnecting", "vpn disconnect drop dropping"),
    SymptomTag.VPN_CANNOT_CONNECT: ("VPN will not connect", "vpn connect connection"),
    SymptomTag.OUTLOOK_NOT_SYNCING: ("Outlook not syncing email",
                                     "outlook email mail sync syncing inbox receive"),
    SymptomTag.TEAMS_NO_AUDIO: ("No audio in Teams meetings",
                                "teams audio microphone sound speaker meeting"),
    SymptomTag.TEAMS_SIGN_IN: ("Cannot sign in to Teams", "teams sign login"),
    SymptomTag.MFA_NO_PROMPT: ("MFA prompt not arriving",
                               "mfa prompt notification authenticator push"),
    SymptomTag.MFA_CODE_REJECTED: ("MFA code rejected", "mfa code verification rejected"),
    SymptomTag.ACCOUNT_LOCKED: ("Account locked out", "account locked lockout password"),
    SymptomTag.PRINTER_OFFLINE: ("Printer offline", "printer print printing offline"),
}


class ResolutionCode(str, Enum):
    RESTART_CLIENT = "restart_client"
    REAUTHENTICATE = "reauthenticate"
    RESET_NETWORK = "reset_network"
    UPDATE_CLIENT = "update_client"
    REBUILD_PROFILE = "rebuild_profile"
    SELECT_DEVICE = "select_device"
    REREGISTER_MFA = "reregister_mfa"
    SYNC_DEVICE_TIME = "sync_device_time"
    PASSWORD_RESET = "password_reset"
    SERVICE_FIX = "service_fix"
    REPLACE_HARDWARE = "replace_hardware"

    @property
    def label(self) -> str:
        return _RESOLUTIONS[self]


_RESOLUTIONS = {
    ResolutionCode.RESTART_CLIENT: "restarting the affected application",
    ResolutionCode.REAUTHENTICATE: "signing out and signing in again",
    ResolutionCode.RESET_NETWORK: "resetting the network connection",
    ResolutionCode.UPDATE_CLIENT: "updating the client application",
    ResolutionCode.REBUILD_PROFILE: "recreating the mail profile",
    ResolutionCode.SELECT_DEVICE: "selecting the correct audio or video device",
    ResolutionCode.REREGISTER_MFA: "re-registering the MFA device",
    ResolutionCode.SYNC_DEVICE_TIME: "correcting the device date and time",
    ResolutionCode.PASSWORD_RESET: "a self-service password reset",
    ResolutionCode.SERVICE_FIX: "a service-side fix (no user action needed)",
    ResolutionCode.REPLACE_HARDWARE: "replacing faulty hardware",
}


def _free_text(value: Any, name: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > MAX_TEXT:
        raise ValueError(f"historical case {name} must be text of at most {MAX_TEXT} characters")
    return value


@dataclass(frozen=True)
class HistoricalCase:
    case_ref: str
    category: CaseCategory
    state: CaseState
    eligible: bool
    symptoms: tuple[SymptomTag, ...]
    resolution: Optional[ResolutionCode]
    # Untrusted free text — matching only, never displayed.
    description: str = ""
    resolution_notes: str = ""
    private: Mapping[str, str] = field(default_factory=dict)
    """Source-system fields (incident number, caller, work notes, sys_id).
    Never displayed, logged, matched or returned."""

    def __post_init__(self) -> None:
        if not isinstance(self.case_ref, str) or not CASE_REF_RE.fullmatch(self.case_ref):
            raise ValueError("historical case_ref must be HC followed by 5 digits")
        if not isinstance(self.category, CaseCategory):
            raise ValueError("historical case category must be a CaseCategory")
        if not isinstance(self.state, CaseState):
            raise ValueError("historical case state must be a CaseState")
        if not isinstance(self.eligible, bool):
            raise ValueError("historical case eligible must be a bool")
        if not isinstance(self.symptoms, tuple) or not self.symptoms \
                or not all(isinstance(t, SymptomTag) for t in self.symptoms):
            raise ValueError("historical case needs at least one SymptomTag")
        if self.resolution is not None and not isinstance(self.resolution, ResolutionCode):
            raise ValueError("historical case resolution must be a ResolutionCode")
        _free_text(self.description, "description")
        _free_text(self.resolution_notes, "resolution_notes")
        if not isinstance(self.private, Mapping):
            raise ValueError("historical case private fields must be a mapping")
        object.__setattr__(self, "private", MappingProxyType(dict(self.private)))

    @property
    def usable(self) -> bool:
        """Resolved/closed, explicitly marked eligible, with a known resolution."""
        return (self.eligible
                and self.state in (CaseState.RESOLVED, CaseState.CLOSED)
                and self.resolution is not None)

    def __repr__(self) -> str:  # never expose free text or private fields
        return f"HistoricalCase({self.case_ref}, {self.state.value}, eligible={self.eligible})"

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "HistoricalCase":
        if not isinstance(record, Mapping):
            raise ValueError("historical case record must be a mapping")
        try:
            resolution = record.get("resolution")
            return cls(
                case_ref=record["case_ref"],
                category=CaseCategory(record["category"]),
                state=CaseState(record["state"]),
                eligible=record["eligible"],
                symptoms=tuple(SymptomTag(t) for t in record["symptoms"]),
                resolution=ResolutionCode(resolution) if resolution is not None else None,
                description=_free_text(record.get("description"), "description"),
                resolution_notes=_free_text(record.get("resolution_notes"), "resolution_notes"),
                private={k: v for k, v in (record.get("private") or {}).items()
                         if isinstance(k, str) and isinstance(v, str)},
            )
        except (KeyError, TypeError) as exc:
            raise ValueError("historical case record is missing or has invalid fields") from exc


# Words that make a question about history but say nothing about the issue.
_HISTORY_WORDS = frozenset(tokenize(
    "seen before similar case cases incident incidents issue issues problem problems "
    "ticket tickets happened happen occurred anyone anybody someone others else "
    "previous previously past historical earlier fixed resolved solved dealt "
    "encountered reported had this that same like something"
))


@dataclass(frozen=True)
class CaseSearchRequest:
    query: str
    max_results: int = 5
    tokens: tuple[str, ...] = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.query, str):
            raise ValueError("case search query must be text")
        if isinstance(self.max_results, bool) or not isinstance(self.max_results, int) \
                or not 1 <= self.max_results <= MAX_RESULTS:
            raise ValueError(f"max_results must be between 1 and {MAX_RESULTS}")
        tokens = [t for t in tokenize(self.query[:500]) if t not in _HISTORY_WORDS]
        object.__setattr__(self, "tokens", tuple(dict.fromkeys(tokens))[:32])

    @property
    def empty(self) -> bool:
        return not self.tokens

    def __repr__(self) -> str:
        return f"CaseSearchRequest(tokens={len(self.tokens)}, max_results={self.max_results})"


class CaseOutcome(str, Enum):
    FOUND = "found"
    NO_MATCH = "no_match"
    NEEDS_TOPIC = "needs_topic"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class CaseEvidence:
    """What may be shown for one case: controlled values only."""

    case_ref: str
    category: CaseCategory
    symptom: SymptomTag
    resolution: ResolutionCode
    score: int


@dataclass(frozen=True)
class CaseSearchResult:
    outcome: CaseOutcome
    cases: tuple[CaseEvidence, ...] = ()
    withheld: int = 0

    @property
    def case_refs(self) -> tuple[str, ...]:
        return tuple(c.case_ref for c in self.cases)
