from dataclasses import dataclass, field
from typing import Any


@dataclass
class ConversationState:
    intent: str | None = None
    summary: str | None = None
    collected_details: dict[str, Any] = field(default_factory=dict)
    awaiting_confirmation: bool = False


# POC ONLY:
# Stores conversation state in application memory.
# This will be replaced with persistent storage later.
_sessions: dict[str, ConversationState] = {}


def get_session(user_id: str) -> ConversationState:
    if user_id not in _sessions:
        _sessions[user_id] = ConversationState()

    return _sessions[user_id]


def update_session(
    user_id: str,
    *,
    intent: str | None = None,
    summary: str | None = None,
    collected_details: dict[str, Any] | None = None,
    awaiting_confirmation: bool | None = None,
) -> ConversationState:

    session = get_session(user_id)

    if intent is not None:
        session.intent = intent

    if summary is not None:
        session.summary = summary

    if collected_details:
        session.collected_details.update(collected_details)

    if awaiting_confirmation is not None:
        session.awaiting_confirmation = awaiting_confirmation

    return session


def clear_session(user_id: str) -> None:
    _sessions.pop(user_id, None)
