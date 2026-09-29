"""
app/request_collection.py — Service Request variable collection (DEMO-06).

PURPOSE
───────
Collects the required catalog variables for a selected CatalogItem while the
conversation is in ``ConversationPhase.COLLECTING`` and, once every required
variable is provided and valid, moves the conversation to
``READY_FOR_CONFIRMATION`` with a summary built from the collected values.

    IDLE ──► COLLECTING ──► READY_FOR_CONFIRMATION     (stops here)
                 │
                 └──► CANCELLED ──► IDLE               (user cancels)

Confirmation (BL-003), authorization (BL-004) and execution (BL-005) are
NOT performed here.

PURITY
──────
This module does not call ServiceNow, the Tool Gateway, Ollama, Teams or any
network service, and does not read credentials or environment variables.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

from app.catalog.models import CatalogItem, CatalogVariable, VariableKind
from app.confirmation import _CANCEL_PHRASES
from app.knowledge.sanitize import safe_text
from app.state import ConversationPhase, ConversationState

logger = logging.getLogger(__name__)

CREATE_REQUEST_ACTION = "create_request"


class RequestCollectionError(Exception):
    """Raised when the collector is used from a phase it does not own."""


@dataclass(frozen=True)
class RequestCollectionResult:
    """Outcome of processing one request collection turn."""

    reply: str
    phase: ConversationPhase
    missing_variables: tuple[str, ...]
    errors: tuple[str, ...] = ()
    cancelled: bool = False


def _get_target_variable(item: CatalogItem, collected_vars: dict[str, str]) -> Optional[CatalogVariable]:
    """Find the next missing required variable for item."""
    for var in item.variables:
        if var.required and var.name not in collected_vars:
            return var
    return None


def format_request_confirmation(item_name: str, item_ref: str, variables: dict[str, str]) -> str:
    """Format confirmation message for service request creation."""
    lines = [
        f"📦 **Request Confirmation**",
        f"Item: **{item_name}** ({item_ref})",
        "",
        "**Details to submit:**",
    ]
    if variables:
        for k, v in variables.items():
            label = k.replace("_", " ").capitalize()
            lines.append(f"- **{label}**: {v}")
    else:
        lines.append("- *(No extra options required)*")

    lines.extend([
        "",
        "This will create an official service request in ServiceNow.",
        "Please reply with **yes** to confirm or **cancel** to cancel."
    ])
    return "\n".join(lines)


def start_request_collection(
    session: ConversationState,
    item: CatalogItem,
    initial_message: str = "",
) -> RequestCollectionResult:
    """
    Initialize request collection for an approved catalog item.
    """
    if session.phase not in (
        ConversationPhase.IDLE,
        ConversationPhase.COMPLETED,
        ConversationPhase.FAILED,
        ConversationPhase.CANCELLED,
    ):
        raise RequestCollectionError(f"Cannot start request collection from phase {session.phase.value!r}")

    session.transition_to(ConversationPhase.COLLECTING)
    session.pending_action = CREATE_REQUEST_ACTION
    
    # Details stored in session
    session.collected_details = {
        "item_ref": item.item_ref,
        "sys_id": item.sys_id,
        "item_name": item.name,
        "variables": {},
    }

    # If there are no variables or no required variables
    next_var = _get_target_variable(item, {})
    if next_var is None:
        session.transition_to(ConversationPhase.READY_FOR_CONFIRMATION)
        reply = format_request_confirmation(item.name, item.item_ref, {})
        return RequestCollectionResult(
            reply=reply,
            phase=session.phase,
            missing_variables=(),
        )

    # Ask for the first missing variable
    prompt = _prompt_for_variable(item, next_var)
    return RequestCollectionResult(
        reply=prompt,
        phase=session.phase,
        missing_variables=tuple(v.name for v in item.variables if v.required),
    )


def _prompt_for_variable(item: CatalogItem, var: CatalogVariable) -> str:
    """Generate prompt string for missing variable."""
    if var.kind is VariableKind.CHOICE:
        choices_str = ", ".join(f"**{c}**" for c in var.choices)
        return (
            f"To request **{item.name}**, please specify **{var.label}**.\n"
            f"Allowed choices: {choices_str}"
        )
    return f"To request **{item.name}**, please provide **{var.label}**."


def process_request_collection_message(
    session: ConversationState,
    item: CatalogItem,
    user_message: str,
) -> RequestCollectionResult:
    """
    Process an incoming user message during COLLECTING phase for a request.
    """
    if session.phase is not ConversationPhase.COLLECTING:
        raise RequestCollectionError(f"Collector called in phase {session.phase.value!r}")

    text = user_message.strip()

    # User cancellation
    if text.lower() in _CANCEL_PHRASES:
        session.transition_to(ConversationPhase.CANCELLED)
        session.transition_to(ConversationPhase.IDLE)
        return RequestCollectionResult(
            reply="❌ Request cancelled. No request has been submitted.",
            phase=session.phase,
            missing_variables=(),
            cancelled=True,
        )

    details = session.collected_details
    collected_vars: dict[str, str] = details.get("variables", {})

    target_var = _get_target_variable(item, collected_vars)
    if target_var is None:
        # All required variables already present
        session.transition_to(ConversationPhase.READY_FOR_CONFIRMATION)
        reply = format_request_confirmation(item.name, item.item_ref, collected_vars)
        return RequestCollectionResult(
            reply=reply,
            phase=session.phase,
            missing_variables=(),
        )

    # Validate and sanitize input
    cleaned_text = safe_text(text)
    if not cleaned_text:
        return RequestCollectionResult(
            reply=f"That value is invalid. {_prompt_for_variable(item, target_var)}",
            phase=session.phase,
            missing_variables=tuple(v.name for v in item.variables if v.required and v.name not in collected_vars),
            errors=("Invalid input",),
        )

    if target_var.kind is VariableKind.CHOICE:
        # Match choice case-insensitively
        matched_choice = None
        for choice in target_var.choices:
            if cleaned_text.lower() == choice.lower():
                matched_choice = choice
                break
        if not matched_choice:
            choices_str = ", ".join(f"**{c}**" for c in target_var.choices)
            return RequestCollectionResult(
                reply=f"Invalid choice '{cleaned_text}'. Please choose one of: {choices_str}",
                phase=session.phase,
                missing_variables=tuple(v.name for v in item.variables if v.required and v.name not in collected_vars),
                errors=("Invalid choice",),
            )
        val_to_save = matched_choice
    else:
        val_to_save = cleaned_text

    collected_vars[target_var.name] = val_to_save
    details["variables"] = collected_vars

    next_var = _get_target_variable(item, collected_vars)
    if next_var is None:
        session.transition_to(ConversationPhase.READY_FOR_CONFIRMATION)
        reply = format_request_confirmation(item.name, item.item_ref, collected_vars)
        return RequestCollectionResult(
            reply=reply,
            phase=session.phase,
            missing_variables=(),
        )
    else:
        prompt = _prompt_for_variable(item, next_var)
        return RequestCollectionResult(
            reply=prompt,
            phase=session.phase,
            missing_variables=tuple(v.name for v in item.variables if v.required and v.name not in collected_vars),
        )
