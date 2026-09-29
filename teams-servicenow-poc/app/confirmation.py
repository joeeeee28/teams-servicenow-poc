"""
app/confirmation.py — Confirmation / Side-effect Gate (BL-003).

PURPOSE
───────
This module is the single, authoritative gate that must be passed before
any side-effecting action is allowed to transition to EXECUTING.

It guarantees that a side effect cannot occur merely because:
  - the LLM classified an intent
  - the user described a problem
  - the router recognised create_incident
  - the state contains an action identifier

DESIGN
──────
``evaluate_confirmation(state, message)`` is a **pure** function:

  - It does NOT call ServiceNow.
  - It does NOT call Ollama or any other AI service.
  - It does NOT perform network operations.
  - It does NOT access credentials or environment variables.
  - It does NOT execute or schedule any side effect.
  - It does NOT transition state itself — it returns a ``ConfirmationDecision``
    and the caller is responsible for applying the transition.

CONFIRMATION REQUIREMENTS
─────────────────────────
All of the following must be true for ``confirmed=True``:

  1. ``state.phase`` is ``READY_FOR_CONFIRMATION``.
  2. ``state.pending_action`` is set and in ``EXECUTABLE_ACTIONS``.
  3. The normalised message is an exact match against ``_CONFIRM_PHRASES``.

CANCELLATION REQUIREMENTS
─────────────────────────
All of the following must be true for ``cancelled=True``:

  1. ``state.phase`` is ``READY_FOR_CONFIRMATION``.
  2. The normalised message is an exact match against ``_CANCEL_PHRASES``.

IDLE SAFETY
───────────
When ``state.phase`` is ``IDLE``, any message — including "yes", "confirm",
"go ahead" — returns ``confirmed=False``.  No side effect is possible.

AMBIGUOUS SAFETY
────────────────
Phrases that are positive-sounding but NOT in the explicit allowlist
(e.g. "sounds good", "okay", "sure", "maybe") return ``confirmed=False``
and leave the state unchanged.  If uncertain, the gate denies.

STALE-CONFIRMATION SAFETY
──────────────────────────
If ``state.pending_action`` is ``None`` or not in ``EXECUTABLE_ACTIONS``,
confirmation is always denied regardless of the user's message or phase.

SECURITY
────────
No message content (raw or normalised) is written to logs.
Only the phase, pending_action identity (not content), and decision outcome
are recorded at DEBUG level.

EXTENDING
─────────
To add a new confirmable action:
  1. Add its identifier to ``EXECUTABLE_ACTIONS``.
  2. No other change is required in this module.

To add a confirmation phrase:
  1. Add it (lowercase, stripped) to ``_CONFIRM_PHRASES``.

To add a cancellation phrase:
  1. Add it (lowercase, stripped) to ``_CANCEL_PHRASES``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from app.state import ConversationPhase, ConversationState

logger = logging.getLogger(__name__)


# ===========================================================================
# Allowlisted executable actions
# ===========================================================================

# Only identifiers in this set may ever transition to EXECUTING.
# Arbitrary strings from user input are NEVER added here at runtime.
EXECUTABLE_ACTIONS: frozenset[str] = frozenset(
    {
        "create_incident",
        # Future: "update_incident", "submit_service_request", etc.
        # Add identifiers here only when BL-005 implements their execution.
    }
)


# ===========================================================================
# Phrase allowlists  (all lowercase, stripped)
# ===========================================================================

# CONSERVATIVE explicit affirmatives only.
# Do NOT add general positive language such as "okay", "sounds good", "sure".
_CONFIRM_PHRASES: frozenset[str] = frozenset(
    {
        "yes",
        "confirm",
        "create it",
        "go ahead",
        "proceed",
        "submit it",
        "do it",
        "approved",
    }
)

# Explicit cancellations.
_CANCEL_PHRASES: frozenset[str] = frozenset(
    {
        "cancel",
        "no",
        "stop",
        "don't create it",
        "do not create it",
        "abort",
        "never mind",
        "nevermind",
        "forget it",
    }
)


# ===========================================================================
# Confirmation decision
# ===========================================================================

@dataclass(frozen=True)
class ConfirmationDecision:
    """
    Structured result returned by ``evaluate_confirmation``.

    This is a value object — it describes a decision but performs no action.

    Fields
    ──────
    confirmed : bool
        ``True`` if the user has explicitly confirmed and all gate conditions
        are satisfied.  The caller should transition to ``EXECUTING``.

    cancelled : bool
        ``True`` if the user has explicitly cancelled.  The caller should
        transition to ``CANCELLED``.

    action : str | None
        The ``pending_action`` identifier that was approved (only set when
        ``confirmed=True``).

    reason : str | None
        Human-readable explanation of the decision.  Safe to log.
        Must NOT contain user message content.
    """

    confirmed: bool
    cancelled: bool
    action: Optional[str]
    reason: Optional[str]

    def __post_init__(self) -> None:
        if self.confirmed and self.cancelled:
            raise ValueError(
                "ConfirmationDecision cannot be both confirmed and cancelled."
            )

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def approved(cls, action: str) -> "ConfirmationDecision":
        """Return a confirmed decision for *action*."""
        return cls(
            confirmed=True,
            cancelled=False,
            action=action,
            reason=f"Explicit confirmation for action '{action}'.",
        )

    @classmethod
    def denied(cls, reason: str) -> "ConfirmationDecision":
        """Return a not-confirmed, not-cancelled decision."""
        return cls(
            confirmed=False,
            cancelled=False,
            action=None,
            reason=reason,
        )

    @classmethod
    def cancellation(cls) -> "ConfirmationDecision":
        """Return a cancellation decision."""
        return cls(
            confirmed=False,
            cancelled=True,
            action=None,
            reason="Explicit cancellation by user.",
        )


# ===========================================================================
# Gate function
# ===========================================================================

def evaluate_confirmation(
    state: ConversationState,
    message: str,
) -> ConfirmationDecision:
    """
    Evaluate whether *message* constitutes a valid confirmation or
    cancellation of the pending action in *state*.

    This function is **pure**:
      - No network calls.
      - No ServiceNow access.
      - No credential reads.
      - No state mutation.
      - No logging of message content.

    Parameters
    ----------
    state:
        Current ``ConversationState`` for the user.  Not mutated.

    message:
        Raw message text from the Teams user.

    Returns
    -------
    ConfirmationDecision
        ``confirmed=True``  → caller should transition to EXECUTING.
        ``cancelled=True``  → caller should transition to CANCELLED.
        Both ``False``      → ambiguous; caller should stay in current phase.

    Security guarantees
    ────────────────────
    - Returns ``denied`` for ANY message when phase is not
      ``READY_FOR_CONFIRMATION``.
    - Returns ``denied`` when ``pending_action`` is absent or unknown.
    - Returns ``denied`` when message is not in the exact confirm allowlist.
    - Only returns ``confirmed=True`` when ALL three conditions hold:
        1. phase == READY_FOR_CONFIRMATION
        2. pending_action in EXECUTABLE_ACTIONS
        3. normalised message in _CONFIRM_PHRASES
    """
    phase = state.phase
    pending = state.pending_action

    # ── Guard 1: phase must be READY_FOR_CONFIRMATION ────────────────────────
    if phase is not ConversationPhase.READY_FOR_CONFIRMATION:
        logger.debug(
            "confirmation_gate: denied — phase is %r, not ready_for_confirmation",
            phase.value,
        )
        return ConfirmationDecision.denied(
            f"Phase is '{phase.value}'; confirmation requires ready_for_confirmation."
        )

    # ── Guard 2: a known pending action must exist ────────────────────────────
    if not pending or pending not in EXECUTABLE_ACTIONS:
        logger.debug(
            "confirmation_gate: denied — pending_action %r is absent or not executable",
            pending,
        )
        return ConfirmationDecision.denied(
            "No executable pending action is set for this conversation."
        )

    # ── Normalise the message ─────────────────────────────────────────────────
    normalised = message.strip().lower()

    # ── Check for explicit cancellation ──────────────────────────────────────
    if normalised in _CANCEL_PHRASES:
        logger.debug(
            "confirmation_gate: cancellation — pending_action=%r",
            pending,
        )
        return ConfirmationDecision.cancellation()

    # ── Check for explicit confirmation ──────────────────────────────────────
    if normalised in _CONFIRM_PHRASES:
        logger.debug(
            "confirmation_gate: approved — pending_action=%r",
            pending,
        )
        return ConfirmationDecision.approved(pending)

    # ── Ambiguous — deny by default ───────────────────────────────────────────
    logger.debug(
        "confirmation_gate: denied — message not in allowlist; "
        "pending_action=%r, phase=%r",
        pending,
        phase.value,
    )
    return ConfirmationDecision.denied(
        "Message is not an explicit confirmation or cancellation."
    )
