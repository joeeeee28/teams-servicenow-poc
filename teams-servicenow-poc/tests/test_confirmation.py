"""
tests/test_confirmation.py — Test suite for app.confirmation (BL-003).

Covers all 24 required test cases from the BL-003 specification, plus
regression guards for BL-001 and BL-002 behaviour.

 1.  READY_FOR_CONFIRMATION + "yes"       → confirmed.
 2.  READY_FOR_CONFIRMATION + "confirm"   → confirmed.
 3.  READY_FOR_CONFIRMATION + "go ahead"  → confirmed.
 4.  READY_FOR_CONFIRMATION + "create it" → confirmed.
 5.  READY_FOR_CONFIRMATION + "proceed"   → confirmed.
 6.  READY_FOR_CONFIRMATION + ambiguous   → not confirmed.
 7.  READY_FOR_CONFIRMATION + "cancel"    → cancelled.
 8.  READY_FOR_CONFIRMATION + "no"        → cancelled.
 9.  IDLE + "yes"                         → not confirmed.
10.  IDLE + "confirm"                     → not confirmed.
11.  COLLECTING + "yes"                   → not confirmed.
12.  COMPLETED + "yes"                    → not confirmed.
13.  FAILED + "yes"                       → not confirmed.
14.  READY_FOR_CONFIRMATION, no pending_action → not confirmed.
15.  Unknown pending_action               → not executable.
16.  Confirmation transitions to EXECUTING.
17.  Cancellation transitions to CANCELLED.
18.  Ambiguous response leaves state unchanged.
19.  State isolation between two users.
20.  Confirmation gate does not import/call ServiceNow.
21.  Confirmation gate performs no network operation.
22.  No credentials are accessed.
23.  Confirmation cannot directly complete an action.
24.  Confirmation cannot transition directly to COMPLETED.

Run with:  python3 -m unittest discover -s tests -p "test_*.py" -v
"""

import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from app.confirmation import (  # noqa: E402
    EXECUTABLE_ACTIONS,
    ConfirmationDecision,
    evaluate_confirmation,
)
from app.state import (  # noqa: E402
    ConversationPhase,
    ConversationState,
    InMemoryStateRepository,
    InvalidTransitionError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ready_state(pending: str = "create_incident") -> ConversationState:
    """Return a ConversationState in READY_FOR_CONFIRMATION with a pending action."""
    return ConversationState(
        phase=ConversationPhase.READY_FOR_CONFIRMATION,
        intent="create_incident",
        summary="VPN broken",
        pending_action=pending,
    )


def _state(phase: ConversationPhase, pending: str | None = "create_incident") -> ConversationState:
    return ConversationState(phase=phase, pending_action=pending)


# ===========================================================================
# Tests 1–5: Valid explicit confirmations
# ===========================================================================

class TestExplicitConfirmations(unittest.TestCase):
    """READY_FOR_CONFIRMATION + explicit phrase → confirmed=True."""

    def _assert_confirmed(self, phrase: str):
        state = _ready_state()
        decision = evaluate_confirmation(state, phrase)
        self.assertTrue(decision.confirmed, f"Expected confirmed for {phrase!r}")
        self.assertFalse(decision.cancelled)
        self.assertEqual(decision.action, "create_incident")

    def test_1_yes(self):
        self._assert_confirmed("yes")

    def test_2_confirm(self):
        self._assert_confirmed("confirm")

    def test_3_go_ahead(self):
        self._assert_confirmed("go ahead")

    def test_4_create_it(self):
        self._assert_confirmed("create it")

    def test_5_proceed(self):
        self._assert_confirmed("proceed")

    def test_submit_it(self):
        self._assert_confirmed("submit it")

    def test_do_it(self):
        self._assert_confirmed("do it")

    def test_approved(self):
        self._assert_confirmed("approved")

    def test_whitespace_stripped(self):
        """Leading/trailing whitespace must be stripped before matching."""
        self._assert_confirmed("  yes  ")

    def test_uppercase_normalised(self):
        """Uppercase must be normalised before matching."""
        self._assert_confirmed("YES")

    def test_mixed_case(self):
        self._assert_confirmed("Go Ahead")


# ===========================================================================
# Test 6: Ambiguous text → not confirmed
# ===========================================================================

class TestAmbiguousNotConfirmed(unittest.TestCase):
    """Positive-sounding but non-allowlisted phrases must NOT confirm."""

    def _assert_denied(self, phrase: str):
        state = _ready_state()
        decision = evaluate_confirmation(state, phrase)
        self.assertFalse(decision.confirmed, f"Expected NOT confirmed for {phrase!r}")
        self.assertFalse(decision.cancelled)

    def test_6_sounds_good(self):
        self._assert_denied("sounds good")

    def test_okay(self):
        self._assert_denied("okay")

    def test_ok(self):
        self._assert_denied("ok")

    def test_thanks(self):
        self._assert_denied("thanks")

    def test_sure(self):
        self._assert_denied("sure")

    def test_sure_tell_me_more(self):
        self._assert_denied("sure, tell me more")

    def test_maybe(self):
        self._assert_denied("maybe")

    def test_i_think_so(self):
        self._assert_denied("I think so")

    def test_yep(self):
        self._assert_denied("yep")

    def test_yeah(self):
        self._assert_denied("yeah")

    def test_alright(self):
        self._assert_denied("alright")

    def test_fine(self):
        self._assert_denied("fine")

    def test_empty_string(self):
        self._assert_denied("")

    def test_arbitrary_text(self):
        self._assert_denied("please do the thing")


# ===========================================================================
# Tests 7–8: Explicit cancellation
# ===========================================================================

class TestExplicitCancellation(unittest.TestCase):
    """READY_FOR_CONFIRMATION + cancel phrase → cancelled=True."""

    def _assert_cancelled(self, phrase: str):
        state = _ready_state()
        decision = evaluate_confirmation(state, phrase)
        self.assertFalse(decision.confirmed)
        self.assertTrue(decision.cancelled, f"Expected cancelled for {phrase!r}")
        self.assertIsNone(decision.action)

    def test_7_cancel(self):
        self._assert_cancelled("cancel")

    def test_8_no(self):
        self._assert_cancelled("no")

    def test_stop(self):
        self._assert_cancelled("stop")

    def test_dont_create_it(self):
        self._assert_cancelled("don't create it")

    def test_abort(self):
        self._assert_cancelled("abort")

    def test_never_mind(self):
        self._assert_cancelled("never mind")

    def test_nevermind(self):
        self._assert_cancelled("nevermind")

    def test_forget_it(self):
        self._assert_cancelled("forget it")

    def test_cancel_uppercase(self):
        self._assert_cancelled("CANCEL")

    def test_no_with_whitespace(self):
        self._assert_cancelled("  no  ")


# ===========================================================================
# Tests 9–10: IDLE phase safety
# ===========================================================================

class TestIdleSafety(unittest.TestCase):
    """Confirmation/cancellation must do nothing when phase is IDLE."""

    def test_9_idle_yes_not_confirmed(self):
        state = _state(ConversationPhase.IDLE)
        decision = evaluate_confirmation(state, "yes")
        self.assertFalse(decision.confirmed)
        self.assertFalse(decision.cancelled)

    def test_10_idle_confirm_not_confirmed(self):
        state = _state(ConversationPhase.IDLE)
        decision = evaluate_confirmation(state, "confirm")
        self.assertFalse(decision.confirmed)

    def test_idle_go_ahead_not_confirmed(self):
        state = _state(ConversationPhase.IDLE)
        decision = evaluate_confirmation(state, "go ahead")
        self.assertFalse(decision.confirmed)

    def test_idle_create_it_not_confirmed(self):
        state = _state(ConversationPhase.IDLE)
        decision = evaluate_confirmation(state, "create it")
        self.assertFalse(decision.confirmed)

    def test_idle_cancel_not_cancelled(self):
        """Even "cancel" in IDLE should not trigger cancelled=True."""
        state = _state(ConversationPhase.IDLE)
        decision = evaluate_confirmation(state, "cancel")
        self.assertFalse(decision.cancelled)
        self.assertFalse(decision.confirmed)


# ===========================================================================
# Test 11: COLLECTING + "yes" → not confirmed
# ===========================================================================

class TestCollectingPhaseSafety(unittest.TestCase):

    def test_11_collecting_yes_not_confirmed(self):
        state = _state(ConversationPhase.COLLECTING)
        decision = evaluate_confirmation(state, "yes")
        self.assertFalse(decision.confirmed)
        self.assertFalse(decision.cancelled)

    def test_collecting_confirm_not_confirmed(self):
        state = _state(ConversationPhase.COLLECTING)
        decision = evaluate_confirmation(state, "confirm")
        self.assertFalse(decision.confirmed)


# ===========================================================================
# Test 12: COMPLETED + "yes" → not confirmed
# ===========================================================================

class TestCompletedPhaseSafety(unittest.TestCase):

    def test_12_completed_yes_not_confirmed(self):
        state = _state(ConversationPhase.COMPLETED, pending=None)
        decision = evaluate_confirmation(state, "yes")
        self.assertFalse(decision.confirmed)

    def test_completed_confirm_not_confirmed(self):
        state = _state(ConversationPhase.COMPLETED, pending="create_incident")
        decision = evaluate_confirmation(state, "confirm")
        self.assertFalse(decision.confirmed)


# ===========================================================================
# Test 13: FAILED + "yes" → not confirmed
# ===========================================================================

class TestFailedPhaseSafety(unittest.TestCase):

    def test_13_failed_yes_not_confirmed(self):
        state = _state(ConversationPhase.FAILED, pending=None)
        decision = evaluate_confirmation(state, "yes")
        self.assertFalse(decision.confirmed)

    def test_failed_confirm_not_confirmed(self):
        state = _state(ConversationPhase.FAILED, pending="create_incident")
        decision = evaluate_confirmation(state, "confirm")
        self.assertFalse(decision.confirmed)


# ===========================================================================
# Test 14: READY_FOR_CONFIRMATION with no pending_action → not confirmed
# ===========================================================================

class TestNoPendingAction(unittest.TestCase):

    def test_14_no_pending_action_yes_denied(self):
        state = ConversationState(
            phase=ConversationPhase.READY_FOR_CONFIRMATION,
            pending_action=None,
        )
        decision = evaluate_confirmation(state, "yes")
        self.assertFalse(decision.confirmed)
        self.assertFalse(decision.cancelled)

    def test_no_pending_action_confirm_denied(self):
        state = ConversationState(
            phase=ConversationPhase.READY_FOR_CONFIRMATION,
            pending_action=None,
        )
        decision = evaluate_confirmation(state, "confirm")
        self.assertFalse(decision.confirmed)


# ===========================================================================
# Test 15: Unknown/not-allowlisted pending_action → not executable
# ===========================================================================

class TestUnknownPendingAction(unittest.TestCase):

    def test_15_unknown_action_yes_denied(self):
        state = ConversationState(
            phase=ConversationPhase.READY_FOR_CONFIRMATION,
            pending_action="delete_all_data",  # not in EXECUTABLE_ACTIONS
        )
        decision = evaluate_confirmation(state, "yes")
        self.assertFalse(decision.confirmed)

    def test_arbitrary_string_not_executable(self):
        state = ConversationState(
            phase=ConversationPhase.READY_FOR_CONFIRMATION,
            pending_action="DROP TABLE users; --",
        )
        decision = evaluate_confirmation(state, "yes")
        self.assertFalse(decision.confirmed)

    def test_empty_string_pending_action_not_executable(self):
        state = ConversationState(
            phase=ConversationPhase.READY_FOR_CONFIRMATION,
            pending_action="",
        )
        decision = evaluate_confirmation(state, "yes")
        self.assertFalse(decision.confirmed)

    def test_executable_actions_set_is_non_empty(self):
        self.assertIn("create_incident", EXECUTABLE_ACTIONS)

    def test_executable_actions_set_is_frozenset(self):
        self.assertIsInstance(EXECUTABLE_ACTIONS, frozenset)


# ===========================================================================
# Test 16: Confirmation transitions to EXECUTING
# ===========================================================================

class TestConfirmationTransitionsToExecuting(unittest.TestCase):

    def test_16_confirmed_then_execute_transition(self):
        state = _ready_state()
        decision = evaluate_confirmation(state, "yes")
        self.assertTrue(decision.confirmed)
        # The caller is responsible for the transition.
        state.transition_to(ConversationPhase.EXECUTING)
        self.assertEqual(state.phase, ConversationPhase.EXECUTING)

    def test_confirmed_action_matches_pending(self):
        state = _ready_state("create_incident")
        decision = evaluate_confirmation(state, "proceed")
        self.assertEqual(decision.action, "create_incident")

    def test_executing_phase_is_not_completed(self):
        """EXECUTING must not automatically become COMPLETED here."""
        state = _ready_state()
        evaluate_confirmation(state, "yes")
        # Gate does not mutate state; phase is still READY_FOR_CONFIRMATION.
        self.assertEqual(state.phase, ConversationPhase.READY_FOR_CONFIRMATION)


# ===========================================================================
# Test 17: Cancellation transitions to CANCELLED
# ===========================================================================

class TestCancellationTransitionsToCancelled(unittest.TestCase):

    def test_17_cancelled_then_cancelled_transition(self):
        state = _ready_state()
        decision = evaluate_confirmation(state, "cancel")
        self.assertTrue(decision.cancelled)
        # The caller drives the transition.
        state.transition_to(ConversationPhase.CANCELLED)
        self.assertEqual(state.phase, ConversationPhase.CANCELLED)

    def test_after_cancellation_can_reset_to_idle(self):
        state = _ready_state()
        evaluate_confirmation(state, "no")
        state.transition_to(ConversationPhase.CANCELLED)
        state.transition_to(ConversationPhase.IDLE)
        self.assertEqual(state.phase, ConversationPhase.IDLE)


# ===========================================================================
# Test 18: Ambiguous response leaves state unchanged
# ===========================================================================

class TestAmbiguousLeavesStateUnchanged(unittest.TestCase):

    def test_18_ambiguous_phase_unchanged(self):
        state = _ready_state()
        original_phase = state.phase
        decision = evaluate_confirmation(state, "sounds good")
        # Gate must not mutate state.
        self.assertEqual(state.phase, original_phase)
        self.assertFalse(decision.confirmed)
        self.assertFalse(decision.cancelled)

    def test_ambiguous_pending_action_unchanged(self):
        state = _ready_state()
        evaluate_confirmation(state, "maybe")
        self.assertEqual(state.pending_action, "create_incident")

    def test_ambiguous_no_state_side_effect(self):
        state = _ready_state()
        evaluate_confirmation(state, "okay")
        self.assertIsNone(state.last_error)
        self.assertEqual(state.phase, ConversationPhase.READY_FOR_CONFIRMATION)


# ===========================================================================
# Test 19: State isolation between two users
# ===========================================================================

class TestStateIsolationBetweenUsers(unittest.TestCase):

    def test_19_two_users_independent(self):
        repo = InMemoryStateRepository()

        state_alice = repo.get("alice")
        state_alice.intent = "create_incident"
        state_alice.pending_action = "create_incident"
        state_alice.transition_to(ConversationPhase.COLLECTING)
        state_alice.transition_to(ConversationPhase.READY_FOR_CONFIRMATION)
        repo.save("alice", state_alice)

        state_bob = repo.get("bob")
        # Bob should still be in IDLE.
        self.assertEqual(state_bob.phase, ConversationPhase.IDLE)

        decision_alice = evaluate_confirmation(state_alice, "yes")
        self.assertTrue(decision_alice.confirmed)

        decision_bob = evaluate_confirmation(state_bob, "yes")
        self.assertFalse(decision_bob.confirmed)

    def test_alice_confirmation_does_not_affect_bob(self):
        repo = InMemoryStateRepository()

        state_alice = ConversationState(
            phase=ConversationPhase.READY_FOR_CONFIRMATION,
            pending_action="create_incident",
        )
        repo.save("alice", state_alice)

        state_bob = repo.get("bob")
        self.assertEqual(state_bob.phase, ConversationPhase.IDLE)

        evaluate_confirmation(state_alice, "yes")

        state_bob_again = repo.get("bob")
        self.assertEqual(state_bob_again.phase, ConversationPhase.IDLE)


# ===========================================================================
# Test 20: Confirmation gate does not import/call ServiceNow
# ===========================================================================

class TestNoServiceNowAccess(unittest.TestCase):

    def setUp(self):
        fake_sn = types.ModuleType("app.servicenow")

        class _Sentinel:
            def __init__(self, *a, **kw):
                raise AssertionError(
                    "evaluate_confirmation must NOT instantiate ServiceNowClient"
                )

        fake_sn.ServiceNowClient = _Sentinel
        self._patch = patch.dict("sys.modules", {"app.servicenow": fake_sn})

    def test_20_no_servicenow_on_confirm(self):
        with self._patch:
            state = _ready_state()
            decision = evaluate_confirmation(state, "yes")
        self.assertTrue(decision.confirmed)

    def test_20_no_servicenow_on_cancel(self):
        with self._patch:
            state = _ready_state()
            decision = evaluate_confirmation(state, "cancel")
        self.assertTrue(decision.cancelled)

    def test_20_no_servicenow_on_deny(self):
        with self._patch:
            state = _ready_state()
            decision = evaluate_confirmation(state, "sounds good")
        self.assertFalse(decision.confirmed)

    def test_20_no_servicenow_on_idle(self):
        with self._patch:
            state = _state(ConversationPhase.IDLE)
            decision = evaluate_confirmation(state, "yes")
        self.assertFalse(decision.confirmed)


# ===========================================================================
# Test 21: Confirmation gate performs no network operation
# ===========================================================================

class TestNoNetworkOperation(unittest.TestCase):

    def _mock_httpx(self):
        mock_httpx = MagicMock()
        mock_httpx.AsyncClient.side_effect = AssertionError(
            "evaluate_confirmation must NOT make network calls"
        )
        mock_httpx.Client.side_effect = AssertionError(
            "evaluate_confirmation must NOT make network calls"
        )
        return mock_httpx

    def test_21_no_network_on_confirm(self):
        with patch.dict("sys.modules", {"httpx": self._mock_httpx()}):
            state = _ready_state()
            decision = evaluate_confirmation(state, "yes")
        self.assertTrue(decision.confirmed)

    def test_21_no_network_on_cancel(self):
        with patch.dict("sys.modules", {"httpx": self._mock_httpx()}):
            state = _ready_state()
            decision = evaluate_confirmation(state, "no")
        self.assertTrue(decision.cancelled)

    def test_21_no_network_on_deny(self):
        with patch.dict("sys.modules", {"httpx": self._mock_httpx()}):
            state = _ready_state()
            decision = evaluate_confirmation(state, "okay")
        self.assertFalse(decision.confirmed)

    def test_21_is_synchronous_function(self):
        import inspect
        self.assertFalse(
            inspect.iscoroutinefunction(evaluate_confirmation),
            "evaluate_confirmation must be synchronous",
        )


# ===========================================================================
# Test 22: No credentials accessed
# ===========================================================================

class TestNoCredentialAccess(unittest.TestCase):

    _CRED_KEYS = [
        "SERVICENOW_INSTANCE",
        "SERVICENOW_CLIENT_ID",
        "SERVICENOW_CLIENT_SECRET",
        "TEAMS_CLIENT_ID",
        "TEAMS_CLIENT_SECRET",
        "TEAMS_TENANT_ID",
        "ADMIN_API_KEY",
    ]

    def test_22_no_credentials_on_confirm(self):
        backup = {k: os.environ.pop(k, None) for k in self._CRED_KEYS}
        try:
            state = _ready_state()
            decision = evaluate_confirmation(state, "yes")
            self.assertTrue(decision.confirmed)
        finally:
            for k, v in backup.items():
                if v is not None:
                    os.environ[k] = v

    def test_22_no_credentials_on_deny(self):
        backup = {k: os.environ.pop(k, None) for k in self._CRED_KEYS}
        try:
            state = _ready_state()
            decision = evaluate_confirmation(state, "sounds good")
            self.assertFalse(decision.confirmed)
        finally:
            for k, v in backup.items():
                if v is not None:
                    os.environ[k] = v


# ===========================================================================
# Test 23: Confirmation cannot directly complete an action
# ===========================================================================

class TestNoDirectCompletion(unittest.TestCase):

    def test_23_evaluate_does_not_transition_state(self):
        """
        evaluate_confirmation is pure: it must NOT mutate the state object.
        The phase must remain READY_FOR_CONFIRMATION after evaluation.
        """
        state = _ready_state()
        evaluate_confirmation(state, "yes")
        self.assertEqual(state.phase, ConversationPhase.READY_FOR_CONFIRMATION)

    def test_23_confirmed_decision_action_is_not_completed(self):
        """The decision says confirmed; it does not say completed."""
        state = _ready_state()
        decision = evaluate_confirmation(state, "yes")
        self.assertTrue(decision.confirmed)
        # Phase is still READY_FOR_CONFIRMATION — caller must drive transition.
        self.assertEqual(state.phase, ConversationPhase.READY_FOR_CONFIRMATION)

    def test_23_cannot_go_directly_ready_to_completed(self):
        """
        The state machine rejects READY_FOR_CONFIRMATION → COMPLETED.
        Even if a caller tried it, it must raise InvalidTransitionError.
        """
        state = _ready_state()
        with self.assertRaises(InvalidTransitionError):
            state.transition_to(ConversationPhase.COMPLETED)


# ===========================================================================
# Test 24: Confirmation cannot transition directly to COMPLETED
# ===========================================================================

class TestNoDirectTransitionToCompleted(unittest.TestCase):

    def test_24_executing_to_completed_requires_separate_step(self):
        """
        After confirmation, the flow is EXECUTING → COMPLETED.
        READY_FOR_CONFIRMATION → COMPLETED is invalid.
        """
        state = _ready_state()
        evaluate_confirmation(state, "yes")
        # State is still READY_FOR_CONFIRMATION (gate is pure).
        # Caller drives EXECUTING; direct → COMPLETED must fail.
        with self.assertRaises(InvalidTransitionError):
            state.transition_to(ConversationPhase.COMPLETED)

    def test_24_correct_sequence_is_ready_executing_completed(self):
        """
        The valid sequence after confirmation:
        READY → EXECUTING (gate approves) → COMPLETED (execution layer).
        """
        state = _ready_state()
        decision = evaluate_confirmation(state, "yes")
        self.assertTrue(decision.confirmed)
        state.transition_to(ConversationPhase.EXECUTING)
        state.transition_to(ConversationPhase.COMPLETED)
        self.assertEqual(state.phase, ConversationPhase.COMPLETED)

    def test_24_gate_decision_has_no_completed_flag(self):
        """ConfirmationDecision has no 'completed' field."""
        state = _ready_state()
        decision = evaluate_confirmation(state, "yes")
        self.assertFalse(hasattr(decision, "completed"))


# ===========================================================================
# ConfirmationDecision data class integrity
# ===========================================================================

class TestConfirmationDecisionIntegrity(unittest.TestCase):

    def test_approved_factory(self):
        d = ConfirmationDecision.approved("create_incident")
        self.assertTrue(d.confirmed)
        self.assertFalse(d.cancelled)
        self.assertEqual(d.action, "create_incident")
        self.assertIsNotNone(d.reason)

    def test_denied_factory(self):
        d = ConfirmationDecision.denied("test reason")
        self.assertFalse(d.confirmed)
        self.assertFalse(d.cancelled)
        self.assertIsNone(d.action)
        self.assertEqual(d.reason, "test reason")

    def test_cancellation_factory(self):
        d = ConfirmationDecision.cancellation()
        self.assertFalse(d.confirmed)
        self.assertTrue(d.cancelled)
        self.assertIsNone(d.action)

    def test_cannot_be_both_confirmed_and_cancelled(self):
        with self.assertRaises(ValueError):
            ConfirmationDecision(
                confirmed=True,
                cancelled=True,
                action="create_incident",
                reason="bad",
            )

    def test_is_frozen_dataclass(self):
        """ConfirmationDecision must be immutable."""
        d = ConfirmationDecision.approved("create_incident")
        with self.assertRaises((AttributeError, TypeError)):
            d.confirmed = False  # type: ignore[misc]


# ===========================================================================
# Stale-confirmation safety
# ===========================================================================

class TestStaleConfirmationSafety(unittest.TestCase):

    def test_after_idle_reset_yes_does_nothing(self):
        """
        If the state was reset to IDLE (e.g. after COMPLETED → IDLE),
        a later "yes" must not confirm anything.
        """
        state = ConversationState(phase=ConversationPhase.IDLE)
        decision = evaluate_confirmation(state, "yes")
        self.assertFalse(decision.confirmed)
        self.assertFalse(decision.cancelled)
        # Phase must remain IDLE.
        self.assertEqual(state.phase, ConversationPhase.IDLE)

    def test_full_cycle_then_stale_yes(self):
        """
        Complete a full happy-path cycle, reset to IDLE, then verify
        that "yes" does not confirm a new (non-existent) action.
        """
        state = ConversationState()
        state.transition_to(ConversationPhase.COLLECTING)
        state.pending_action = "create_incident"
        state.transition_to(ConversationPhase.READY_FOR_CONFIRMATION)
        state.transition_to(ConversationPhase.EXECUTING)
        state.transition_to(ConversationPhase.COMPLETED)
        state.transition_to(ConversationPhase.IDLE)  # clears all fields

        # Now a stale "yes" arrives.
        decision = evaluate_confirmation(state, "yes")
        self.assertFalse(decision.confirmed)
        self.assertIsNone(state.pending_action)  # confirmed cleared by reset


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
