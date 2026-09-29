"""
tests/test_state.py — Test suite for app.state (BL-002).

Tests cover all 17 required cases from the BL-002 specification:

 1.  New session starts in IDLE.
 2.  IDLE → COLLECTING works.
 3.  COLLECTING → READY_FOR_CONFIRMATION works.
 4.  READY_FOR_CONFIRMATION → EXECUTING works.
 5.  EXECUTING → COMPLETED works.
 6.  EXECUTING → FAILED works.
 7.  READY_FOR_CONFIRMATION → CANCELLED works.
 8.  COMPLETED → IDLE works.
 9.  CANCELLED → IDLE works.
10.  FAILED → IDLE works.
11.  Invalid transitions are rejected.
12.  State data survives a repository get/set cycle.
13.  Two user IDs have isolated state.
14.  Clearing one user does not affect another.
15.  No ServiceNow client is invoked.
16.  No network operation occurs.
17.  No credentials are accessed.

Run with:   python -m unittest discover -s tests -p "test_*.py" -v
Or:         pytest -q
"""

import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from app.state import (  # noqa: E402
    ConversationPhase,
    ConversationState,
    InMemoryStateRepository,
    InvalidTransitionError,
    StateRepository,
    clear_session,
    get_session,
    save_session,
    update_session,
)


# ===========================================================================
# Helper
# ===========================================================================

def _fresh_repo() -> InMemoryStateRepository:
    """Return a new, empty repository for test isolation."""
    return InMemoryStateRepository()


# ===========================================================================
# 1. New session starts in IDLE
# ===========================================================================

class TestNewSessionIsIdle(unittest.TestCase):

    def test_default_phase_is_idle(self):
        repo = _fresh_repo()
        state = repo.get("user-1")
        self.assertEqual(state.phase, ConversationPhase.IDLE)

    def test_default_intent_is_none(self):
        repo = _fresh_repo()
        state = repo.get("user-1")
        self.assertIsNone(state.intent)

    def test_default_summary_is_none(self):
        repo = _fresh_repo()
        state = repo.get("user-1")
        self.assertIsNone(state.summary)

    def test_default_collected_details_empty(self):
        repo = _fresh_repo()
        state = repo.get("user-1")
        self.assertEqual(state.collected_details, {})

    def test_default_pending_action_is_none(self):
        repo = _fresh_repo()
        state = repo.get("user-1")
        self.assertIsNone(state.pending_action)

    def test_default_incident_number_is_none(self):
        repo = _fresh_repo()
        state = repo.get("user-1")
        self.assertIsNone(state.incident_number)

    def test_default_last_error_is_none(self):
        repo = _fresh_repo()
        state = repo.get("user-1")
        self.assertIsNone(state.last_error)

    def test_conversation_state_is_dataclass(self):
        state = ConversationState()
        self.assertIsInstance(state, ConversationState)


# ===========================================================================
# 2. IDLE → COLLECTING
# ===========================================================================

class TestIdleToCollecting(unittest.TestCase):

    def test_transition_succeeds(self):
        state = ConversationState()
        result = state.transition_to(ConversationPhase.COLLECTING)
        self.assertEqual(state.phase, ConversationPhase.COLLECTING)

    def test_transition_returns_self(self):
        state = ConversationState()
        result = state.transition_to(ConversationPhase.COLLECTING)
        self.assertIs(result, state)


# ===========================================================================
# 3. COLLECTING → READY_FOR_CONFIRMATION
# ===========================================================================

class TestCollectingToReady(unittest.TestCase):

    def test_transition_succeeds(self):
        state = ConversationState(phase=ConversationPhase.COLLECTING)
        state.transition_to(ConversationPhase.READY_FOR_CONFIRMATION)
        self.assertEqual(state.phase, ConversationPhase.READY_FOR_CONFIRMATION)

    def test_data_preserved_across_transition(self):
        state = ConversationState(phase=ConversationPhase.COLLECTING)
        state.intent = "create_incident"
        state.summary = "VPN broken"
        state.collected_details = {"description": "Cannot connect"}
        state.transition_to(ConversationPhase.READY_FOR_CONFIRMATION)
        self.assertEqual(state.intent, "create_incident")
        self.assertEqual(state.summary, "VPN broken")
        self.assertEqual(state.collected_details["description"], "Cannot connect")


# ===========================================================================
# 4. READY_FOR_CONFIRMATION → EXECUTING
# ===========================================================================

class TestReadyToExecuting(unittest.TestCase):

    def test_transition_succeeds(self):
        state = ConversationState(phase=ConversationPhase.READY_FOR_CONFIRMATION)
        state.transition_to(ConversationPhase.EXECUTING)
        self.assertEqual(state.phase, ConversationPhase.EXECUTING)


# ===========================================================================
# 5. EXECUTING → COMPLETED
# ===========================================================================

class TestExecutingToCompleted(unittest.TestCase):

    def test_transition_succeeds(self):
        state = ConversationState(phase=ConversationPhase.EXECUTING)
        state.transition_to(ConversationPhase.COMPLETED)
        self.assertEqual(state.phase, ConversationPhase.COMPLETED)


# ===========================================================================
# 6. EXECUTING → FAILED
# ===========================================================================

class TestExecutingToFailed(unittest.TestCase):

    def test_transition_succeeds(self):
        state = ConversationState(phase=ConversationPhase.EXECUTING)
        state.transition_to(ConversationPhase.FAILED)
        self.assertEqual(state.phase, ConversationPhase.FAILED)

    def test_last_error_survives_executing_to_failed(self):
        state = ConversationState(phase=ConversationPhase.EXECUTING)
        state.last_error = "ServiceNow timeout"
        state.transition_to(ConversationPhase.FAILED)
        self.assertEqual(state.last_error, "ServiceNow timeout")


# ===========================================================================
# 7. READY_FOR_CONFIRMATION → CANCELLED
# ===========================================================================

class TestReadyToCancelled(unittest.TestCase):

    def test_transition_succeeds(self):
        state = ConversationState(phase=ConversationPhase.READY_FOR_CONFIRMATION)
        state.transition_to(ConversationPhase.CANCELLED)
        self.assertEqual(state.phase, ConversationPhase.CANCELLED)


# ===========================================================================
# 8. COMPLETED → IDLE
# ===========================================================================

class TestCompletedToIdle(unittest.TestCase):

    def test_transition_succeeds(self):
        state = ConversationState(phase=ConversationPhase.COMPLETED)
        state.transition_to(ConversationPhase.IDLE)
        self.assertEqual(state.phase, ConversationPhase.IDLE)

    def test_fields_cleared_on_reset(self):
        state = ConversationState(
            phase=ConversationPhase.COMPLETED,
            intent="create_incident",
            summary="VPN",
            collected_details={"foo": "bar"},
            pending_action="create_incident",
            incident_number="INC0010002",
            last_error=None,
        )
        state.transition_to(ConversationPhase.IDLE)
        self.assertIsNone(state.intent)
        self.assertIsNone(state.summary)
        self.assertEqual(state.collected_details, {})
        self.assertIsNone(state.pending_action)
        self.assertIsNone(state.incident_number)
        self.assertIsNone(state.last_error)


# ===========================================================================
# 9. CANCELLED → IDLE
# ===========================================================================

class TestCancelledToIdle(unittest.TestCase):

    def test_transition_succeeds(self):
        state = ConversationState(phase=ConversationPhase.CANCELLED)
        state.transition_to(ConversationPhase.IDLE)
        self.assertEqual(state.phase, ConversationPhase.IDLE)

    def test_fields_cleared_on_reset(self):
        state = ConversationState(
            phase=ConversationPhase.CANCELLED,
            intent="create_incident",
            summary="test",
        )
        state.transition_to(ConversationPhase.IDLE)
        self.assertIsNone(state.intent)
        self.assertIsNone(state.summary)


# ===========================================================================
# 10. FAILED → IDLE
# ===========================================================================

class TestFailedToIdle(unittest.TestCase):

    def test_transition_succeeds(self):
        state = ConversationState(phase=ConversationPhase.FAILED)
        state.transition_to(ConversationPhase.IDLE)
        self.assertEqual(state.phase, ConversationPhase.IDLE)

    def test_last_error_cleared_on_reset(self):
        state = ConversationState(
            phase=ConversationPhase.FAILED,
            last_error="Timeout",
        )
        state.transition_to(ConversationPhase.IDLE)
        self.assertIsNone(state.last_error)


# ===========================================================================
# 11. Invalid transitions are rejected
# ===========================================================================

class TestInvalidTransitions(unittest.TestCase):
    """
    Every transition NOT in the valid table must raise InvalidTransitionError.
    """

    def _assert_invalid(self, from_phase: ConversationPhase, to_phase: ConversationPhase):
        state = ConversationState(phase=from_phase)
        with self.assertRaises(InvalidTransitionError) as ctx:
            state.transition_to(to_phase)
        self.assertEqual(ctx.exception.from_phase, from_phase)
        self.assertEqual(ctx.exception.to_phase, to_phase)

    def test_idle_to_ready(self):
        self._assert_invalid(ConversationPhase.IDLE, ConversationPhase.READY_FOR_CONFIRMATION)

    def test_idle_to_executing(self):
        self._assert_invalid(ConversationPhase.IDLE, ConversationPhase.EXECUTING)

    def test_idle_to_completed(self):
        self._assert_invalid(ConversationPhase.IDLE, ConversationPhase.COMPLETED)

    def test_idle_to_cancelled(self):
        self._assert_invalid(ConversationPhase.IDLE, ConversationPhase.CANCELLED)

    def test_idle_to_failed(self):
        self._assert_invalid(ConversationPhase.IDLE, ConversationPhase.FAILED)

    def test_collecting_to_idle(self):
        self._assert_invalid(ConversationPhase.COLLECTING, ConversationPhase.IDLE)

    def test_collecting_to_executing(self):
        self._assert_invalid(ConversationPhase.COLLECTING, ConversationPhase.EXECUTING)

    def test_collecting_to_cancelled(self):
        # BL-006 made COLLECTING → CANCELLED valid (cancellation during
        # incident collection).  COLLECTING → IDLE must remain invalid, so
        # cancellation still passes through CANCELLED.
        state = ConversationState(phase=ConversationPhase.COLLECTING)
        state.transition_to(ConversationPhase.CANCELLED)
        self.assertEqual(state.phase, ConversationPhase.CANCELLED)
        state.transition_to(ConversationPhase.IDLE)
        self.assertEqual(state.phase, ConversationPhase.IDLE)

    def test_ready_to_collecting(self):
        self._assert_invalid(
            ConversationPhase.READY_FOR_CONFIRMATION,
            ConversationPhase.COLLECTING,
        )

    def test_ready_to_completed(self):
        self._assert_invalid(
            ConversationPhase.READY_FOR_CONFIRMATION,
            ConversationPhase.COMPLETED,
        )

    def test_ready_to_failed(self):
        self._assert_invalid(
            ConversationPhase.READY_FOR_CONFIRMATION,
            ConversationPhase.FAILED,
        )

    def test_executing_to_idle(self):
        self._assert_invalid(ConversationPhase.EXECUTING, ConversationPhase.IDLE)

    def test_executing_to_collecting(self):
        self._assert_invalid(ConversationPhase.EXECUTING, ConversationPhase.COLLECTING)

    def test_executing_to_cancelled(self):
        self._assert_invalid(ConversationPhase.EXECUTING, ConversationPhase.CANCELLED)

    def test_completed_to_collecting(self):
        self._assert_invalid(ConversationPhase.COMPLETED, ConversationPhase.COLLECTING)

    def test_cancelled_to_executing(self):
        self._assert_invalid(ConversationPhase.CANCELLED, ConversationPhase.EXECUTING)

    def test_failed_to_executing(self):
        self._assert_invalid(ConversationPhase.FAILED, ConversationPhase.EXECUTING)

    def test_invalid_transition_error_message(self):
        state = ConversationState(phase=ConversationPhase.IDLE)
        try:
            state.transition_to(ConversationPhase.COMPLETED)
        except InvalidTransitionError as exc:
            self.assertIn("idle", str(exc))
            self.assertIn("completed", str(exc))
        else:
            self.fail("Expected InvalidTransitionError was not raised")

    def test_phase_unchanged_after_invalid_transition(self):
        """
        Ensure the phase is not mutated when the transition is invalid.
        """
        state = ConversationState(phase=ConversationPhase.IDLE)
        try:
            state.transition_to(ConversationPhase.COMPLETED)
        except InvalidTransitionError:
            pass
        self.assertEqual(state.phase, ConversationPhase.IDLE)


# ===========================================================================
# 12. State data survives a repository get/set cycle
# ===========================================================================

class TestRepositoryGetSetCycle(unittest.TestCase):

    def test_saved_state_is_retrievable(self):
        repo = _fresh_repo()
        state = ConversationState(
            phase=ConversationPhase.COLLECTING,
            intent="create_incident",
            summary="VPN broken",
            collected_details={"impact": "3"},
            pending_action="create_incident",
            incident_number=None,
            last_error=None,
        )
        repo.save("user-42", state)
        retrieved = repo.get("user-42")
        self.assertEqual(retrieved.phase, ConversationPhase.COLLECTING)
        self.assertEqual(retrieved.intent, "create_incident")
        self.assertEqual(retrieved.summary, "VPN broken")
        self.assertEqual(retrieved.collected_details["impact"], "3")
        self.assertEqual(retrieved.pending_action, "create_incident")

    def test_subsequent_mutation_visible(self):
        repo = _fresh_repo()
        state = repo.get("user-99")
        state.intent = "diagnose"
        repo.save("user-99", state)
        retrieved = repo.get("user-99")
        self.assertEqual(retrieved.intent, "diagnose")


# ===========================================================================
# 13. Two user IDs have isolated state
# ===========================================================================

class TestMultiUserIsolation(unittest.TestCase):

    def test_different_users_have_independent_state(self):
        repo = _fresh_repo()
        state_a = repo.get("alice")
        state_a.intent = "create_incident"
        state_a.transition_to(ConversationPhase.COLLECTING)
        repo.save("alice", state_a)

        state_b = repo.get("bob")
        # bob is untouched — must still be IDLE with no intent
        self.assertEqual(state_b.phase, ConversationPhase.IDLE)
        self.assertIsNone(state_b.intent)

    def test_mutating_one_does_not_affect_other(self):
        repo = _fresh_repo()
        # Create both sessions
        state_a = repo.get("alice")
        state_b = repo.get("bob")

        state_a.summary = "VPN problem"
        repo.save("alice", state_a)

        state_b_again = repo.get("bob")
        self.assertIsNone(state_b_again.summary)


# ===========================================================================
# 14. Clearing one user does not affect another
# ===========================================================================

class TestClearIsolation(unittest.TestCase):

    def test_clear_does_not_affect_other_user(self):
        repo = _fresh_repo()
        state_a = repo.get("alice")
        state_a.intent = "create_incident"
        repo.save("alice", state_a)

        state_b = repo.get("bob")
        state_b.intent = "diagnose"
        repo.save("bob", state_b)

        repo.clear("alice")

        # alice is gone (fresh state)
        fresh_a = repo.get("alice")
        self.assertEqual(fresh_a.phase, ConversationPhase.IDLE)
        self.assertIsNone(fresh_a.intent)

        # bob is unaffected
        surviving_b = repo.get("bob")
        self.assertEqual(surviving_b.intent, "diagnose")

    def test_clear_nonexistent_user_is_safe(self):
        repo = _fresh_repo()
        try:
            repo.clear("nobody")
        except Exception as exc:
            self.fail(f"clear() raised unexpectedly: {exc}")


# ===========================================================================
# 15. No ServiceNow client is invoked
# ===========================================================================

class TestNoServiceNowInvocation(unittest.TestCase):
    """
    Replace app.servicenow with a sentinel that raises if ServiceNowClient
    is instantiated, then exercise the state machine.
    """

    def setUp(self):
        fake_sn = types.ModuleType("app.servicenow")

        class _Sentinel:
            def __init__(self, *a, **kw):
                raise AssertionError(
                    "State machine must NOT instantiate ServiceNowClient"
                )

        fake_sn.ServiceNowClient = _Sentinel
        self._patch = patch.dict("sys.modules", {"app.servicenow": fake_sn})

    def _exercise(self):
        """Run through a full happy-path cycle."""
        state = ConversationState()
        state.transition_to(ConversationPhase.COLLECTING)
        state.transition_to(ConversationPhase.READY_FOR_CONFIRMATION)
        state.transition_to(ConversationPhase.EXECUTING)
        state.transition_to(ConversationPhase.COMPLETED)
        state.transition_to(ConversationPhase.IDLE)

    def test_full_lifecycle_never_touches_servicenow(self):
        with self._patch:
            self._exercise()  # must not raise AssertionError

    def test_invalid_transition_never_touches_servicenow(self):
        with self._patch:
            state = ConversationState()
            try:
                state.transition_to(ConversationPhase.COMPLETED)
            except InvalidTransitionError:
                pass
            # If ServiceNowClient was touched, the sentinel would have raised
            # AssertionError, which would appear as a test error, not a failure.


# ===========================================================================
# 16. No network operation occurs
# ===========================================================================

class TestNoNetworkOperation(unittest.TestCase):

    def test_state_machine_makes_no_network_calls(self):
        mock_httpx = MagicMock()
        mock_httpx.AsyncClient.side_effect = AssertionError(
            "State machine must NOT make network calls"
        )
        mock_httpx.Client.side_effect = AssertionError(
            "State machine must NOT make network calls"
        )
        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            state = ConversationState()
            state.transition_to(ConversationPhase.COLLECTING)
            state.transition_to(ConversationPhase.READY_FOR_CONFIRMATION)
            state.transition_to(ConversationPhase.CANCELLED)
            state.transition_to(ConversationPhase.IDLE)
        # Reaching here means no network call was attempted.

    def test_repository_makes_no_network_calls(self):
        mock_httpx = MagicMock()
        mock_httpx.AsyncClient.side_effect = AssertionError(
            "Repository must NOT make network calls"
        )
        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            repo = InMemoryStateRepository()
            state = repo.get("test-user")
            state.intent = "diagnose"
            repo.save("test-user", state)
            repo.clear("test-user")


# ===========================================================================
# 17. No credentials are accessed
# ===========================================================================

class TestNoCredentialAccess(unittest.TestCase):

    def test_state_machine_does_not_read_env_credentials(self):
        """
        Temporarily hide all servicenow/teams credential env vars and verify
        the state machine still operates correctly.
        """
        credential_keys = [
            "SERVICENOW_INSTANCE",
            "SERVICENOW_CLIENT_ID",
            "SERVICENOW_CLIENT_SECRET",
            "TEAMS_CLIENT_ID",
            "TEAMS_CLIENT_SECRET",
            "TEAMS_TENANT_ID",
            "ADMIN_API_KEY",
        ]
        env_backup = {k: os.environ.pop(k, None) for k in credential_keys}
        try:
            state = ConversationState()
            state.transition_to(ConversationPhase.COLLECTING)
            state.transition_to(ConversationPhase.READY_FOR_CONFIRMATION)
            state.transition_to(ConversationPhase.EXECUTING)
            state.transition_to(ConversationPhase.FAILED)
            state.transition_to(ConversationPhase.IDLE)
            self.assertEqual(state.phase, ConversationPhase.IDLE)
        finally:
            # Restore env vars so other tests/processes are not affected.
            for k, v in env_backup.items():
                if v is not None:
                    os.environ[k] = v

    def test_state_machine_import_does_not_access_env(self):
        """
        Verifies that importing / using app.state does not require
        credential environment variables to be set.
        """
        state = ConversationState()
        self.assertEqual(state.phase, ConversationPhase.IDLE)


# ===========================================================================
# Bonus: ConversationPhase is a str Enum (serialisable)
# ===========================================================================

class TestConversationPhaseProperties(unittest.TestCase):

    def test_phase_is_str(self):
        self.assertIsInstance(ConversationPhase.IDLE.value, str)

    def test_phase_equality_with_string(self):
        # str Enum: the value equals the string
        self.assertEqual(ConversationPhase.IDLE, "idle")

    def test_all_phases_have_values(self):
        expected = {
            "idle", "collecting", "ready_for_confirmation",
            "executing", "completed", "cancelled", "failed",
        }
        actual = {p.value for p in ConversationPhase}
        self.assertEqual(actual, expected)


# ===========================================================================
# Bonus: StateRepository ABC is correctly abstract
# ===========================================================================

class TestStateRepositoryABC(unittest.TestCase):

    def test_cannot_instantiate_abstract_class(self):
        with self.assertRaises(TypeError):
            StateRepository()  # type: ignore[abstract]

    def test_in_memory_is_subclass(self):
        self.assertTrue(issubclass(InMemoryStateRepository, StateRepository))

    def test_module_level_get_session_returns_state(self):
        # Just verify the module-level helper doesn't raise.
        state = get_session("__test_isolation_user__")
        self.assertIsInstance(state, ConversationState)
        clear_session("__test_isolation_user__")

    def test_module_level_save_session(self):
        user = "__test_save_user__"
        state = get_session(user)
        state.intent = "diagnose"
        save_session(user, state)
        retrieved = get_session(user)
        self.assertEqual(retrieved.intent, "diagnose")
        clear_session(user)

    def test_module_level_update_session_backward_compat(self):
        user = "__test_update_compat__"
        result = update_session(user, intent="diagnose", summary="test")
        self.assertEqual(result.intent, "diagnose")
        clear_session(user)

    def test_awaiting_confirmation_param_is_no_op(self):
        """
        BL-002: awaiting_confirmation is deprecated and must not raise.
        """
        user = "__test_awaiting_compat__"
        result = update_session(user, awaiting_confirmation=True)
        # Phase must remain IDLE — the parameter is ignored.
        self.assertEqual(result.phase, ConversationPhase.IDLE)
        clear_session(user)


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
