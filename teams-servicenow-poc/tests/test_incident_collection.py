"""
tests/test_incident_collection.py — Test suite for incident collection (BL-006).

Covers the 45 required BL-006 cases plus edge cases:

 1.  Incident intent starts COLLECTING.
 2.  Empty collection state is created correctly.
 3.  Short description is collected.
 4.  Description is collected.
 5.  Impact is collected.
 6.  Urgency is collected.
 7.  Multiple fields can be collected from one message.
 8.  Missing fields are detected.
 9.  Only missing fields are requested.
10-15. Invalid impact/urgency 0, 4, 5 rejected.
16-21. Valid impact/urgency 1, 2, 3 accepted.
22-25. Corrections of impact, urgency, description, short description.
26-29. Each missing field prevents READY_FOR_CONFIRMATION.
30.  Complete valid collection transitions to READY_FOR_CONFIRMATION.
31.  Collection does not transition to EXECUTING.
32.  Collection does not call ServiceNow.
33.  Collection does not call the ServiceNow Tool Gateway.
34.  Collection does not access credentials.
35.  Collection does not make HTTP calls.
36.  Cancellation resets collection appropriately.
37.  No incident is created on cancellation.
38.  User A's collection does not affect User B.
39.  Invalid input leaves the user in COLLECTING.
40.  Confirmation summary contains only collected values.
41.  Confirmation summary does not invent priority.
42.  Confirmation summary does not invent assignment group.
43.  Confirmation summary does not invent category.
44.  LLM cannot bypass deterministic impact/urgency validation.
45.  Arbitrary fields cannot enter the structured incident payload.

Run with:  python3 -m unittest discover -s tests -p "test_*.py" -v
"""

from __future__ import annotations

import inspect
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import app.incident_collection as collection_module  # noqa: E402
from app.confirmation import evaluate_confirmation  # noqa: E402
from app.incident_collection import (  # noqa: E402
    IMPACT_ERROR,
    INCIDENT_FIELDS,
    URGENCY_ERROR,
    IncidentCollectionError,
    build_confirmation_summary,
    missing_fields,
    process_collection_message,
    sanitize_details,
    start_incident_collection,
    validate_incident_payload,
)
from app.servicenow import ServiceNowClient  # noqa: E402
from app.state import (  # noqa: E402
    ConversationPhase,
    ConversationState,
    InMemoryStateRepository,
)
from app.tools.servicenow import (  # noqa: E402
    CreateIncidentToolRequest,
    ServiceNowToolGateway,
)


FULL_MESSAGE = (
    "VPN is down for me and I can't access internal applications. "
    "Impact is 2 and urgency is 1."
)


def _collecting(message: str = "I need to report an issue") -> ConversationState:
    state = ConversationState()
    start_incident_collection(state, message)
    return state


def _with_text_fields() -> ConversationState:
    """COLLECTING with short_description + description, awaiting impact."""
    state = _collecting()
    process_collection_message(state, "My laptop VPN isn't connecting.")
    return state


def _with_impact(impact: str = "2") -> ConversationState:
    """COLLECTING with everything except urgency."""
    state = _with_text_fields()
    process_collection_message(state, impact)
    return state


def _complete() -> ConversationState:
    state = _with_impact("2")
    process_collection_message(state, "1")
    return state


# ===========================================================================
# 1–2: Starting collection
# ===========================================================================

class TestStartCollection(unittest.TestCase):

    def test_01_incident_intent_starts_collecting(self):
        state = ConversationState()
        result = start_incident_collection(state, "I need to report an issue")
        self.assertEqual(state.phase, ConversationPhase.COLLECTING)
        self.assertEqual(result.phase, ConversationPhase.COLLECTING)
        self.assertEqual(state.pending_action, "create_incident")
        self.assertEqual(state.intent, "create_incident")

    def test_02_empty_collection_state_created(self):
        state = ConversationState(collected_details={"stale": "x", "impact": "1"})
        result = start_incident_collection(state, "Please raise a ticket.")
        self.assertEqual(state.collected_details, {})
        self.assertEqual(result.missing, INCIDENT_FIELDS)
        self.assertIn("short description", result.reply.lower())

    def test_start_from_terminal_phase_returns_through_idle(self):
        for phase in (
            ConversationPhase.COMPLETED,
            ConversationPhase.FAILED,
            ConversationPhase.CANCELLED,
        ):
            with self.subTest(phase=phase):
                state = ConversationState(phase=phase, incident_number="INC0010001")
                start_incident_collection(state, "raise a ticket")
                self.assertEqual(state.phase, ConversationPhase.COLLECTING)
                self.assertIsNone(state.incident_number)

    def test_start_rejected_from_active_phases(self):
        for phase in (
            ConversationPhase.COLLECTING,
            ConversationPhase.READY_FOR_CONFIRMATION,
            ConversationPhase.EXECUTING,
        ):
            with self.subTest(phase=phase):
                state = ConversationState(phase=phase)
                with self.assertRaises(IncidentCollectionError):
                    start_incident_collection(state, "raise a ticket")
                self.assertEqual(state.phase, phase)

    def test_request_only_messages_capture_nothing(self):
        for message in (
            "I need to report an issue",
            "Please raise a ticket.",
            "Log this issue with IT.",
            "Report this as an incident.",
            "Create an incident",
        ):
            with self.subTest(message=message):
                state = _collecting(message)
                self.assertEqual(state.collected_details, {})

    def test_request_wording_stripped_from_details(self):
        state = _collecting("Create an incident for my VPN issue")
        self.assertEqual(state.collected_details["description"], "my VPN issue")
        state = _collecting("My VPN is down, please raise a ticket.")
        self.assertEqual(state.collected_details["description"], "My VPN is down")

    def test_process_requires_collecting_phase(self):
        for phase in ConversationPhase:
            if phase is ConversationPhase.COLLECTING:
                continue
            with self.subTest(phase=phase):
                with self.assertRaises(IncidentCollectionError):
                    process_collection_message(ConversationState(phase=phase), "impact 2")


# ===========================================================================
# 3–9: Collecting fields
# ===========================================================================

class TestFieldCollection(unittest.TestCase):

    def test_03_short_description_collected(self):
        state = _collecting()
        process_collection_message(state, "short description: VPN outage")
        self.assertEqual(state.collected_details["short_description"], "VPN outage")

    def test_04_description_collected(self):
        state = _collecting()
        process_collection_message(state, "short description: VPN outage")
        result = process_collection_message(
            state, "Cannot reach the intranet over VPN since this morning."
        )
        self.assertEqual(
            state.collected_details["description"],
            "Cannot reach the intranet over VPN since this morning.",
        )
        self.assertIn("description", result.captured)

    def test_04b_labelled_description_collected(self):
        state = _collecting()
        process_collection_message(state, "description: cannot reach intranet")
        self.assertEqual(state.collected_details["description"], "cannot reach intranet")

    def test_05_impact_collected(self):
        state = _with_text_fields()
        process_collection_message(state, "2")
        self.assertEqual(state.collected_details["impact"], "2")

    def test_06_urgency_collected(self):
        state = _with_impact()
        process_collection_message(state, "3")
        self.assertEqual(state.collected_details["urgency"], "3")

    def test_07_multiple_fields_from_one_message(self):
        state = ConversationState()
        start_incident_collection(state, FULL_MESSAGE)
        details = state.collected_details
        self.assertEqual(
            details["short_description"],
            "VPN is down for me and I can't access internal applications",
        )
        self.assertEqual(
            details["description"],
            "VPN is down for me and I can't access internal applications.",
        )
        self.assertEqual(details["impact"], "2")
        self.assertEqual(details["urgency"], "1")

    def test_07b_multiple_labelled_fields_mid_collection(self):
        state = _with_text_fields()
        result = process_collection_message(state, "Impact 2, urgency 1.")
        self.assertEqual(state.collected_details["impact"], "2")
        self.assertEqual(state.collected_details["urgency"], "1")
        self.assertTrue(result.ready)

    def test_08_missing_fields_detected(self):
        self.assertEqual(missing_fields({}), INCIDENT_FIELDS)
        self.assertEqual(
            missing_fields({"short_description": "a", "impact": "1"}),
            ("description", "urgency"),
        )
        self.assertEqual(missing_fields({"description": "", "impact": "1"}),
                         ("short_description", "description", "urgency"))

    def test_09_only_missing_fields_requested(self):
        state = ConversationState()
        result = start_incident_collection(
            state, "My VPN keeps dropping. Impact 2."
        )
        self.assertEqual(result.missing, ("urgency",))
        self.assertIn("urgency", result.reply.lower())
        self.assertNotIn("impact is this having", result.reply.lower())
        self.assertNotIn("short description", result.reply.lower())

    def test_prompts_follow_collection_order(self):
        state = ConversationState()
        r = start_incident_collection(state, "raise a ticket")
        self.assertIn("short description", r.reply.lower())
        r = process_collection_message(state, "title: VPN outage")
        self.assertIn("describe the issue", r.reply.lower())
        r = process_collection_message(state, "Cannot reach intranet.")
        self.assertIn("what impact", r.reply.lower())
        r = process_collection_message(state, "2")
        self.assertIn("urgency", r.reply.lower())

    def test_single_sentence_does_not_invent_impact_or_urgency(self):
        state = _collecting("My VPN isn't working")
        self.assertNotIn("impact", state.collected_details)
        self.assertNotIn("urgency", state.collected_details)
        self.assertEqual(state.phase, ConversationPhase.COLLECTING)

    def test_prose_mentioning_impact_is_not_a_value(self):
        state = _collecting("Outlook crashes. This has a big impact on my work.")
        self.assertNotIn("impact", state.collected_details)
        self.assertIn("big impact", state.collected_details["description"])

    def test_help_question_lists_missing_fields_without_capturing(self):
        state = _with_text_fields()
        result = process_collection_message(state, "What details do you need?")
        self.assertIn("Impact", result.reply)
        self.assertIn("Urgency", result.reply)
        self.assertNotIn("Short description", result.reply)
        self.assertEqual(set(state.collected_details), {"short_description", "description"})
        self.assertEqual(state.phase, ConversationPhase.COLLECTING)


# ===========================================================================
# 10–21: Impact / urgency validation
# ===========================================================================

class TestLevelValidation(unittest.TestCase):

    def _assert_rejected(self, state, message, field, error):
        before = dict(state.collected_details)
        result = process_collection_message(state, message)
        self.assertIn(error, result.errors)
        self.assertIn(error, result.reply)
        self.assertEqual(state.collected_details.get(field), before.get(field))
        self.assertEqual(state.phase, ConversationPhase.COLLECTING)

    def test_10_invalid_impact_0_rejected(self):
        self._assert_rejected(_with_text_fields(), "0", "impact", IMPACT_ERROR)

    def test_11_invalid_impact_4_rejected(self):
        self._assert_rejected(_with_text_fields(), "4", "impact", IMPACT_ERROR)

    def test_12_invalid_impact_5_rejected(self):
        self._assert_rejected(_with_text_fields(), "impact 5", "impact", IMPACT_ERROR)

    def test_13_invalid_urgency_0_rejected(self):
        self._assert_rejected(_with_impact(), "0", "urgency", URGENCY_ERROR)

    def test_14_invalid_urgency_4_rejected(self):
        self._assert_rejected(_with_impact(), "urgency is 4", "urgency", URGENCY_ERROR)

    def test_15_invalid_urgency_5_rejected(self):
        self._assert_rejected(_with_impact(), "5", "urgency", URGENCY_ERROR)

    def test_words_rejected_without_mapping(self):
        for word in ("high", "medium", "low", "critical"):
            with self.subTest(word=word):
                self._assert_rejected(_with_text_fields(), word, "impact", IMPACT_ERROR)
                self._assert_rejected(
                    _with_text_fields(), f"impact is {word}", "impact", IMPACT_ERROR
                )
                self._assert_rejected(_with_impact(), word, "urgency", URGENCY_ERROR)

    def test_free_text_answer_to_level_question_rejected(self):
        self._assert_rejected(
            _with_text_fields(), "it affects the whole team", "impact", IMPACT_ERROR
        )
        self._assert_rejected(_with_text_fields(), "2 people", "impact", IMPACT_ERROR)

    def test_16_to_18_valid_impact_accepted(self):
        for value in ("1", "2", "3"):
            with self.subTest(value=value):
                state = _with_text_fields()
                result = process_collection_message(state, value)
                self.assertEqual(state.collected_details["impact"], value)
                self.assertEqual(result.errors, ())

    def test_16_valid_impact_1_accepted(self):
        state = _with_text_fields()
        process_collection_message(state, "impact: 1")
        self.assertEqual(state.collected_details["impact"], "1")

    def test_17_valid_impact_2_accepted(self):
        state = _with_text_fields()
        process_collection_message(state, "Impact is 2")
        self.assertEqual(state.collected_details["impact"], "2")

    def test_18_valid_impact_3_accepted(self):
        state = _with_text_fields()
        process_collection_message(state, "3.")
        self.assertEqual(state.collected_details["impact"], "3")

    def test_19_valid_urgency_1_accepted(self):
        state = _with_impact()
        process_collection_message(state, "1")
        self.assertEqual(state.collected_details["urgency"], "1")

    def test_20_valid_urgency_2_accepted(self):
        state = _with_impact()
        process_collection_message(state, "urgency 2")
        self.assertEqual(state.collected_details["urgency"], "2")

    def test_21_valid_urgency_3_accepted(self):
        state = _with_impact()
        process_collection_message(state, "Urgency: 3")
        self.assertEqual(state.collected_details["urgency"], "3")

    def test_invalid_label_does_not_discard_valid_label_in_same_message(self):
        state = _with_text_fields()
        result = process_collection_message(state, "impact 5 and urgency 2")
        self.assertIn(IMPACT_ERROR, result.errors)
        self.assertEqual(state.collected_details["urgency"], "2")
        self.assertNotIn("impact", state.collected_details)


# ===========================================================================
# 22–25: Corrections
# ===========================================================================

class TestCorrections(unittest.TestCase):

    def test_22_correction_of_impact(self):
        state = _with_impact("2")
        result = process_collection_message(state, "Actually impact should be 1.")
        self.assertEqual(state.collected_details["impact"], "1")
        self.assertEqual(state.phase, ConversationPhase.COLLECTING)
        self.assertEqual(result.missing, ("urgency",))

    def test_23_correction_of_urgency(self):
        state = _with_text_fields()
        process_collection_message(state, "urgency 1")
        process_collection_message(state, "Change urgency to 3.")
        self.assertEqual(state.collected_details["urgency"], "3")
        self.assertEqual(state.phase, ConversationPhase.COLLECTING)

    def test_24_correction_of_description(self):
        state = _with_text_fields()
        process_collection_message(
            state, "Change the description to VPN fails with error 809 since 9am"
        )
        self.assertEqual(
            state.collected_details["description"],
            "VPN fails with error 809 since 9am",
        )
        self.assertEqual(state.phase, ConversationPhase.COLLECTING)

    def test_25_correction_of_short_description(self):
        state = _with_text_fields()
        process_collection_message(state, "The short description should be VPN error 809")
        self.assertEqual(state.collected_details["short_description"], "VPN error 809")
        process_collection_message(state, "change the title to VPN outage")
        self.assertEqual(state.collected_details["short_description"], "VPN outage")

    def test_invalid_correction_keeps_previous_valid_value(self):
        state = _with_impact("2")
        result = process_collection_message(state, "change impact to 4")
        self.assertIn(IMPACT_ERROR, result.errors)
        self.assertEqual(state.collected_details["impact"], "2")

    def test_corrected_value_used_in_summary(self):
        state = _with_impact("2")
        process_collection_message(state, "actually impact should be 3")
        result = process_collection_message(state, "1")
        self.assertIn("**Impact:** 3", result.reply)
        self.assertNotIn("**Impact:** 2", result.reply)


# ===========================================================================
# Short description limits
# ===========================================================================

class TestShortDescription(unittest.TestCase):

    def test_long_single_sentence_not_used_as_title(self):
        long_text = "VPN " + "fails repeatedly " * 15
        state = _collecting()
        result = process_collection_message(state, long_text)
        self.assertIn("description", state.collected_details)
        self.assertNotIn("short_description", state.collected_details)
        self.assertEqual(result.missing[0], "short_description")

    def test_first_sentence_used_when_it_fits(self):
        state = _collecting()
        process_collection_message(
            state, "VPN drops. " + "It disconnects every few minutes. " * 10
        )
        self.assertEqual(state.collected_details["short_description"], "VPN drops")

    def test_overlong_short_description_rejected(self):
        state = _collecting()
        result = process_collection_message(state, "title: " + "x" * 161)
        self.assertNotIn("short_description", state.collected_details)
        self.assertTrue(result.errors)
        self.assertEqual(state.phase, ConversationPhase.COLLECTING)

    def test_160_character_short_description_accepted(self):
        state = _collecting()
        process_collection_message(state, "title: " + "x" * 160)
        self.assertEqual(len(state.collected_details["short_description"]), 160)


# ===========================================================================
# 26–31: Completion boundary
# ===========================================================================

class TestCompletion(unittest.TestCase):

    def _assert_not_ready_without(self, field):
        values = {
            "short_description": "title: VPN outage",
            "description": "description: cannot reach intranet",
            "impact": "impact 2",
            "urgency": "urgency 1",
        }
        state = _collecting()
        for name, message in values.items():
            if name != field:
                process_collection_message(state, message)
        self.assertEqual(state.phase, ConversationPhase.COLLECTING)
        self.assertEqual(missing_fields(state.collected_details), (field,))

    def test_26_missing_description_prevents_ready(self):
        self._assert_not_ready_without("description")

    def test_27_missing_impact_prevents_ready(self):
        self._assert_not_ready_without("impact")

    def test_28_missing_urgency_prevents_ready(self):
        self._assert_not_ready_without("urgency")

    def test_29_missing_short_description_prevents_ready(self):
        self._assert_not_ready_without("short_description")

    def test_30_complete_collection_transitions_to_ready(self):
        state = _with_impact("2")
        result = process_collection_message(state, "1")
        self.assertTrue(result.ready)
        self.assertEqual(state.phase, ConversationPhase.READY_FOR_CONFIRMATION)
        self.assertEqual(state.pending_action, "create_incident")
        self.assertEqual(state.summary, state.collected_details["short_description"])

    def test_30b_all_fields_in_first_message_reaches_ready(self):
        state = ConversationState()
        result = start_incident_collection(state, FULL_MESSAGE)
        self.assertTrue(result.ready)
        self.assertEqual(state.phase, ConversationPhase.READY_FOR_CONFIRMATION)

    def test_31_collection_never_transitions_to_executing(self):
        seen = []
        original = ConversationState.transition_to

        def spy(self, new_phase):
            seen.append(new_phase)
            return original(self, new_phase)

        with patch.object(ConversationState, "transition_to", spy):
            state = ConversationState()
            start_incident_collection(state, "raise a ticket")
            for msg in ("title: VPN", "description: down", "2", "yes", "1"):
                if state.phase is ConversationPhase.COLLECTING:
                    process_collection_message(state, msg)

        self.assertNotIn(ConversationPhase.EXECUTING, seen)
        self.assertNotIn(ConversationPhase.COMPLETED, seen)
        self.assertEqual(state.phase, ConversationPhase.READY_FOR_CONFIRMATION)

    def test_confirmation_words_are_not_collected_or_treated_as_approval(self):
        state = _with_impact()
        for word in ("yes", "okay", "sure", "sounds good"):
            with self.subTest(word=word):
                result = process_collection_message(state, word)
                self.assertIn(URGENCY_ERROR, result.errors)
                self.assertEqual(state.phase, ConversationPhase.COLLECTING)

    def test_ready_state_is_accepted_by_bl003_gate(self):
        state = _complete()
        self.assertTrue(evaluate_confirmation(state, "yes").confirmed)
        # BL-006 does not treat vague wording as confirmation.
        self.assertFalse(evaluate_confirmation(state, "sounds good").confirmed)

    def test_ready_payload_is_valid_for_bl005_gateway_contract(self):
        state = _complete()
        request = CreateIncidentToolRequest(**state.collected_details)
        request.validate()  # raises on contract violation


# ===========================================================================
# 32–35: Side-effect and security boundaries
# ===========================================================================

class TestNoSideEffects(unittest.TestCase):

    def _run_full_collection(self):
        state = ConversationState()
        start_incident_collection(state, "I need to report an issue")
        for msg in (
            "My laptop VPN isn't connecting.",
            "2",
            "Actually impact should be 1.",
            "3",
        ):
            process_collection_message(state, msg)
        return state

    def test_32_collection_does_not_call_servicenow(self):
        with patch.object(ServiceNowClient, "create_incident", new_callable=AsyncMock) as create, \
             patch.object(ServiceNowClient, "update_incident", new_callable=AsyncMock) as update, \
             patch.object(ServiceNowClient, "get_incident", new_callable=AsyncMock) as get:
            state = self._run_full_collection()
        self.assertEqual(state.phase, ConversationPhase.READY_FOR_CONFIRMATION)
        create.assert_not_called()
        update.assert_not_called()
        get.assert_not_called()

    def test_33_collection_does_not_call_tool_gateway(self):
        with patch.object(ServiceNowToolGateway, "execute", new_callable=AsyncMock) as execute:
            self._run_full_collection()
        execute.assert_not_called()

    def test_34_collection_does_not_access_credentials(self):
        with patch("os.getenv", side_effect=AssertionError("getenv called")), \
             patch.dict("os.environ", {}, clear=True):
            state = self._run_full_collection()
        self.assertEqual(state.phase, ConversationPhase.READY_FOR_CONFIRMATION)
        source = inspect.getsource(collection_module)
        for forbidden in ("getenv", "os.environ", "dotenv", "token", "client_secret"):
            self.assertNotIn(forbidden, source)

    def test_35_collection_does_not_make_http_calls(self):
        import httpx

        with patch.object(httpx.AsyncClient, "send", side_effect=AssertionError("HTTP")), \
             patch.object(httpx.Client, "send", side_effect=AssertionError("HTTP")), \
             patch("socket.socket.connect", side_effect=AssertionError("socket")):
            state = self._run_full_collection()
        self.assertEqual(state.phase, ConversationPhase.READY_FOR_CONFIRMATION)

    def test_collector_module_has_no_transport_imports(self):
        source = inspect.getsource(collection_module)
        for forbidden in (
            "import httpx", "import requests", "app.servicenow", "app.tools",
            "app.ai", "ollama", "microsoft_teams", "app.security",
        ):
            self.assertNotIn(forbidden, source)


# ===========================================================================
# 36–39: Cancellation, isolation, invalid input
# ===========================================================================

class TestCancellationAndIsolation(unittest.TestCase):

    def test_36_cancellation_resets_collection(self):
        for phrase in ("cancel", "stop", "never mind", "abort", "  CANCEL "):
            with self.subTest(phrase=phrase):
                state = _with_impact()
                result = process_collection_message(state, phrase)
                self.assertTrue(result.cancelled)
                self.assertEqual(state.phase, ConversationPhase.IDLE)
                self.assertEqual(state.collected_details, {})
                self.assertIsNone(state.pending_action)
                self.assertIsNone(state.intent)
                self.assertNotIn("urgency", result.reply.lower())

    def test_36b_cancellation_passes_through_cancelled(self):
        seen = []
        original = ConversationState.transition_to

        def spy(self, new_phase):
            seen.append(new_phase)
            return original(self, new_phase)

        state = _with_text_fields()
        with patch.object(ConversationState, "transition_to", spy):
            process_collection_message(state, "cancel")
        self.assertEqual(seen, [ConversationPhase.CANCELLED, ConversationPhase.IDLE])

    def test_37_no_incident_created_on_cancellation(self):
        with patch.object(ServiceNowClient, "create_incident", new_callable=AsyncMock) as create, \
             patch.object(ServiceNowToolGateway, "execute", new_callable=AsyncMock) as execute:
            state = _with_impact()
            process_collection_message(state, "cancel")
            # A later confirmation word cannot resurrect the cancelled request.
            self.assertFalse(evaluate_confirmation(state, "yes").confirmed)
        create.assert_not_called()
        execute.assert_not_called()

    def test_38_users_are_isolated(self):
        repo = InMemoryStateRepository()
        a = repo.get("user-a")
        b = repo.get("user-b")
        start_incident_collection(a, "raise a ticket")
        start_incident_collection(b, "raise a ticket")
        process_collection_message(a, "title: Printer jam")
        process_collection_message(a, "description: Paper stuck")
        process_collection_message(a, "impact 1")
        process_collection_message(b, "title: VPN down")

        self.assertEqual(repo.get("user-a").collected_details["short_description"], "Printer jam")
        self.assertEqual(repo.get("user-a").collected_details["impact"], "1")
        self.assertEqual(repo.get("user-b").collected_details, {"short_description": "VPN down"})

        process_collection_message(b, "cancel")
        self.assertEqual(repo.get("user-b").phase, ConversationPhase.IDLE)
        self.assertEqual(repo.get("user-a").phase, ConversationPhase.COLLECTING)
        self.assertEqual(repo.get("user-a").collected_details["impact"], "1")

    def test_39_invalid_input_stays_collecting(self):
        state = _with_text_fields()
        for message in ("0", "9", "high", "", "   ", "impact 7"):
            with self.subTest(message=message):
                process_collection_message(state, message)
                self.assertEqual(state.phase, ConversationPhase.COLLECTING)
                self.assertNotIn("impact", state.collected_details)


# ===========================================================================
# 40–43: Confirmation summary
# ===========================================================================

class TestConfirmationSummary(unittest.TestCase):

    def setUp(self):
        self.state = ConversationState()
        self.result = start_incident_collection(self.state, FULL_MESSAGE)
        self.summary = self.result.reply

    def test_40_summary_contains_only_collected_values(self):
        details = self.state.collected_details
        for field in INCIDENT_FIELDS:
            self.assertIn(details[field], self.summary)
        lines = [line for line in self.summary.splitlines() if line.startswith("**")]
        self.assertEqual(
            [line.split(":**")[0] for line in lines],
            ["**Short description", "**Description", "**Impact", "**Urgency"],
        )
        self.assertIn("Shall I create this incident?", self.summary)

    def test_41_summary_does_not_invent_priority(self):
        self.assertNotIn("priority", self.summary.lower())

    def test_42_summary_does_not_invent_assignment_group(self):
        self.assertNotIn("assignment", self.summary.lower())
        self.assertNotIn("group", self.summary.lower())

    def test_43_summary_does_not_invent_category(self):
        for word in ("category", "subcategory", "caller", "location", "department"):
            self.assertNotIn(word, self.summary.lower())

    def test_build_summary_ignores_extra_keys(self):
        payload = validate_incident_payload(
            {
                "short_description": "VPN",
                "description": "Down",
                "impact": "2",
                "urgency": "1",
                "priority": "1",
                "assignment_group": "Network",
            }
        )
        summary = build_confirmation_summary(payload)
        self.assertNotIn("priority", summary.lower())
        self.assertNotIn("Network", summary)


# ===========================================================================
# 44–45: LLM boundary and payload allowlist
# ===========================================================================

def _teams_context(user_id: str, text: str):
    activity = SimpleNamespace(
        text=text,
        from_=SimpleNamespace(aad_object_id=user_id, id=user_id),
        channel_data={},
    )
    return SimpleNamespace(activity=activity, send=AsyncMock())


class TestMainIntegration(unittest.IsolatedAsyncioTestCase):
    """Drives app.main.on_message with the LLM, ServiceNow and gateway mocked."""

    async def asyncSetUp(self):
        import app.main as main

        self.main = main
        self.user_id = "bl006-integration-user"
        from app.state import clear_session

        clear_session(self.user_id)
        self.addCleanup(clear_session, self.user_id)

        self.classify = AsyncMock(
            return_value={
                "intent": "create_incident",
                # Hostile LLM output: claims values and extra fields.
                "summary": "Impact 1 urgency 1 priority 1 assignment group Network",
                "impact": "5",
                "urgency": "9",
                "assignment_group": "Network",
                "needs_service_now": True,
            }
        )
        patches = [
            patch.object(main, "classify_message", self.classify),
            patch.object(main.servicenow_gateway, "execute", new_callable=AsyncMock),
            patch.object(main.servicenow, "create_incident", new_callable=AsyncMock),
            patch.object(main.servicenow, "update_incident", new_callable=AsyncMock),
        ]
        mocks = [p.start() for p in patches]
        for p in patches:
            self.addCleanup(p.stop)
        self.execute, self.create, self.update = mocks[1], mocks[2], mocks[3]

    async def _send(self, text):
        ctx = _teams_context(self.user_id, text)
        await self.main.on_message(ctx)
        ctx.send.assert_awaited_once()
        return ctx.send.await_args.args[0]

    async def test_44_llm_cannot_bypass_validation(self):
        from app.state import get_session

        await self._send("Create an incident for my VPN issue")
        session = get_session(self.user_id)
        self.assertEqual(session.phase, ConversationPhase.COLLECTING)
        self.assertNotIn("impact", session.collected_details)
        self.assertNotIn("urgency", session.collected_details)
        self.assertNotIn("assignment_group", session.collected_details)

        # While collecting, the LLM is not consulted at all.
        self.classify.reset_mock()
        reply = await self._send("impact 5")
        self.assertIn(IMPACT_ERROR, reply)
        self.classify.assert_not_called()
        self.assertNotIn("impact", get_session(self.user_id).collected_details)

    async def test_full_flow_stops_at_ready_for_confirmation(self):
        from app.state import get_session

        reply = await self._send("I need to report an issue")
        self.assertIn("short description", reply.lower())
        await self._send("My laptop VPN isn't connecting.")
        reply = await self._send("2")
        self.assertIn("urgency", reply.lower())
        reply = await self._send("1")

        session = get_session(self.user_id)
        self.assertEqual(session.phase, ConversationPhase.READY_FOR_CONFIRMATION)
        self.assertIn("Shall I create this incident?", reply)
        self.assertNotIn("priority", reply.lower())
        self.assertEqual(self.classify.await_count, 1)
        self.execute.assert_not_called()
        self.create.assert_not_called()
        self.update.assert_not_called()

    async def test_cancel_during_collection_via_handler(self):
        from app.state import get_session

        await self._send("I need to report an issue")
        reply = await self._send("never mind")
        self.assertIn("No incident has been created", reply)
        self.assertEqual(get_session(self.user_id).phase, ConversationPhase.IDLE)
        self.execute.assert_not_called()
        self.create.assert_not_called()


class TestPayloadAllowlist(unittest.TestCase):

    def test_45_arbitrary_fields_cannot_enter_payload(self):
        state = _collecting()
        state.collected_details.update(
            {"assignment_group": "Network", "priority": "1", "sys_id": "abc", "table": "sys_user"}
        )
        process_collection_message(state, FULL_MESSAGE)
        self.assertEqual(state.phase, ConversationPhase.READY_FOR_CONFIRMATION)
        self.assertEqual(set(state.collected_details), set(INCIDENT_FIELDS))

    def test_45b_message_cannot_introduce_new_keys(self):
        state = _collecting()
        process_collection_message(
            state,
            "assignment group: Network. priority: 1. category: hardware. "
            "title: VPN down",
        )
        self.assertTrue(set(state.collected_details) <= set(INCIDENT_FIELDS))

    def test_45c_sanitize_and_validate_drop_unknown_keys(self):
        dirty = {
            "short_description": "VPN",
            "description": "Down",
            "impact": "2",
            "urgency": "1",
            "caller_id": "admin",
            "impact_override": "5",
        }
        self.assertEqual(set(sanitize_details(dirty)), set(INCIDENT_FIELDS))
        self.assertEqual(set(validate_incident_payload(dirty)), set(INCIDENT_FIELDS))

    def test_validate_payload_rejects_out_of_contract_values(self):
        base = {"short_description": "VPN", "description": "Down", "impact": "2", "urgency": "1"}
        for field, bad in (("impact", "4"), ("urgency", "5"), ("impact", "high"),
                           ("short_description", "x" * 161), ("description", "  ")):
            with self.subTest(field=field, bad=bad):
                with self.assertRaises(ValueError):
                    validate_incident_payload({**base, field: bad})

    def test_non_string_values_are_dropped(self):
        self.assertEqual(sanitize_details({"impact": 2, "urgency": None}), {})


if __name__ == "__main__":
    unittest.main()
