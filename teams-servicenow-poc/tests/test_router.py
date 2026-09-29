"""
tests/test_router.py — Test suite for app.router (BL-001 corrective patch).

Test categories
───────────────
1.  Valid exact incident number
2.  Valid status patterns
3.  Lowercase normalisation
4.  Leading/trailing whitespace
5.  Suspicious suffix / prefix content
6.  SQL-like injection text
7.  HTML / script-like text
8.  Unsupported extra words
9.  Router purity (no ServiceNow instantiation, no network calls)

Run with:   pytest -q
Compile with: python -m compileall tests
"""

import sys
import types
import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Ensure the project root is on the path when running directly or via pytest.
# ---------------------------------------------------------------------------
import os

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from app.router import RouteResult, route_message  # noqa: E402


# ===========================================================================
# Helper
# ===========================================================================

def _assert_incident_status(message: str, expected_number: str = "INC0010002") -> RouteResult:
    """Assert route_message returns incident_status and the expected number."""
    result = route_message(message)
    assert result is not None, f"Expected RouteResult for {message!r}, got None"
    assert result.intent == "incident_status", (
        f"Expected intent='incident_status', got {result.intent!r} for {message!r}"
    )
    assert result.incident_number == expected_number, (
        f"Expected incident_number={expected_number!r}, "
        f"got {result.incident_number!r} for {message!r}"
    )
    return result


def _assert_no_route(message: str) -> None:
    """Assert route_message returns None (no deterministic route)."""
    result = route_message(message)
    assert result is None, (
        f"Expected None for {message!r}, got {result!r}"
    )


# ===========================================================================
# 1. Valid exact incident number
# ===========================================================================

class TestValidExactIncidentNumber(unittest.TestCase):
    """Bare incident number with no surrounding text must be routed."""

    def test_bare_incident_number_standard(self):
        _assert_incident_status("INC0010002")

    def test_bare_incident_number_7_digits(self):
        _assert_incident_status("INC0000001", expected_number="INC0000001")

    def test_bare_incident_number_10_digits(self):
        _assert_incident_status("INC0000000001", expected_number="INC0000000001")

    def test_bare_returns_route_result_type(self):
        result = route_message("INC0010002")
        self.assertIsInstance(result, RouteResult)

    def test_bare_incident_number_intent(self):
        result = route_message("INC0010002")
        self.assertEqual(result.intent, "incident_status")

    def test_bare_incident_number_extracted(self):
        result = route_message("INC0010002")
        self.assertEqual(result.incident_number, "INC0010002")


# ===========================================================================
# 2. Valid status patterns
# ===========================================================================

class TestValidStatusPatterns(unittest.TestCase):
    """All approved lead-in phrases must route correctly."""

    def test_status_of(self):
        _assert_incident_status("status of INC0010002")

    def test_check(self):
        _assert_incident_status("check INC0010002")

    def test_check_status_of(self):
        _assert_incident_status("check status of INC0010002")

    def test_what_is_the_status_of(self):
        _assert_incident_status("what is the status of INC0010002")

    def test_what_is_the_check_status_of(self):
        # Pattern allows: "what is the" + "check" + "status of" combined.
        # This is a legitimate match of the approved optional parts.
        _assert_incident_status("what is the check status of INC0010002")


# ===========================================================================
# 3. Lowercase normalisation
# ===========================================================================

class TestLowercaseNormalisation(unittest.TestCase):
    """Incident numbers in any case must be normalised to upper-case."""

    def test_all_lowercase_bare(self):
        _assert_incident_status("inc0010002")

    def test_all_lowercase_status_of(self):
        _assert_incident_status("status of inc0010002")

    def test_mixed_case_check(self):
        _assert_incident_status("check Inc0010002")

    def test_uppercase_preserved(self):
        result = route_message("inc0010002")
        self.assertEqual(result.incident_number, "INC0010002")

    def test_lead_in_lowercase(self):
        _assert_incident_status("STATUS OF INC0010002")

    def test_lead_in_mixed_case(self):
        _assert_incident_status("Check Status Of INC0010002")


# ===========================================================================
# 4. Leading / trailing whitespace
# ===========================================================================

class TestWhitespaceHandling(unittest.TestCase):
    """Leading and trailing whitespace must be ignored."""

    def test_leading_spaces(self):
        _assert_incident_status("   INC0010002")

    def test_trailing_spaces(self):
        _assert_incident_status("INC0010002   ")

    def test_both_sides(self):
        _assert_incident_status("   INC0010002   ")

    def test_tabs(self):
        _assert_incident_status("\tINC0010002\t")

    def test_newline(self):
        _assert_incident_status("\nINC0010002\n")

    def test_check_with_extra_spaces_stripped(self):
        # "   check   inc0010002   " — only outer strip is guaranteed;
        # internal multiple spaces between "check" and the number are
        # handled by \s+ in the pattern.
        _assert_incident_status("   check   inc0010002   ")


# ===========================================================================
# 5. Suspicious suffix / prefix content
# ===========================================================================

class TestSuspiciousSuffixPrefix(unittest.TestCase):
    """Arbitrary text surrounding the incident number must block routing."""

    def test_suspicious_prefix(self):
        _assert_no_route("EVIL status of INC0010002")

    def test_extra_word_after(self):
        _assert_no_route("status of INC0010002 foo")

    def test_check_with_extra_word(self):
        _assert_no_route("check INC0010002 anything else")

    def test_number_in_middle_of_sentence(self):
        _assert_no_route("please check INC0010002 urgently")

    def test_number_only_surrounded_by_words(self):
        _assert_no_route("the incident INC0010002 needs attention")


# ===========================================================================
# 6. SQL-like injection text
# ===========================================================================

class TestSQLInjection(unittest.TestCase):
    """SQL-like injection suffixes must not be extracted as incident status."""

    def test_semicolon_drop_table(self):
        _assert_no_route("status of INC0010002; DROP TABLE incident")

    def test_double_dash_comment(self):
        _assert_no_route("status of INC0010002 -- comment")

    def test_union_select(self):
        _assert_no_route("status of INC0010002 UNION SELECT 1")

    def test_or_1_equals_1(self):
        _assert_no_route("status of INC0010002 OR 1=1")

    def test_semicolon_alone(self):
        _assert_no_route("INC0010002;")

    def test_check_semicolon_drop(self):
        _assert_no_route("check INC0010002; DROP TABLE users")


# ===========================================================================
# 7. HTML / script-like text
# ===========================================================================

class TestHTMLScriptInjection(unittest.TestCase):
    """HTML/script injection suffixes must not be extracted as incident status."""

    def test_script_tag_after(self):
        _assert_no_route("status of INC0010002<script>")

    def test_script_tag_full(self):
        _assert_no_route("status of INC0010002<script>alert(1)</script>")

    def test_angle_bracket_after(self):
        _assert_no_route("INC0010002<")

    def test_angle_bracket_before(self):
        _assert_no_route("<INC0010002")

    def test_html_entity_after(self):
        _assert_no_route("INC0010002&amp;")

    def test_url_encoded(self):
        _assert_no_route("INC0010002%3Cscript%3E")


# ===========================================================================
# 8. Unsupported extra words
# ===========================================================================

class TestUnsupportedExtraWords(unittest.TestCase):
    """Only approved lead-in phrases are accepted; anything else must fail."""

    def test_please_check(self):
        # "please check" is not an approved lead-in
        _assert_no_route("please check INC0010002")

    def test_show_me(self):
        _assert_no_route("show me INC0010002")

    def test_get_status(self):
        _assert_no_route("get status INC0010002")

    def test_find_incident(self):
        _assert_no_route("find incident INC0010002")

    def test_lookup(self):
        _assert_no_route("lookup INC0010002")

    def test_can_you_check(self):
        _assert_no_route("can you check INC0010002")

    def test_trailing_period(self):
        _assert_no_route("INC0010002.")

    def test_trailing_question_mark(self):
        _assert_no_route("INC0010002?")

    def test_empty_string(self):
        _assert_no_route("")

    def test_whitespace_only(self):
        _assert_no_route("   ")


# ===========================================================================
# 9. Router purity
# ===========================================================================

class TestRouterPurity(unittest.TestCase):
    """
    Demonstrate that route_message():
      - does not instantiate ServiceNowClient
      - does not call ServiceNow
      - does not perform network operations

    Strategy: inject a fake ``app.servicenow`` module whose
    ServiceNowClient raises immediately if instantiated, and patch
    ``httpx.AsyncClient`` / ``httpx.Client`` to raise if called.
    Then verify that route_message completes successfully without
    triggering any of those sentinels.
    """

    def setUp(self):
        # Build a fake servicenow module with a sentinel ServiceNowClient.
        fake_sn = types.ModuleType("app.servicenow")

        class _SentinelClient:
            def __init__(self, *args, **kwargs):
                raise AssertionError(
                    "route_message must NOT instantiate ServiceNowClient"
                )

        fake_sn.ServiceNowClient = _SentinelClient
        self._fake_sn = fake_sn

    def _run_with_fake_servicenow(self, message: str):
        """
        Replace app.servicenow in sys.modules with our sentinel and call
        route_message.  Any attempt to instantiate ServiceNowClient will
        raise AssertionError.
        """
        with patch.dict("sys.modules", {"app.servicenow": self._fake_sn}):
            return route_message(message)

    def test_no_servicenow_instantiation_on_valid(self):
        """Valid incident message must not touch ServiceNowClient."""
        result = self._run_with_fake_servicenow("status of INC0010002")
        self.assertIsNotNone(result)
        self.assertEqual(result.intent, "incident_status")

    def test_no_servicenow_instantiation_on_invalid(self):
        """Rejected message must also not touch ServiceNowClient."""
        result = self._run_with_fake_servicenow(
            "status of INC0010002; DROP TABLE incident"
        )
        self.assertIsNone(result)

    def test_no_network_on_valid(self):
        """
        Patch httpx to raise if any HTTP call is attempted.
        route_message must complete without triggering it.
        """
        mock_httpx = MagicMock()
        mock_httpx.AsyncClient.side_effect = AssertionError(
            "route_message must NOT make network calls"
        )
        mock_httpx.Client.side_effect = AssertionError(
            "route_message must NOT make network calls"
        )
        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = route_message("check INC0010002")
        self.assertIsNotNone(result)
        self.assertEqual(result.incident_number, "INC0010002")

    def test_no_network_on_rejected(self):
        """Rejected message must also complete without any network call."""
        mock_httpx = MagicMock()
        mock_httpx.AsyncClient.side_effect = AssertionError(
            "route_message must NOT make network calls"
        )
        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = route_message("status of INC0010002<script>")
        self.assertIsNone(result)

    def test_route_message_is_synchronous(self):
        """route_message must be a plain function, not a coroutine."""
        import inspect
        self.assertFalse(
            inspect.iscoroutinefunction(route_message),
            "route_message must be synchronous (pure function)",
        )

    def test_route_result_equality(self):
        """RouteResult equality is value-based."""
        a = RouteResult(intent="incident_status", incident_number="INC0010002")
        b = RouteResult(intent="incident_status", incident_number="INC0010002")
        self.assertEqual(a, b)

    def test_route_result_repr(self):
        """RouteResult repr must include both fields."""
        r = RouteResult(intent="incident_status", incident_number="INC0010002")
        self.assertIn("incident_status", repr(r))
        self.assertIn("INC0010002", repr(r))


# ===========================================================================
# Entry point — run via `python tests/test_router.py` as well as pytest
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
