"""Tests for the security-critical policy decisions.

``policy`` is stdlib-only by design, so this whole suite runs with no
dependencies installed.
"""

import base64

import pytest

import policy

PROJECT = "example-proj"
DOMAIN = "@example-proj.iam.gserviceaccount.com"

PROTECTED = {
    "job-runner@example-proj.iam.gserviceaccount.com",
    "scheduler-invoker@example-proj.iam.gserviceaccount.com",
    "bq-query-runner@example-proj.iam.gserviceaccount.com",
    "dispatcher@example-proj.iam.gserviceaccount.com",
}
MONITORED = {"workload-sa@example-proj.iam.gserviceaccount.com"}


class TestParseSaCsv:
    def test_strips_and_lowercases(self):
        assert policy.parse_sa_csv(" A@B.com , c@d.com ") == {"a@b.com", "c@d.com"}

    def test_none_and_empty(self):
        assert policy.parse_sa_csv(None) == set()
        assert policy.parse_sa_csv("") == set()
        assert policy.parse_sa_csv(",,,") == set()


class TestEligibility:
    def test_protected_account_is_never_quarantined(self):
        # A protected SA that is ALSO monitored must lose. Self-protection
        # outranks the allowlist.
        both = MONITORED | PROTECTED
        ok, reason = policy.is_eligible_for_quarantine(
            "dispatcher@example-proj.iam.gserviceaccount.com", PROJECT, PROTECTED, both
        )
        assert ok is False
        assert "BYPASSED" in reason

    def test_case_insensitive_protection(self):
        ok, reason = policy.is_eligible_for_quarantine(
            "Dispatcher@Example-Proj.iam.gserviceaccount.com", PROJECT, PROTECTED, MONITORED
        )
        assert ok is False
        assert "BYPASSED" in reason

    def test_google_managed_service_agent_rejected(self):
        ok, reason = policy.is_eligible_for_quarantine(
            "service-1234@gcp-sa-pubsub.iam.gserviceaccount.com",
            PROJECT,
            PROTECTED,
            {"service-1234@gcp-sa-pubsub.iam.gserviceaccount.com"},
        )
        assert ok is False
        assert "Google-managed" in reason

    def test_external_human_rejected(self):
        ok, reason = policy.is_eligible_for_quarantine(
            "attacker@evil.com", PROJECT, PROTECTED, {"attacker@evil.com"}
        )
        assert ok is False
        assert "external user" in reason

    def test_cross_project_sa_rejected(self):
        ok, _ = policy.is_eligible_for_quarantine(
            "sa@other-project.iam.gserviceaccount.com",
            PROJECT,
            PROTECTED,
            {"sa@other-project.iam.gserviceaccount.com"},
        )
        assert ok is False

    def test_empty_allowlist_means_never_remediate(self):
        ok, reason = policy.is_eligible_for_quarantine(
            "workload-sa@example-proj.iam.gserviceaccount.com", PROJECT, PROTECTED, set()
        )
        assert ok is False
        assert "allowlist" in reason

    @pytest.mark.parametrize("bad", ["", None, "no-at-sign", "@", "unauthenticated"])
    def test_malformed_principal_rejected(self, bad):
        ok, reason = policy.is_eligible_for_quarantine(bad, PROJECT, PROTECTED, MONITORED)
        assert ok is False
        assert "not a valid email" in reason

    def test_monitored_account_is_eligible(self):
        ok, reason = policy.is_eligible_for_quarantine(
            "workload-sa@example-proj.iam.gserviceaccount.com", PROJECT, PROTECTED, MONITORED
        )
        assert (ok, reason) == (True, "ELIGIBLE")


class TestConfusedDeputyRegression:
    """The exploit that motivated the allowlist."""

    def test_forged_caller_cannot_expand_blast_radius(self):
        # An attacker with topic publish rights forges a payload naming an
        # arbitrary in-project SA. Because that SA is not on the allowlist,
        # no disable occurs. This is the regression that matters.
        forged = "production-db-sa@example-proj.iam.gserviceaccount.com"
        assert forged not in MONITORED

        ok, reason = policy.is_eligible_for_quarantine(
            forged, PROJECT, PROTECTED, MONITORED
        )
        assert ok is False
        assert "allowlist" in reason


class TestSelfProtection:
    def test_dispatcher_on_allowlist_is_fatal(self):
        # Regression: a config error must stop the function before it can
        # disable its own service account mid-incident.
        dispatcher = "dispatcher@example-proj.iam.gserviceaccount.com"
        with pytest.raises(RuntimeError, match="Refusing to start"):
            policy.assert_dispatcher_not_monitored(
                dispatcher, MONITORED | PROTECTED, PROTECTED
            )

    def test_dispatcher_missing_from_protected_list_is_fatal(self):
        # Env var failed to bind -> protection would silently fail open.
        with pytest.raises(RuntimeError, match="PROTECTED_SERVICE_ACCOUNTS"):
            policy.assert_dispatcher_not_monitored(
                "dispatcher@example-proj.iam.gserviceaccount.com", set(), set()
            )

    def test_healthy_config_passes(self):
        policy.assert_dispatcher_not_monitored(
            "dispatcher@example-proj.iam.gserviceaccount.com", MONITORED, PROTECTED
        )

    def test_empty_allowlist_is_valid_alert_only_mode(self):
        policy.assert_dispatcher_not_monitored(
            "dispatcher@example-proj.iam.gserviceaccount.com", set(), PROTECTED
        )


class TestDecodePubsubData:
    def _event(self, data):
        return {"message": {"data": base64.b64encode(data).decode()}}

    def test_valid_payload(self):
        record, reason = policy.decode_pubsub_data(self._event(b'{"a": 1}'))
        assert record == {"a": 1}
        assert reason == ""

    @pytest.mark.parametrize(
        "payload",
        [b'["a", "list"]', b'"just a string"', b"123", b"null", b"true"],
        ids=["list", "string", "number", "null", "bool"],
    )
    def test_non_object_json_is_poison_not_crash(self, payload):
        record, reason = policy.decode_pubsub_data(self._event(payload))
        assert record is None
        assert reason

    def test_malformed_json_is_poison(self):
        record, reason = policy.decode_pubsub_data(self._event(b"{not json"))
        assert record is None
        assert "JSON" in reason

    def test_bad_base64_is_poison(self):
        record, reason = policy.decode_pubsub_data({"message": {"data": "!!!not-b64!!!"}})
        assert record is None

    @pytest.mark.parametrize(
        "data", [{}, {"nope": 1}, "a string", None]
    )
    def test_malformed_envelope_is_poison(self, data):
        record, reason = policy.decode_pubsub_data(data)
        assert record is None


class TestSlackEscape:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("<https://evil.example|click>", "&lt;https://evil.example|click&gt;"),
            ("a & b", "a &amp; b"),
            ("```injected```", "'''injected'''"),
            ("&<>", "&amp;&lt;&gt;"),
        ],
    )
    def test_escapes(self, raw, expected):
        assert policy.slack_escape(raw) == expected

    def test_ampersand_is_not_double_escaped(self):
        # Order matters: & is escaped first, so a literal "&lt;" the attacker
        # supplied becomes "&amp;lt;" rather than being re-interpreted.
        assert policy.slack_escape("&lt;") == "&amp;lt;"