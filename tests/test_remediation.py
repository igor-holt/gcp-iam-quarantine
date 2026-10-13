"""Tests for remediation step isolation.

``google-cloud-iam`` is not a local test dependency, so a minimal fake is
injected into ``sys.modules`` before importing :mod:`remediation`. The point
of these tests is the partial-failure contract: a failure in key revocation
must never prevent the authoritative account-disable step.
"""

import sys
import types as pytypes

import pytest

import remediation

SA = "workload-sa@example-proj.iam.gserviceaccount.com"


class FakeKey:
    def __init__(self, name, disabled=False):
        self.name = name
        self.disabled = disabled


class FakeClient:
    def __init__(self, keys=(), list_error=None, disable_error=None):
        self._keys = list(keys)
        self._list_error = list_error
        self._disable_error = disable_error
        self.disabled_keys = []
        self.account_disabled = False
        self.disable_request_name = None

    def list_service_account_keys(self, request=None):
        if self._list_error:
            raise self._list_error
        return pytypes.SimpleNamespace(keys=self._keys)

    def disable_service_account_key(self, request=None):
        self.disabled_keys.append(request.name)

    def disable_service_account(self, request=None):
        self.disable_request_name = request.name
        if self._disable_error:
            raise self._disable_error
        self.account_disabled = True


@pytest.fixture
def fake_iam(monkeypatch):
    """Install a fake google.cloud.iam_admin_v1 and return a setter."""

    state = {"client": FakeClient()}

    client_cls = lambda: state["client"]

    iam_module = pytypes.ModuleType("google.cloud.iam_admin_v1")
    iam_module.IAMClient = client_cls

    request_types = pytypes.ModuleType("google.cloud.iam_admin_v1.types")

    class _ListRequest:
        KeyType = pytypes.SimpleNamespace(USER_MANAGED="USER_MANAGED")

        def __init__(self, name, key_types=None):
            self.name = name
            self.key_types = key_types

    request_types.ListServiceAccountKeysRequest = _ListRequest
    request_types.DisableServiceAccountKeyRequest = pytypes.SimpleNamespace
    request_types.DisableServiceAccountRequest = pytypes.SimpleNamespace

    monkeypatch.setitem(sys.modules, "google", pytypes.ModuleType("google"))
    monkeypatch.setitem(sys.modules, "google.cloud", pytypes.ModuleType("google.cloud"))
    monkeypatch.setitem(sys.modules, "google.cloud.iam_admin_v1", iam_module)
    monkeypatch.setitem(sys.modules, "google.cloud.iam_admin_v1.types", request_types)

    def use(client):
        state["client"] = client
        return client

    use.default = lambda: state["client"]
    return use


class TestQuarantine:
    def test_happy_path_revokes_keys_then_disables(self, fake_iam):
        client = fake_iam(
            FakeClient(keys=[FakeKey("k1"), FakeKey("k2"), FakeKey("k3", disabled=True)])
        )
        result = remediation.quarantine_service_account("example-proj", SA)

        assert result.startswith("QUARANTINED")
        assert client.account_disabled is True
        assert len(client.disabled_keys) == 2  # already-disabled key skipped
        assert "2 user-managed key(s) revoked" in result
        assert "account disabled" in result

    def test_disable_attempted_even_when_key_listing_fails(self, fake_iam):
        # The account disable is the strong control; a listing failure must
        # not skip it.
        client = fake_iam(FakeClient(list_error=RuntimeError("boom")))
        result = remediation.quarantine_service_account("example-proj", SA)

        assert client.account_disabled is True
        assert "KEY REVOCATION ERROR" in result
        assert result.startswith("QUARANTINED")

    def test_partial_state_when_disable_fails_after_revoke(self, fake_iam):
        client = fake_iam(
            FakeClient(keys=[FakeKey("k1")], disable_error=RuntimeError("denied"))
        )
        result = remediation.quarantine_service_account("example-proj", SA)

        assert result.startswith("PARTIAL")
        assert client.account_disabled is False
        assert len(client.disabled_keys) == 1
        assert "ACCOUNT DISABLE ERROR" in result

    def test_total_failure_when_nothing_worked(self, fake_iam):
        fake_iam(
            FakeClient(
                keys=[FakeKey("k1")],
                list_error=RuntimeError("list"),
                disable_error=RuntimeError("disable"),
            )
        )
        result = remediation.quarantine_service_account("example-proj", SA)

        assert result.startswith("FAILED")

    def test_uses_project_scoped_resource_name(self, fake_iam):
        # The API is always called with a full resource path, never a bare
        # email, so an email containing "/" or unusual characters cannot
        # redirect the call to a different project.
        client = fake_iam(FakeClient())
        remediation.quarantine_service_account("example-proj", SA)

        assert client.disable_request_name == (
            "projects/example-proj/serviceAccounts/" + SA
        )