import time
from unittest.mock import Mock

import click
import pytest
from pygitguardian import GGClient
from pygitguardian.models import APITokensResponse, Detail, TokenScope

from ggshield.core import auth_check_cache
from ggshield.core.client import check_client_api_key
from ggshield.core.errors import handle_api_error


API_TOKENS_RESPONSE = APITokensResponse.from_dict(
    {
        "id": "5ddaad0c-5a0c-4674-beb5-1cd198d13360",
        "name": "test-name",
        "workspace_id": 1,
        "type": "personal_access_token",
        "status": "active",
        "created_at": "2023-01-01T00:00:00Z",
        "scopes": [TokenScope.SCAN_CREATE_INCIDENTS.value],
    }
)


def _make_client_mock() -> Mock:
    client_mock = Mock(spec=GGClient)
    client_mock.base_uri = "http://localhost"
    client_mock.api_key = "test-api-key"
    client_mock.secrets_engine_version = "2.0.0"
    client_mock.read_metadata.return_value = None  # Success
    client_mock.api_tokens.return_value = API_TOKENS_RESPONSE
    return client_mock


def test_cache_skips_metadata_and_api_tokens_on_hit():
    """
    GIVEN a prior successful check populated the cache
    WHEN check_client_api_key is called again with the same scopes
    THEN neither read_metadata nor api_tokens is called
    """
    client_mock = _make_client_mock()

    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})
    client_mock.read_metadata.reset_mock()
    client_mock.api_tokens.reset_mock()

    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})

    client_mock.read_metadata.assert_not_called()
    client_mock.api_tokens.assert_not_called()


def test_cache_hit_restores_secrets_engine_version_on_client():
    """
    GIVEN a prior check populated the cache while the /v1/metadata response
          set client.secrets_engine_version
    WHEN a subsequent check hits the cache and skips /v1/metadata
    THEN the cached version is copied back onto the client so downstream
         code (notably the docker scan) does not see None
    """
    client_mock = _make_client_mock()
    client_mock.secrets_engine_version = "2.0.0"
    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})

    # Simulate a fresh subprocess: a new client with the engine version reset.
    fresh_client = _make_client_mock()
    fresh_client.secrets_engine_version = None

    check_client_api_key(fresh_client, {TokenScope.SCAN_CREATE_INCIDENTS})

    fresh_client.read_metadata.assert_not_called()
    fresh_client.api_tokens.assert_not_called()
    assert fresh_client.secrets_engine_version == "2.0.0"


def test_cache_miss_on_different_api_key():
    """
    GIVEN the cache was populated for one api_key
    WHEN the same instance is checked with a different api_key
    THEN the cache does not short-circuit
    """
    client_mock = _make_client_mock()
    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})

    client_mock.api_key = "different-api-key"
    client_mock.read_metadata.reset_mock()
    client_mock.api_tokens.reset_mock()

    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})

    client_mock.read_metadata.assert_called_once()
    client_mock.api_tokens.assert_called_once()


def test_cache_hit_for_metadata_still_fetches_scopes_when_needed():
    """
    GIVEN a cache entry seeded without scopes (e.g. from an auth-login flow)
    WHEN check_client_api_key runs with required scopes
    THEN read_metadata is skipped but api_tokens is still fetched
    """
    client_mock = _make_client_mock()
    check_client_api_key(client_mock, set())  # caches with scopes=None
    client_mock.read_metadata.reset_mock()
    client_mock.api_tokens.reset_mock()

    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})

    client_mock.read_metadata.assert_not_called()
    client_mock.api_tokens.assert_called_once()


def test_expired_cache_is_ignored(monkeypatch):
    """
    GIVEN the cache TTL has elapsed
    WHEN check_client_api_key runs
    THEN both calls are made again
    """
    client_mock = _make_client_mock()
    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})

    later = time.time() + auth_check_cache.TTL_SECONDS + 1
    monkeypatch.setattr(auth_check_cache.time, "time", lambda: later)
    client_mock.read_metadata.reset_mock()
    client_mock.api_tokens.reset_mock()

    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})

    client_mock.read_metadata.assert_called_once()
    client_mock.api_tokens.assert_called_once()


def test_invalidate_removes_cache_entry():
    client_mock = _make_client_mock()
    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})
    assert auth_check_cache.load("http://localhost", "test-api-key") is not None

    auth_check_cache.invalidate()

    assert auth_check_cache.load("http://localhost", "test-api-key") is None


def test_handle_api_error_401_invalidates_cache():
    """
    GIVEN the cache was populated by a successful auth check
    WHEN any later API call surfaces a 401 through handle_api_error
    THEN the cache entry is dropped so the next check re-verifies the key
    """
    client_mock = _make_client_mock()
    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})
    assert auth_check_cache.load("http://localhost", "test-api-key") is not None

    with pytest.raises(click.UsageError):
        handle_api_error(Detail("Invalid API key", 401))

    assert auth_check_cache.load("http://localhost", "test-api-key") is None


def test_load_returns_none_on_corrupt_yaml():
    """
    GIVEN the cache file contains bytes that are not valid YAML
    WHEN load is called
    THEN it returns None instead of propagating the parse error
    """
    cache_file = auth_check_cache._cache_file()
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text("not: valid: yaml: [")

    assert auth_check_cache.load("http://localhost", "test-api-key") is None


def test_load_ignores_unknown_cached_scope(monkeypatch):
    """
    GIVEN a cache entry persisted an API scope the current ggshield build does
          not know about (forward compatibility with a newer API)
    WHEN load decodes it
    THEN the unknown scope is dropped and the rest of the entry is returned
    """
    auth_check_cache.store(
        "http://localhost", "test-api-key", {TokenScope.SCAN_CREATE_INCIDENTS}, "2.0.0"
    )
    # Inject an extra scope the enum does not know about by rewriting the file.
    from ggshield.core.config.utils import load_yaml_dict, save_yaml_dict

    data = load_yaml_dict(auth_check_cache._cache_file())
    assert data is not None
    data["scopes"] = sorted(data["scopes"] + ["scan:future_scope_not_in_enum"])
    save_yaml_dict(data, auth_check_cache._cache_file())

    cached = auth_check_cache.load("http://localhost", "test-api-key")

    assert cached is not None
    assert cached.scopes == {TokenScope.SCAN_CREATE_INCIDENTS}


def test_store_failure_is_swallowed(monkeypatch, caplog):
    """
    GIVEN saving the cache file raises (e.g. disk full, read-only FS)
    WHEN store is called
    THEN the error is logged and does not propagate to the caller
    """

    def _boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(auth_check_cache, "save_yaml_dict", _boom)

    auth_check_cache.store("http://localhost", "test-api-key", None, None)

    assert any("Could not save auth check cache" in r.message for r in caplog.records)


def test_invalidate_failure_is_swallowed(monkeypatch, caplog):
    """
    GIVEN unlinking the cache file raises (e.g. permission error)
    WHEN invalidate is called
    THEN the error is logged and does not propagate
    """

    def _boom(*args, **kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(auth_check_cache.Path, "unlink", _boom)

    auth_check_cache.invalidate()

    assert any(
        "Could not invalidate auth check cache" in r.message for r in caplog.records
    )
