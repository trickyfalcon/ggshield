import hashlib
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml
from pygitguardian.models import TokenScope

from ggshield.core.config.utils import load_yaml_dict, save_yaml_dict
from ggshield.core.dirs import get_cache_dir
from ggshield.core.errors import UnexpectedError


logger = logging.getLogger(__name__)

# How long a successful auth check (metadata + token scopes) stays valid.
# Short enough that revoked tokens and scope changes propagate quickly;
# long enough that a burst of scans (e.g. IDE on-save) shares one check.
TTL_SECONDS = 300


def _cache_file() -> Path:
    # Resolved lazily so GG_CACHE_DIR overrides (tests, sandboxed envs) are honored.
    return get_cache_dir() / "auth_check.yaml"


@dataclass
class CachedAuthCheck:
    # The API key has been verified against /v1/metadata and is usable.
    metadata_verified: bool
    # If not None, these are the scopes fetched from /v1/api_tokens/self.
    # None means we haven't fetched scopes yet (e.g. from an auth-login flow
    # where no specific scopes were required).
    scopes: Optional[set[TokenScope]]
    # X-Secrets-Engine-Version header from the last metadata response.
    # Callers (notably the docker scan) need this on the client and would
    # otherwise hit an AssertionError when the cache skips /v1/metadata.
    secrets_engine_version: Optional[str]


def _key_hash(instance_url: str, api_key: str) -> str:
    return hashlib.sha256(f"{instance_url}\0{api_key}".encode("utf-8")).hexdigest()[:16]


def load(instance_url: str, api_key: str) -> Optional[CachedAuthCheck]:
    """Return the cached auth check for this (instance, key) pair, or None on miss."""
    try:
        data = load_yaml_dict(_cache_file())
    except (OSError, ValueError, yaml.YAMLError) as e:
        logger.warning("Could not load auth check cache: %s", repr(e))
        return None

    if not data:
        return None
    if data.get("key_hash") != _key_hash(instance_url, api_key):
        return None
    if data.get("expires_at", 0) < time.time():
        return None

    raw_scopes = data.get("scopes")
    scopes: Optional[set[TokenScope]]
    if raw_scopes is None:
        scopes = None
    else:
        scopes = set()
        for scope_str in raw_scopes:
            try:
                scopes.add(TokenScope(scope_str))
            except ValueError:
                logger.debug("Ignoring unknown cached scope: '%s'", scope_str)

    raw_version = data.get("secrets_engine_version")
    secrets_engine_version = raw_version if isinstance(raw_version, str) else None

    return CachedAuthCheck(
        metadata_verified=True,
        scopes=scopes,
        secrets_engine_version=secrets_engine_version,
    )


def store(
    instance_url: str,
    api_key: str,
    scopes: Optional[set[TokenScope]],
    secrets_engine_version: Optional[str],
) -> None:
    """Record a successful auth check.

    Pass scopes=None if token scopes were not fetched (only metadata was checked).
    """
    try:
        save_yaml_dict(
            {
                "key_hash": _key_hash(instance_url, api_key),
                "scopes": (None if scopes is None else sorted(s.value for s in scopes)),
                "secrets_engine_version": secrets_engine_version,
                "expires_at": int(time.time()) + TTL_SECONDS,
            },
            _cache_file(),
            restricted=True,
        )
    except (OSError, UnexpectedError) as e:
        logger.warning("Could not save auth check cache: %s", repr(e))


def invalidate() -> None:
    """Drop the cached auth check, typically after a 401 from any API call."""
    try:
        _cache_file().unlink(missing_ok=True)
    except OSError as e:
        logger.warning("Could not invalidate auth check cache: %s", repr(e))
