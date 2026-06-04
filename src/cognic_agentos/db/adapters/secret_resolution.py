"""Async resolution of a config secret field that may carry a ``vault://`` URI.

Wave-1 deploy-safety T2: T1's ``core/config.py`` guards require the 4 service
secrets to be ``vault://`` URIs (or ``None``) in strict profiles; this resolver
turns a ``vault://`` URI into the real secret at adapter-construction time by
reading the Vault dict field ``"key"`` (matching the ``_VAULT_KEY_FIELD = "key"``
precedent at ``compliance/iso42001/signing.py:30``). Fails loud on every
malformed payload — a bank secret must be a real, non-empty string.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, NoReturn

if TYPE_CHECKING:
    from cognic_agentos.db.adapters.protocols import SecretAdapter

_VAULT_PREFIX = "vault://"
_SECRET_VALUE_KEY = "key"  # matches compliance/iso42001/signing.py:_VAULT_KEY_FIELD


class SecretFieldResolutionError(RuntimeError):
    """Raised (reason-prefix ``secret_field_resolution_failed``) when a ``vault://``
    field cannot be resolved: Vault unreachable, path missing, payload not a dict,
    no ``"key"`` field, or a non-string / empty ``"key"`` value."""


def _fail(field_name: str, path: str, why: str) -> NoReturn:
    raise SecretFieldResolutionError(
        f"secret_field_resolution_failed: {field_name} (path={path!r}): {why}"
    )


async def resolve_secret_field(
    value: str | None,
    *,
    secret_adapter: SecretAdapter,
    field_name: str,
) -> str | None:
    """Return ``value`` unchanged if it is ``None`` or a plain (non-``vault://``)
    string; otherwise read ``secret_adapter.read(<path>)["key"]`` and return it.
    Fail-loud (``SecretFieldResolutionError``) on every malformed shape."""
    if value is None:
        return None
    if not value.startswith(_VAULT_PREFIX):
        return value
    path = value[len(_VAULT_PREFIX) :]
    try:
        payload = await secret_adapter.read(path)
    except Exception as exc:  # fail-loud: wrap any read failure into the closed reason
        raise SecretFieldResolutionError(
            f"secret_field_resolution_failed: {field_name} (path={path!r}): "
            f"read failed: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        _fail(field_name, path, f"Vault payload is not a dict (got {type(payload).__name__})")
    if _SECRET_VALUE_KEY not in payload:
        _fail(field_name, path, f"Vault secret missing the {_SECRET_VALUE_KEY!r} field")
    resolved = payload[_SECRET_VALUE_KEY]
    if not isinstance(resolved, str) or not resolved:
        _fail(
            field_name,
            path,
            f"{_SECRET_VALUE_KEY!r} must be a non-empty str (got {type(resolved).__name__})",
        )
    return resolved
