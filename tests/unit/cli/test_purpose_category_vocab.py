"""Sprint 10.6 T12 — Wave-1 vocabulary drift detector for ``PurposeCategory``.

The ``PurposeCategory`` Literal at :mod:`cognic_agentos.cli._governance_vocab`
is the closed-enum vocabulary for the per-credential ``purpose_category``
field declared in pack manifests' ``[credentials.<logical_name>]`` blocks
per ADR-017 + Sprint 10.6 spec §5.1.

Drift on this Literal is **wire-protocol-public**: the value lands on
the manifest's signed-artifact bundle (build-time consumer at
``cli/validators/credentials.py``; T14), on the T18
``sandbox/projection.py`` planner's metadata + the T21
``SandboxBackend.create()`` lifecycle integration emitting
``sandbox.lifecycle.*`` chain rows for projection events, and on SIEM
consumers that filter credential events by purpose. Removal of a
value or rename is a wire-protocol break.

Additive Wave-2 expansion (adding new categories) is safe — the
vocabulary is open to future-sprint growth via this same drift detector
(bump the count guard + add the new value to the canonical set guard).
"""

from __future__ import annotations

from typing import get_args

from cognic_agentos.cli._governance_vocab import PurposeCategory


def test_exactly_eight_values() -> None:
    """Count guard — Wave-1 lock is 8 values."""
    assert len(get_args(PurposeCategory)) == 8


def test_canonical_values() -> None:
    """Set guard — exact Wave-1 vocabulary per Sprint 10.6 spec §5.1."""
    assert set(get_args(PurposeCategory)) == {
        "application_database_read",
        "application_database_write",
        "audit_log_write",
        "external_api_authentication",
        "cryptographic_signing",
        "cryptographic_decryption",
        "service_account_token",
        "monitoring_endpoint_access",
    }
