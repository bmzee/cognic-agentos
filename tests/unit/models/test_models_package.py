"""Sprint 9.5 A5 — public-API re-exports for ``cognic_agentos.models``.

The package ``__init__.py`` exposes a flat surface: every name listed
here is importable as ``from cognic_agentos.models import <name>`` and
is identity-equal to its source-module definition. Drift between the
expected re-export set and ``models.__all__`` is the most-likely
future regression class (someone adds a new public symbol to one of
the source modules but forgets the package re-export).
"""

from __future__ import annotations

import cognic_agentos.models as models_pkg
from cognic_agentos.models import registry as registry_mod
from cognic_agentos.models import storage as storage_mod
from cognic_agentos.models import trust as trust_mod

#: Canonical re-export set: name → source module. Owns the public
#: API surface of the ``cognic_agentos.models`` package.
_EXPECTED_REEXPORTS: dict[str, object] = {
    # registry.py
    "MODEL_LIFECYCLE_ISO_CONTROLS": registry_mod,
    "ModelKind": registry_mod,
    "ModelLifecycleRefusalReason": registry_mod,
    "ModelLifecycleRefused": registry_mod,
    "ModelLifecycleState": registry_mod,
    "ModelTransition": registry_mod,
    "validate_transition": registry_mod,
    # storage.py
    "ModelNotFound": storage_mod,
    "ModelRecord": storage_mod,
    "ModelRecordStore": storage_mod,
    # trust.py
    "ModelSignatureVerificationError": trust_mod,
    "ModelTrustGate": trust_mod,
    "sigstore_bundle_digest": trust_mod,
}


def test_package_reexports_are_identity_equal_to_source() -> None:
    """Each re-export resolves to the SAME object as in the source
    module — no accidental rebinding via shadowed assignment.
    """
    for name, source_mod in _EXPECTED_REEXPORTS.items():
        assert hasattr(models_pkg, name), f"models package missing re-export: {name}"
        assert getattr(models_pkg, name) is getattr(source_mod, name), (
            f"re-export {name!r} identity-mismatch with source module"
        )


def test_package_all_lists_every_reexport() -> None:
    """Every re-export above appears in ``models/__init__.py``'s
    ``__all__``. Drift here means a name is importable but not in the
    public-API surface (confusing tooling + ``import *`` consumers).
    """
    missing = set(_EXPECTED_REEXPORTS) - set(models_pkg.__all__)
    assert missing == set(), f"models __all__ missing expected re-exports: {sorted(missing)}"


def test_package_all_has_exactly_the_expected_reexports() -> None:
    """``__all__`` is the EXACT set of expected re-exports — no extra
    names, no missing names. Catches a future symbol that gets added
    to ``__all__`` without an accompanying entry in
    ``_EXPECTED_REEXPORTS`` (which would mean the source-module
    classification was forgotten).
    """
    assert set(models_pkg.__all__) == set(_EXPECTED_REEXPORTS), (
        f"models __all__ diverges from expected re-exports:\n"
        f"  in __all__ only: {set(models_pkg.__all__) - set(_EXPECTED_REEXPORTS)}\n"
        f"  expected only:   {set(_EXPECTED_REEXPORTS) - set(models_pkg.__all__)}"
    )


def test_package_all_does_not_leak_private_names() -> None:
    """``__all__`` MUST NOT include any leading-underscore names —
    those are implementation detail (e.g. ``_models`` Table,
    ``_record_to_row`` helper).
    """
    private = [n for n in models_pkg.__all__ if n.startswith("_")]
    assert private == [], f"models __all__ leaks private names: {private}"


def test_package_dunder_all_is_sorted_or_sortable() -> None:
    """``__all__`` is a list of strings — pin the shape so a future
    regression that swaps to a tuple/set is caught (tools + IDE
    introspection rely on it being iterable + indexable in declaration
    order).
    """
    assert isinstance(models_pkg.__all__, list)
    assert all(isinstance(n, str) for n in models_pkg.__all__)
