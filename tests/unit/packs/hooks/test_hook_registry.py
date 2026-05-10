"""Sprint-7A2 T6 — :mod:`cognic_agentos.packs.hooks.registry` regression suite.

Pins the public ``HookRegistry`` admission contract per Doctrine Lock D:

* **Single-writer at admission.** ``register_pack(...)`` mutates the indexed
  state; ``snapshot()`` and ``get_phase_hooks(...)`` are read-only and
  return immutable views.
* **Verified-only registration.** A ``VerifiedHookPack`` MUST carry a
  non-empty ``signature_digest``; absent digest refuses fail-closed with
  closed-enum reason ``pack_not_verified``.
* **Cross-pack duplicate-hook-id refuses.** Two distributions registering
  the same ``(phase, hook_id)`` is the plugin-trust shadow surface;
  refused fail-closed with ``duplicate_hook_id_cross_pack``.
* **Stale-digest refuses.** Same ``(distribution_name, distribution_version)``
  re-registered with a different digest is refused fail-closed with
  ``stale_digest`` (idempotent re-registration with the SAME digest is a
  no-op).
* **Defense-in-depth at construction.** ``HookDeclaration.__post_init__``
  refuses (``ValueError``) on empty ``hook_id``, non-positive timeout,
  timeout above the Settings-derived ceiling, ``phase_class_mismatch``
  (``ordering_class`` doesn't belong to ``phase`` per
  ``HOOK_ORDERING_CLASS_PHASE``), and ``fail_open`` policy without
  ``fail_open_exception``. ``VerifiedHookPack.__post_init__`` refuses on
  duplicate ``hook_id`` within a single pack's declarations.
* **Deterministic phase order.** ``get_phase_hooks(phase)`` returns a
  tuple sorted by ``HOOK_ORDERING_RANK[ordering_class]`` ascending, ties
  broken by ``hook_id`` alphabetic — pinned because the dispatcher (T7)
  relies on this ordering being a function of the manifest, not of
  registration sequence.
* **Deferred-load callable.** The ``callable_loader`` is never invoked by
  ``register_pack`` itself; pack code is loaded only at dispatch time
  per the pre-import-trust invariant inherited from Sprint-4
  ``protocol/plugin_registry.py``.

Critical-controls T12 promotion target: ``packs/hooks/registry.py`` joins
the gate at sprint closeout, requiring 95% line / 90% branch coverage.
This suite is the floor.
"""

from __future__ import annotations

import dataclasses
from types import MappingProxyType
from typing import Any

import pytest

from cognic_agentos.cli._governance_vocab import (
    HOOK_ORDERING_CLASS_PHASE,
    HOOK_ORDERING_RANK,
)
from cognic_agentos.packs.hooks.registry import (
    HookDeclaration,
    HookEntry,
    HookRegistry,
    HookRegistryRefusal,
    HookRegistryRefusalReason,
    VerifiedHookPack,
)

# ---------------------------------------------------------------------------
# Test fixtures — minimal verified-pack + declaration builders
# ---------------------------------------------------------------------------


def _stub_loader() -> type:
    """Lazy callable loader; never invoked at registration per the
    deferred-load invariant. Returns ``object`` so a hypothetical caller
    that DID invoke it would not raise — the test doing so would fail
    a separate "not called at registration" assertion."""
    return object


def _make_declaration(
    *,
    hook_id: str = "redact_pii",
    phase: str = "dlp_pre",
    ordering_class: str = "input_redaction",
    timeout_seconds: float = 1.0,
    fail_policy: str = "fail_closed",
    fail_open_exception: str | None = None,
    callable_loader: Any = None,
) -> HookDeclaration:
    return HookDeclaration(
        hook_id=hook_id,
        phase=phase,  # type: ignore[arg-type]
        ordering_class=ordering_class,  # type: ignore[arg-type]
        timeout_seconds=timeout_seconds,
        fail_policy=fail_policy,  # type: ignore[arg-type]
        fail_open_exception=fail_open_exception,
        callable_loader=callable_loader or _stub_loader,
    )


def _make_pack(
    *,
    distribution_name: str = "cognic-hook-redact-pii",
    distribution_version: str = "0.1.0",
    signature_digest: str = "sha256:" + "a" * 64,
    declarations: tuple[HookDeclaration, ...] | None = None,
) -> VerifiedHookPack:
    if declarations is None:
        declarations = (_make_declaration(),)
    return VerifiedHookPack(
        distribution_name=distribution_name,
        distribution_version=distribution_version,
        signature_digest=signature_digest,
        declarations=declarations,
    )


# ---------------------------------------------------------------------------
# HookDeclaration construction-time invariants
# ---------------------------------------------------------------------------


class TestHookDeclarationConstruction:
    """``HookDeclaration.__post_init__`` raises ``ValueError`` for any
    field that violates the declared invariants. These are
    defense-in-depth: the validator (T5) catches the same conditions at
    manifest-load time, but a malicious pack bypassing ``agentos
    validate`` must still fail at the registry boundary."""

    def test_empty_hook_id_refuses(self) -> None:
        with pytest.raises(ValueError, match=r"hook_id"):
            _make_declaration(hook_id="")

    def test_whitespace_only_hook_id_refuses(self) -> None:
        with pytest.raises(ValueError, match=r"hook_id"):
            _make_declaration(hook_id="   ")

    def test_zero_timeout_refuses(self) -> None:
        with pytest.raises(ValueError, match=r"timeout_seconds"):
            _make_declaration(timeout_seconds=0.0)

    def test_negative_timeout_refuses(self) -> None:
        with pytest.raises(ValueError, match=r"timeout_seconds"):
            _make_declaration(timeout_seconds=-1.0)

    def test_phase_class_mismatch_refuses(self) -> None:
        # ``input_redaction`` belongs to ``dlp_pre``; declaring it under
        # ``dlp_post`` is a phase/class mismatch (Doctrine: every
        # ``HookOrderingClass`` belongs to exactly one ``HookPhase``).
        with pytest.raises(ValueError, match=r"phase.*ordering_class|class.*phase"):
            _make_declaration(phase="dlp_post", ordering_class="input_redaction")

    def test_fail_open_without_exception_refuses(self) -> None:
        # ``fail_open`` policy is opt-in and requires the manifest to
        # nominate the exception class that triggers it. Absent
        # exception → fail-closed default; refuse the misconfiguration.
        with pytest.raises(ValueError, match=r"fail_open_exception"):
            _make_declaration(fail_policy="fail_open", fail_open_exception=None)

    def test_fail_closed_with_exception_is_allowed(self) -> None:
        # The reverse is allowed — ``fail_closed`` with an annotated
        # exception is a no-op marker (the dispatcher ignores
        # ``fail_open_exception`` when ``fail_policy`` is fail_closed).
        decl = _make_declaration(fail_policy="fail_closed", fail_open_exception="RecoverableError")
        assert decl.fail_policy == "fail_closed"

    def test_valid_declaration_constructs(self) -> None:
        decl = _make_declaration()
        assert decl.hook_id == "redact_pii"
        assert decl.phase == "dlp_pre"
        assert decl.ordering_class == "input_redaction"
        assert decl.timeout_seconds == 1.0
        assert decl.fail_policy == "fail_closed"
        # ``ordering_rank`` is cached at construction from
        # ``HOOK_ORDERING_RANK`` for dispatcher-side fast lookup.
        assert decl.ordering_rank == HOOK_ORDERING_RANK["input_redaction"]


class TestHookDeclarationFrozenAndSlotted:
    """Production-grade rule: HookDeclaration is immutable + slotted so
    rogue runtime code cannot mutate a declaration after admission and
    redirect the dispatcher's iteration."""

    def test_declaration_is_frozen(self) -> None:
        decl = _make_declaration()
        with pytest.raises(dataclasses.FrozenInstanceError):
            decl.hook_id = "stolen"  # type: ignore[misc]

    def test_declaration_is_slotted(self) -> None:
        # Frozen+slotted dataclass: assigning a non-slot attribute
        # raises FrozenInstanceError (a subclass of AttributeError) on
        # frozen-check first; some Python versions surface the slot
        # miss as TypeError before frozen-check. Either signals the
        # invariant ("rogue runtime cannot inject fields").
        decl = _make_declaration()
        with pytest.raises((AttributeError, TypeError)):
            decl.injected_field = "bad"  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# VerifiedHookPack construction-time invariants
# ---------------------------------------------------------------------------


class TestVerifiedHookPackConstruction:
    def test_empty_signature_digest_is_allowed_at_construction(self) -> None:
        # Signature-digest absence is a registry-level refusal
        # (``pack_not_verified``), not a construction-time refusal —
        # callers can construct a pack value object even if signing
        # didn't run, but it cannot be admitted to the registry.
        pack = _make_pack(signature_digest="")
        assert pack.signature_digest == ""

    def test_duplicate_hook_id_within_one_pack_refuses(self) -> None:
        d1 = _make_declaration(hook_id="redact_pii", phase="dlp_pre")
        d2 = _make_declaration(hook_id="redact_pii", phase="dlp_pre")
        with pytest.raises(ValueError, match=r"duplicate.*hook_id|hook_id.*duplicate"):
            _make_pack(declarations=(d1, d2))

    def test_same_hook_id_different_phases_is_allowed_within_one_pack(self) -> None:
        # The same logical hook can run at both ``dlp_pre`` and
        # ``dlp_post`` — different keys; not a duplicate.
        d1 = _make_declaration(
            hook_id="redact_pii", phase="dlp_pre", ordering_class="input_redaction"
        )
        d2 = _make_declaration(
            hook_id="redact_pii", phase="dlp_post", ordering_class="output_redaction"
        )
        pack = _make_pack(declarations=(d1, d2))
        assert len(pack.declarations) == 2

    def test_pack_is_frozen(self) -> None:
        pack = _make_pack()
        with pytest.raises(dataclasses.FrozenInstanceError):
            pack.distribution_name = "stolen"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# HookRegistry happy path
# ---------------------------------------------------------------------------


class TestHookRegistryHappyPath:
    def test_register_one_pack_one_declaration(self) -> None:
        registry = HookRegistry(max_timeout_seconds=30.0)
        pack = _make_pack()
        entries = registry.register_pack(pack)
        assert len(entries) == 1
        assert entries[0].hook_id == "redact_pii"
        assert entries[0].phase == "dlp_pre"
        assert entries[0].pack_distribution_name == "cognic-hook-redact-pii"
        assert entries[0].signature_digest == pack.signature_digest

    def test_snapshot_after_one_register(self) -> None:
        registry = HookRegistry(max_timeout_seconds=30.0)
        registry.register_pack(_make_pack())
        snap = registry.snapshot()
        assert ("dlp_pre", "redact_pii") in snap
        assert isinstance(snap, MappingProxyType)

    def test_register_two_packs_different_phases(self) -> None:
        registry = HookRegistry(max_timeout_seconds=30.0)
        pack1 = _make_pack(
            distribution_name="cognic-hook-redact-pii",
            declarations=(
                _make_declaration(
                    hook_id="redact_pii",
                    phase="dlp_pre",
                    ordering_class="input_redaction",
                ),
            ),
        )
        pack2 = _make_pack(
            distribution_name="cognic-hook-mask-output",
            signature_digest="sha256:" + "b" * 64,
            declarations=(
                _make_declaration(
                    hook_id="mask_output",
                    phase="dlp_post",
                    ordering_class="output_redaction",
                ),
            ),
        )
        registry.register_pack(pack1)
        registry.register_pack(pack2)
        snap = registry.snapshot()
        assert len(snap) == 2

    def test_register_pack_with_multiple_declarations(self) -> None:
        registry = HookRegistry(max_timeout_seconds=30.0)
        pack = _make_pack(
            declarations=(
                _make_declaration(hook_id="hook_a", ordering_class="input_redaction"),
                _make_declaration(hook_id="hook_b", ordering_class="input_authorization"),
            ),
        )
        entries = registry.register_pack(pack)
        assert len(entries) == 2

    def test_idempotent_re_register_same_digest(self) -> None:
        # Re-registering the SAME pack identity (distribution_name +
        # version + digest) is a no-op (does not raise; returns the
        # already-registered entries).
        registry = HookRegistry(max_timeout_seconds=30.0)
        pack = _make_pack()
        first = registry.register_pack(pack)
        second = registry.register_pack(pack)
        assert first == second
        assert len(registry.snapshot()) == 1


# ---------------------------------------------------------------------------
# HookRegistry fail-closed refusals
# ---------------------------------------------------------------------------


class TestHookRegistryRefusals:
    def test_pack_not_verified_empty_digest(self) -> None:
        registry = HookRegistry(max_timeout_seconds=30.0)
        pack = _make_pack(signature_digest="")
        with pytest.raises(HookRegistryRefusal) as exc_info:
            registry.register_pack(pack)
        assert exc_info.value.reason == "pack_not_verified"

    def test_pack_not_verified_whitespace_digest(self) -> None:
        registry = HookRegistry(max_timeout_seconds=30.0)
        pack = _make_pack(signature_digest="   ")
        with pytest.raises(HookRegistryRefusal) as exc_info:
            registry.register_pack(pack)
        assert exc_info.value.reason == "pack_not_verified"

    def test_duplicate_hook_id_cross_pack(self) -> None:
        registry = HookRegistry(max_timeout_seconds=30.0)
        registry.register_pack(_make_pack(distribution_name="cognic-hook-pack-a"))
        # Second pack tries to register the same (phase, hook_id) →
        # refuse fail-closed.
        pack_b = _make_pack(
            distribution_name="cognic-hook-pack-b",
            signature_digest="sha256:" + "b" * 64,
        )
        with pytest.raises(HookRegistryRefusal) as exc_info:
            registry.register_pack(pack_b)
        assert exc_info.value.reason == "duplicate_hook_id_cross_pack"

    def test_stale_digest_same_pack_different_digest(self) -> None:
        # Same distribution_name + version, different digest → stale_digest
        # refusal. Forces explicit revoke-then-register ordering at
        # supply-chain re-verification time.
        registry = HookRegistry(max_timeout_seconds=30.0)
        pack_v1 = _make_pack(signature_digest="sha256:" + "a" * 64)
        pack_v1_diff_digest = _make_pack(signature_digest="sha256:" + "b" * 64)
        registry.register_pack(pack_v1)
        with pytest.raises(HookRegistryRefusal) as exc_info:
            registry.register_pack(pack_v1_diff_digest)
        assert exc_info.value.reason == "stale_digest"

    def test_refusal_reason_is_closed_enum(self) -> None:
        # Pin the closed-enum literal so future additions force an
        # explicit doctrine review (closed-enum invariant).
        valid_reasons: set[HookRegistryRefusalReason] = {
            "pack_not_verified",
            "duplicate_hook_id_cross_pack",
            "stale_digest",
            "timeout_above_ceiling",
        }
        # The Literal type itself isn't introspectable at runtime
        # without `typing.get_args`; emulate by triggering each refusal
        # and collecting the observed reasons.
        observed: set[str] = set()

        # pack_not_verified
        registry = HookRegistry(max_timeout_seconds=30.0)
        try:
            registry.register_pack(_make_pack(signature_digest=""))
        except HookRegistryRefusal as exc:
            observed.add(exc.reason)

        # duplicate_hook_id_cross_pack
        registry.register_pack(_make_pack(distribution_name="pack-a"))
        try:
            registry.register_pack(
                _make_pack(distribution_name="pack-b", signature_digest="sha256:" + "c" * 64)
            )
        except HookRegistryRefusal as exc:
            observed.add(exc.reason)

        # stale_digest
        try:
            registry.register_pack(
                _make_pack(distribution_name="pack-a", signature_digest="sha256:" + "d" * 64)
            )
        except HookRegistryRefusal as exc:
            observed.add(exc.reason)

        # timeout_above_ceiling — exercise on a fresh registry to
        # avoid coupling to the cross-pack residual state above.
        registry_2 = HookRegistry(max_timeout_seconds=30.0)
        try:
            registry_2.register_pack(
                _make_pack(declarations=(_make_declaration(timeout_seconds=10000.0),))
            )
        except HookRegistryRefusal as exc:
            observed.add(exc.reason)

        assert observed == valid_reasons

    def test_refusal_no_partial_state_mutation(self) -> None:
        # If a multi-declaration pack would conflict on its second
        # declaration, the FIRST declaration must NOT be left in the
        # registry — admission is all-or-nothing per pack.
        registry = HookRegistry(max_timeout_seconds=30.0)
        registry.register_pack(_make_pack(distribution_name="pre-existing"))
        # New pack: first decl is fresh, second collides with the
        # already-registered hook.
        new_pack = _make_pack(
            distribution_name="conflicting-pack",
            signature_digest="sha256:" + "e" * 64,
            declarations=(
                _make_declaration(hook_id="fresh_hook"),
                _make_declaration(hook_id="redact_pii"),  # collides
            ),
        )
        with pytest.raises(HookRegistryRefusal):
            registry.register_pack(new_pack)
        # ``fresh_hook`` MUST NOT be in the registry — admission rolled
        # back the partial state.
        snap = registry.snapshot()
        assert ("dlp_pre", "fresh_hook") not in snap
        assert ("dlp_pre", "redact_pii") in snap  # the original is intact


# ---------------------------------------------------------------------------
# HookRegistry timeout-ceiling enforcement
# ---------------------------------------------------------------------------


class TestHookRegistryTimeoutCeiling:
    """Per Doctrine Lock E: ``min(manifest.timeout_seconds,
    Settings.hook_max_timeout_s)`` is the runtime budget. The registry
    enforces the upper bound at admission time so a malicious manifest
    cannot smuggle in a 1-day timeout."""

    def test_timeout_at_ceiling_is_allowed(self) -> None:
        registry = HookRegistry(max_timeout_seconds=30.0)
        pack = _make_pack(declarations=(_make_declaration(timeout_seconds=30.0),))
        registry.register_pack(pack)  # no raise

    def test_timeout_above_ceiling_is_refused_at_admission(self) -> None:
        # The ceiling check uses the ``HookRegistry.max_timeout_seconds``
        # value passed at registry construction — not a global —
        # because each runtime authority pins its own ceiling.
        # Constructing a declaration in isolation with a very high
        # timeout is ALLOWED (the manifest validator catches that at
        # validate-time); the registry refuses at admission as
        # defense-in-depth for the case where validate is bypassed.
        decl = _make_declaration(timeout_seconds=10000.0)
        registry = HookRegistry(max_timeout_seconds=30.0)
        pack = _make_pack(declarations=(decl,))
        with pytest.raises(HookRegistryRefusal) as exc_info:
            registry.register_pack(pack)
        assert exc_info.value.reason == "timeout_above_ceiling"


# ---------------------------------------------------------------------------
# HookRegistry deterministic phase order
# ---------------------------------------------------------------------------


class TestHookRegistryPhaseOrder:
    def test_get_phase_hooks_sorted_by_ordering_rank(self) -> None:
        # input_validation (rank 10) before input_authorization (rank 20)
        # before input_redaction (rank 30) before input_normalization
        # (rank 40) for ``dlp_pre`` per HOOK_ORDERING_RANK.
        # Dispatcher-deterministic.
        registry = HookRegistry(max_timeout_seconds=30.0)
        # Register in REVERSE rank order to prove the dispatcher
        # sort doesn't depend on insertion order.
        pack_high = _make_pack(
            distribution_name="pack-high-rank",
            signature_digest="sha256:" + "a" * 64,
            declarations=(
                _make_declaration(hook_id="hook_high_rank", ordering_class="input_normalization"),
            ),
        )
        pack_low = _make_pack(
            distribution_name="pack-low-rank",
            signature_digest="sha256:" + "b" * 64,
            declarations=(
                _make_declaration(hook_id="hook_low_rank", ordering_class="input_validation"),
            ),
        )
        registry.register_pack(pack_high)
        registry.register_pack(pack_low)
        ordered = registry.get_phase_hooks("dlp_pre")
        assert [e.hook_id for e in ordered] == ["hook_low_rank", "hook_high_rank"]

    def test_get_phase_hooks_ties_broken_by_hook_id_alphabetic(self) -> None:
        # Two hooks at the same ordering_class (same rank) sort by
        # hook_id alphabetic.
        registry = HookRegistry(max_timeout_seconds=30.0)
        pack_b = _make_pack(
            distribution_name="pack-b",
            signature_digest="sha256:" + "a" * 64,
            declarations=(
                _make_declaration(hook_id="hook_zebra", ordering_class="input_redaction"),
            ),
        )
        pack_a = _make_pack(
            distribution_name="pack-a",
            signature_digest="sha256:" + "b" * 64,
            declarations=(
                _make_declaration(hook_id="hook_alpha", ordering_class="input_redaction"),
            ),
        )
        registry.register_pack(pack_b)
        registry.register_pack(pack_a)
        ordered = registry.get_phase_hooks("dlp_pre")
        assert [e.hook_id for e in ordered] == ["hook_alpha", "hook_zebra"]

    def test_get_phase_hooks_returns_empty_tuple_for_unregistered_phase(self) -> None:
        registry = HookRegistry(max_timeout_seconds=30.0)
        registry.register_pack(_make_pack())  # registers under dlp_pre
        assert registry.get_phase_hooks("dlp_post") == ()

    def test_get_phase_hooks_returns_tuple_not_list(self) -> None:
        # Tuple is immutable; mutating the dispatcher's iteration
        # target through the registry's return value must be impossible.
        registry = HookRegistry(max_timeout_seconds=30.0)
        registry.register_pack(_make_pack())
        result = registry.get_phase_hooks("dlp_pre")
        assert isinstance(result, tuple)


# ---------------------------------------------------------------------------
# HookRegistry deferred-load invariant
# ---------------------------------------------------------------------------


class TestHookRegistryDeferredLoad:
    """Pre-import-trust invariant inherited from Sprint-4
    ``protocol/plugin_registry.py``: registration NEVER calls
    ``EntryPoint.load()``. Pack code is loaded only at dispatch time."""

    def test_callable_loader_not_invoked_at_registration(self) -> None:
        invocation_count = [0]

        def _tracking_loader() -> type:
            invocation_count[0] += 1
            return object

        registry = HookRegistry(max_timeout_seconds=30.0)
        pack = _make_pack(
            declarations=(_make_declaration(callable_loader=_tracking_loader),),
        )
        registry.register_pack(pack)
        assert invocation_count[0] == 0

    def test_callable_loader_carried_through_to_entry(self) -> None:
        sentinel = object()

        def _loader() -> object:
            return sentinel

        registry = HookRegistry(max_timeout_seconds=30.0)
        pack = _make_pack(
            declarations=(_make_declaration(callable_loader=_loader),),
        )
        entries = registry.register_pack(pack)
        # Caller (the dispatcher in T7) explicitly invokes the loader
        # at dispatch time — proving the registry passed the callable
        # through unchanged.
        assert entries[0].callable_loader() is sentinel


# ---------------------------------------------------------------------------
# HookEntry shape pin
# ---------------------------------------------------------------------------


class TestHookEntryShape:
    """``HookEntry`` is the dispatcher's runtime read surface; its
    field set is a wire-shape contract between registry (T6) and
    dispatcher (T7). Pin every public field so a future refactor
    forces this regression to be updated."""

    def test_entry_carries_required_fields(self) -> None:
        registry = HookRegistry(max_timeout_seconds=30.0)
        pack = _make_pack()
        entry = registry.register_pack(pack)[0]
        # Field set is fixed (frozen + slotted); enumerate explicitly.
        assert isinstance(entry, HookEntry)
        assert entry.phase == "dlp_pre"
        assert entry.hook_id == "redact_pii"
        assert entry.ordering_class == "input_redaction"
        assert entry.ordering_rank == HOOK_ORDERING_RANK["input_redaction"]
        assert entry.timeout_seconds == 1.0
        assert entry.fail_policy == "fail_closed"
        assert entry.fail_open_exception is None
        assert callable(entry.callable_loader)
        assert entry.pack_distribution_name == "cognic-hook-redact-pii"
        assert entry.pack_distribution_version == "0.1.0"
        assert entry.signature_digest.startswith("sha256:")

    def test_entry_is_frozen_and_slotted(self) -> None:
        registry = HookRegistry(max_timeout_seconds=30.0)
        entry = registry.register_pack(_make_pack())[0]
        with pytest.raises(dataclasses.FrozenInstanceError):
            entry.hook_id = "stolen"  # type: ignore[misc]
        # See ``test_declaration_is_slotted`` — Python may surface the
        # non-slot assignment as either AttributeError (frozen check
        # first) or TypeError (slot miss first); either signals the
        # immutability invariant.
        with pytest.raises((AttributeError, TypeError)):
            entry.injected = "bad"  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# HookRegistry single-writer + snapshot immutability
# ---------------------------------------------------------------------------


class TestHookRegistrySnapshotImmutability:
    """Doctrine Lock D: ``snapshot()`` returns an immutable view; the
    dispatcher cannot mutate the registry's state through the snapshot,
    and a concurrent registration cannot retroactively appear in a
    snapshot already taken."""

    def test_snapshot_is_mappingproxy(self) -> None:
        registry = HookRegistry(max_timeout_seconds=30.0)
        registry.register_pack(_make_pack())
        snap = registry.snapshot()
        assert isinstance(snap, MappingProxyType)

    def test_snapshot_cannot_be_mutated(self) -> None:
        registry = HookRegistry(max_timeout_seconds=30.0)
        registry.register_pack(_make_pack())
        snap = registry.snapshot()
        with pytest.raises(TypeError):
            snap[("dlp_pre", "stolen")] = None  # type: ignore[index]

    def test_snapshot_is_decoupled_from_subsequent_writes(self) -> None:
        # Snapshot taken BEFORE a second register_pack must NOT include
        # the second pack's entries — the dispatcher's iteration is
        # pinned to its snapshot.
        registry = HookRegistry(max_timeout_seconds=30.0)
        registry.register_pack(_make_pack(distribution_name="pack-1"))
        snap_before = registry.snapshot()
        registry.register_pack(
            _make_pack(
                distribution_name="pack-2",
                signature_digest="sha256:" + "b" * 64,
                declarations=(_make_declaration(hook_id="other_hook"),),
            )
        )
        # snap_before is a dict-snapshot wrapped in MappingProxyType,
        # frozen at the point of the call.
        assert ("dlp_pre", "other_hook") not in snap_before


# ---------------------------------------------------------------------------
# HookOrderingClass / HookPhase invariants enforced by the registry
# ---------------------------------------------------------------------------


class TestHookRegistryRespectsClosedEnumDoctrine:
    """The registry consumes ``HOOK_ORDERING_CLASS_PHASE`` from
    ``cli/_governance_vocab.py``. Pin that the dual-source doctrine
    holds — the registry's phase/class-mismatch check uses the same
    map the validator uses."""

    def test_every_ordering_class_has_a_unique_phase(self) -> None:
        # Pinned for documentation: every HookOrderingClass belongs to
        # exactly one phase. Adding a class shared between phases would
        # break the registry's phase_class_mismatch check.
        # Each class maps to one phase string (no list / set).
        for cls, phase in HOOK_ORDERING_CLASS_PHASE.items():
            assert isinstance(phase, str), f"{cls} maps to non-string {phase!r}"
