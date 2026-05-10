"""Sprint-7A2 T6 — runtime hook registry admission gate.

Per Doctrine Lock D in
``docs/superpowers/plans/2026-05-09-sprint-7a2-hook-packs-runtime.md``:

  ``HookRegistry`` admission gate. Only verified hook packs register
  (consume the existing Sprint-4 ``protocol/plugin_registry.py``
  admission orchestrator's verified-pack list). Indexed by
  ``(phase, hook_id)``; duplicate hook IDs across packs refuse
  fail-closed; stale digests (post-pack-revoke) refuse fail-closed.
  The registry is single-writer at admission; no runtime mutation
  after the registration path completes.

This module ships the **admission half** of the hook runtime; the
**dispatch half** lands at T7 (``packs/hooks/dispatcher.py``). The
boundary is firm: registry mutates at admission; dispatcher reads an
immutable snapshot at dispatch entry. The two share frozen value
objects (``HookEntry``) but never mutable state.

Critical-controls promotion: this module joins the gate at T12
closeout (37 → 40). The closed-enum refusal vocabulary is wire-shape
contract for downstream consumers (audit emitters, kill-switches);
adding a new reason requires explicit doctrine review.

Closed-enum refusal reasons (4):

* ``pack_not_verified`` — empty / whitespace-only ``signature_digest``
  on the ``VerifiedHookPack``. The construct is deliberately
  permissive at the value-object boundary (so test harnesses can
  build packs without a real signature) but the registry refuses
  fail-closed.
* ``duplicate_hook_id_cross_pack`` — two distributions registering
  the same ``(phase, hook_id)``. The plugin-trust shadowing surface;
  refused rather than picking a winner.
* ``stale_digest`` — same ``(distribution_name, distribution_version)``
  re-registered with a different ``signature_digest``. Forces the
  caller to revoke-then-register at supply-chain re-verification time
  rather than silently overwriting.
* ``timeout_above_ceiling`` — declaration's ``timeout_seconds``
  exceeds the registry's runtime ceiling. Defense-in-depth against a
  manifest that bypasses the validator (T5) and smuggles in a
  multi-hour timeout. Pin against denial-of-service via runaway hooks.

Construction-time invariants (raise ``ValueError`` from
``__post_init__``):

* ``HookDeclaration``: empty ``hook_id``, non-positive
  ``timeout_seconds``, ``phase_class_mismatch`` (the
  ``ordering_class`` doesn't belong to the declared ``phase`` per
  ``HOOK_ORDERING_CLASS_PHASE``), and ``fail_open`` policy without
  ``fail_open_exception``.
* ``VerifiedHookPack``: duplicate ``(phase, hook_id)`` keys within
  the pack's own declarations.

The registry's runtime read API:

* ``snapshot()`` → ``MappingProxyType`` view over a dict-snapshot of
  ``(phase, hook_id) → HookEntry``. Stable across subsequent
  registrations (decoupled at call time).
* ``get_phase_hooks(phase)`` → tuple sorted by
  ``HOOK_ORDERING_RANK[ordering_class]`` ascending, ties broken by
  ``hook_id`` alphabetic. Dispatcher-deterministic ordering.

The ``callable_loader`` field is **never invoked at registration**.
Pre-import-trust invariant inherited from Sprint-4
``protocol/plugin_registry.py``: pack code is loaded only at dispatch
time, after the trust gate has cleared. The registry holds the
deferred callable; the dispatcher (T7) is responsible for invoking it.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final, Literal

from cognic_agentos.cli._governance_vocab import (
    HOOK_ORDERING_CLASS_PHASE,
    HOOK_ORDERING_RANK,
    HookFailPolicy,
    HookOrderingClass,
    HookPhase,
)

__all__ = [
    "HookDeclaration",
    "HookEntry",
    "HookRegistry",
    "HookRegistryRefusal",
    "HookRegistryRefusalReason",
    "VerifiedHookPack",
]


#: Closed-enum surface for ``HookRegistry.register_pack`` refusals.
#: Consumed by audit-emitter call sites + kill-switch correlation;
#: extending requires doctrine review (T12 critical-controls promotion
#: pins this as wire-shape contract).
HookRegistryRefusalReason = Literal[
    "pack_not_verified",
    "duplicate_hook_id_cross_pack",
    "stale_digest",
    "timeout_above_ceiling",
]


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HookDeclaration:
    """Per-hook declaration parsed from a verified pack's manifest.

    Frozen + slotted so a rogue runtime caller cannot mutate a
    declaration after admission to redirect the dispatcher. Fields:

    * ``hook_id`` — pack-scoped identifier; non-empty after strip.
    * ``phase`` — closed-enum ``HookPhase`` (Wave-1: ``dlp_pre`` /
      ``dlp_post``).
    * ``ordering_class`` — closed-enum ``HookOrderingClass``; MUST
      belong to ``phase`` per ``HOOK_ORDERING_CLASS_PHASE``.
    * ``timeout_seconds`` — positive float; the registry separately
      enforces the ceiling at admission time.
    * ``fail_policy`` — closed-enum ``HookFailPolicy`` (``fail_closed``
      / ``fail_open``).
    * ``fail_open_exception`` — REQUIRED iff ``fail_policy`` is
      ``fail_open`` (the manifest nominates which exception class
      triggers the open). ``None`` is allowed when ``fail_closed``.
    * ``callable_loader`` — deferred-load callable returning the
      ``Hook`` subclass; NOT invoked at registration.
    * ``ordering_rank`` — cached ``HOOK_ORDERING_RANK[ordering_class]``
      for dispatcher fast-path. Computed in ``__post_init__``; never
      assigned by the caller.
    """

    hook_id: str
    phase: HookPhase
    ordering_class: HookOrderingClass
    timeout_seconds: float
    fail_policy: HookFailPolicy
    fail_open_exception: str | None
    callable_loader: Callable[[], object]
    # ``ordering_rank`` is derived from ``ordering_class`` in
    # ``__post_init__``. ``init=False`` keeps it out of the
    # constructor signature so callers cannot accidentally diverge it
    # from the canonical rank table.
    ordering_rank: int = field(init=False)

    def __post_init__(self) -> None:
        # Empty / whitespace-only hook_id refused. Validate-time
        # (T5) catches this too via the manifest validator; registry
        # is defense-in-depth for the case where validate is bypassed.
        if not self.hook_id or not self.hook_id.strip():
            raise ValueError(f"hook_id must be non-empty after strip; got {self.hook_id!r}")

        # Non-positive timeout refused. The ceiling check is
        # registry-scope (Settings-derived); zero / negative is a
        # universal violation regardless of registry config.
        if self.timeout_seconds <= 0:
            raise ValueError(f"timeout_seconds must be > 0; got {self.timeout_seconds!r}")

        # phase_class_mismatch — ``ordering_class`` belongs to exactly
        # one ``HookPhase`` per ``HOOK_ORDERING_CLASS_PHASE``. Cross-
        # phase declaration is the validator's
        # ``hook_ordering_class_invalid:phase_class_mismatch`` reason.
        expected_phase = HOOK_ORDERING_CLASS_PHASE.get(self.ordering_class)
        if expected_phase is None:
            # Closed-enum violation surfaced as a clear runtime error;
            # static typing should already catch this via Literal
            # narrowing, but defense-in-depth covers the bypass path.
            raise ValueError(
                f"ordering_class {self.ordering_class!r} is not in the "
                f"closed enum HOOK_ORDERING_CLASS_PHASE"
            )
        if expected_phase != self.phase:
            raise ValueError(
                f"phase / ordering_class mismatch: ordering_class "
                f"{self.ordering_class!r} belongs to phase "
                f"{expected_phase!r}, not {self.phase!r}"
            )

        # fail_open requires an exception declaration. Default policy
        # is fail_closed; opting into fail_open is intentional and
        # MUST nominate the exception class that triggers the open.
        if self.fail_policy == "fail_open" and not self.fail_open_exception:
            raise ValueError(
                "fail_policy='fail_open' requires fail_open_exception to "
                "be set (the manifest must nominate which exception "
                "class triggers the open)"
            )

        # Cache the ordering_rank for dispatcher fast-path. Closed-enum
        # invariant: every HookOrderingClass has a rank (the closed-
        # enum-vocabulary test in test_config.py pins this).
        object.__setattr__(self, "ordering_rank", HOOK_ORDERING_RANK[self.ordering_class])


@dataclass(frozen=True, slots=True)
class VerifiedHookPack:
    """A hook pack that has cleared trust + supply-chain verification.

    The value object is constructible without a non-empty
    ``signature_digest`` so test harnesses can build packs ergonomically;
    the registry's ``register_pack`` refuses fail-closed at admission
    time on empty / whitespace digests. Production callers (the host
    startup pipeline that consumes ``protocol/plugin_registry.py``'s
    verified outcomes) always carry a real ``signature_digest`` from
    cosign verification.
    """

    distribution_name: str
    distribution_version: str
    signature_digest: str
    declarations: tuple[HookDeclaration, ...]

    def __post_init__(self) -> None:
        # Duplicate (phase, hook_id) within a single pack's
        # declarations is a manifest-shape violation. Validate-time
        # (T5) catches this via ``hook_id_invalid:duplicate_in_manifest``;
        # registry-side check is defense-in-depth.
        seen: set[tuple[HookPhase, str]] = set()
        for decl in self.declarations:
            key = (decl.phase, decl.hook_id)
            if key in seen:
                raise ValueError(
                    f"duplicate (phase, hook_id) within pack {self.distribution_name!r}: {key!r}"
                )
            seen.add(key)


@dataclass(frozen=True, slots=True)
class HookEntry:
    """A registered hook entry — the wire-shape contract between the
    registry (T6) and the dispatcher (T7). Frozen + slotted so the
    dispatcher's iteration target cannot be mutated mid-dispatch.
    """

    phase: HookPhase
    hook_id: str
    ordering_class: HookOrderingClass
    ordering_rank: int
    timeout_seconds: float
    fail_policy: HookFailPolicy
    fail_open_exception: str | None
    callable_loader: Callable[[], object]
    pack_distribution_name: str
    pack_distribution_version: str
    signature_digest: str


# ---------------------------------------------------------------------------
# Refusal exception
# ---------------------------------------------------------------------------


class HookRegistryRefusal(RuntimeError):
    """Raised by :meth:`HookRegistry.register_pack` on fail-closed
    admission conditions. Carries the closed-enum
    :data:`HookRegistryRefusalReason` so callers can correlate to
    audit / kill-switch records without re-parsing the message."""

    def __init__(self, reason: HookRegistryRefusalReason, detail: str) -> None:
        self.reason: Final[HookRegistryRefusalReason] = reason
        super().__init__(f"hook registry refused [{reason}]: {detail}")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class HookRegistry:
    """Single-writer hook admission gate.

    Indexed by ``(phase, hook_id)``. Registration mutates;
    ``snapshot`` / ``get_phase_hooks`` are read-only. The registry
    enforces the four closed-enum refusal conditions
    (``pack_not_verified`` / ``duplicate_hook_id_cross_pack`` /
    ``stale_digest`` / ``timeout_above_ceiling``) and rolls back any
    partial state on a multi-declaration pack failure.

    Doctrine Lock D pins **single-writer at admission; no runtime
    mutation after the registration path completes**. The
    in-memory dict is mutated only inside ``register_pack``;
    runtime kill-switches operate at the dispatcher level (T7+),
    not by mutating the registry.
    """

    def __init__(self, *, max_timeout_seconds: float) -> None:
        if max_timeout_seconds <= 0:
            raise ValueError(f"max_timeout_seconds must be > 0; got {max_timeout_seconds!r}")
        self._max_timeout_seconds = max_timeout_seconds
        # ``(phase, hook_id) → HookEntry``. Mutated only in
        # ``register_pack`` after all per-declaration validation
        # passes (atomic admission).
        self._records: dict[tuple[HookPhase, str], HookEntry] = {}
        # ``(distribution_name, distribution_version) → signature_digest``.
        # Used by the stale-digest check at re-registration time.
        self._pack_digests: dict[tuple[str, str], str] = {}

    # --- public read API -----------------------------------------------------

    def snapshot(self) -> Mapping[tuple[HookPhase, str], HookEntry]:
        """Return an immutable view over a dict-snapshot of the
        current ``(phase, hook_id) → HookEntry`` map.

        The returned ``MappingProxyType`` wraps a copy taken at call
        time; subsequent ``register_pack`` calls do not retroactively
        appear in a snapshot already taken. The dispatcher (T7) takes
        a single snapshot at dispatch entry and iterates against that
        immutable view for the duration of one dispatch call.
        """
        # Copy first, then proxy — proxy over the mutable dict would
        # leak future mutations into the dispatcher's iteration.
        return MappingProxyType(dict(self._records))

    def get_phase_hooks(self, phase: HookPhase) -> tuple[HookEntry, ...]:
        """Return the registered entries for ``phase`` in
        dispatcher-deterministic order: ``ordering_rank`` ascending,
        ties broken by ``hook_id`` alphabetic.

        Empty tuple if no entries are registered under ``phase``. The
        return type is a tuple (not a list) so the dispatcher cannot
        accidentally mutate the iteration target through this view.
        """
        entries = [e for e in self._records.values() if e.phase == phase]
        entries.sort(key=lambda e: (e.ordering_rank, e.hook_id))
        return tuple(entries)

    # --- public write API ----------------------------------------------------

    def register_pack(self, pack: VerifiedHookPack) -> tuple[HookEntry, ...]:
        """Admit a verified hook pack into the registry.

        Returns the admitted entries (in declaration order) on
        success. Raises :class:`HookRegistryRefusal` on any
        fail-closed condition, leaving the registry's state
        unchanged (atomic admission — partial-state rollback is
        structural: we validate every declaration before mutating
        state).

        Idempotent for the same pack identity (distribution name +
        version + digest): re-registering the SAME pack is a no-op
        and returns the previously-admitted entries.
        """
        # Step 1: pack_not_verified — empty / whitespace-only digest.
        digest = pack.signature_digest.strip()
        if not digest:
            raise HookRegistryRefusal(
                "pack_not_verified",
                f"pack {pack.distribution_name!r} v{pack.distribution_version} "
                f"has empty / whitespace-only signature_digest; the trust "
                f"gate must populate this before admission",
            )

        # Step 2: stale_digest — same identity, different digest.
        pack_key = (pack.distribution_name, pack.distribution_version)
        existing_digest = self._pack_digests.get(pack_key)
        if existing_digest is not None and existing_digest != digest:
            raise HookRegistryRefusal(
                "stale_digest",
                f"pack {pack.distribution_name!r} v{pack.distribution_version} "
                f"already registered with signature_digest {existing_digest!r}; "
                f"refusing to overwrite with {digest!r}. Resolve via explicit "
                f"revoke-then-register at supply-chain re-verification time.",
            )

        # Step 3: idempotent re-register — same pack key, same digest.
        # Return the existing entries without re-mutating state.
        if existing_digest is not None and existing_digest == digest:
            return tuple(
                e
                for e in self._records.values()
                if e.pack_distribution_name == pack.distribution_name
                and e.pack_distribution_version == pack.distribution_version
            )

        # Step 4: per-declaration validation — collect candidate
        # entries WITHOUT mutating state, so a refusal on the last
        # declaration rolls back cleanly.
        candidate_entries: list[HookEntry] = []
        for decl in pack.declarations:
            # timeout_above_ceiling — registry-scope ceiling check.
            if decl.timeout_seconds > self._max_timeout_seconds:
                raise HookRegistryRefusal(
                    "timeout_above_ceiling",
                    f"hook {decl.hook_id!r} in pack "
                    f"{pack.distribution_name!r} declares "
                    f"timeout_seconds={decl.timeout_seconds!r} which "
                    f"exceeds the registry ceiling "
                    f"({self._max_timeout_seconds!r})",
                )

            key = (decl.phase, decl.hook_id)

            # duplicate_hook_id_cross_pack — same (phase, hook_id)
            # already owned by a DIFFERENT pack. Same-pack re-register
            # was caught upstream by the idempotent-re-register branch.
            existing_entry = self._records.get(key)
            if existing_entry is not None:
                # ``existing_entry`` is from a different pack (otherwise
                # the idempotent-re-register branch above would have
                # returned). Refuse fail-closed.
                raise HookRegistryRefusal(
                    "duplicate_hook_id_cross_pack",
                    f"hook ({decl.phase}, {decl.hook_id!r}) is already "
                    f"registered to pack "
                    f"{existing_entry.pack_distribution_name!r} "
                    f"v{existing_entry.pack_distribution_version}; "
                    f"refusing to admit conflicting registration from "
                    f"{pack.distribution_name!r} v{pack.distribution_version}",
                )

            candidate_entries.append(
                HookEntry(
                    phase=decl.phase,
                    hook_id=decl.hook_id,
                    ordering_class=decl.ordering_class,
                    ordering_rank=decl.ordering_rank,
                    timeout_seconds=decl.timeout_seconds,
                    fail_policy=decl.fail_policy,
                    fail_open_exception=decl.fail_open_exception,
                    callable_loader=decl.callable_loader,
                    pack_distribution_name=pack.distribution_name,
                    pack_distribution_version=pack.distribution_version,
                    signature_digest=digest,
                )
            )

        # Step 5: commit — all per-declaration validation passed; mutate
        # state atomically. (Partial-state rollback is structural: a
        # refusal in the loop above never reaches here.)
        for entry in candidate_entries:
            self._records[(entry.phase, entry.hook_id)] = entry
        self._pack_digests[pack_key] = digest
        return tuple(candidate_entries)
