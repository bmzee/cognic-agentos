"""Sprint 8A T7 — egress proxy config rendering + audit record
materialisation (CRITICAL CONTROLS).

Per spec §10.2 (proxy implementation) + §10.3 (audit emission shape) +
§10.4 (proxy-observed vs network-blocked refusal classes).

Critical-controls promotion (spec §17): `sandbox/proxy.py` is the
single substantive egress enforcement decision point in Wave 1. The
sidecar runs upstream code (tinyproxy or equivalent) reading
``ALLOW_LIST`` JSON from env at start; the per-call allow-list that
ends up in that env variable comes through this module's
``render_proxy_config``. A bug here (missing scheme check, host
normalisation drift, list ordering instability) lets forbidden
traffic through.

Public API:

* :data:`ProxyAccessRefusalReason` — closed-enum 2-value Literal for
  Wave-1 proxy-side refusal classes (per spec §10.4).
* :class:`EgressProxyConfig` — frozen dataclass; output of
  :func:`render_proxy_config`; ``.to_env()`` returns the env-var
  dict the sidecar consumes.
* :func:`render_proxy_config` — pure projector from
  ``(egress_allow_list, session_id)`` to an :class:`EgressProxyConfig`.
  Re-runs Stage-1's per-entry scheme + RFC 1123 validation as
  defence-in-depth (cannot silently smuggle a non-HTTP entry to the
  sidecar even if a future caller bypasses Stage-1).
* :func:`proxy_log_to_chain_payload` — materialises a tuple of
  :class:`ProxyAccessRecord` into the canonical-safe ``list[dict]``
  the chain row's ``payload.proxy_log`` requires (per spec §10.3 +
  ``core.canonical.canonical_bytes`` rejecting tuples).
* :class:`ProxyAccessRecord` — re-exported from
  :mod:`cognic_agentos.sandbox.protocol` (the type is owned by the
  Protocol module so ``SandboxExecResult.proxy_log`` can reference
  it without a circular import; this module owns the 2-value
  refusal vocabulary the type's ``refusal_reason`` field carries).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal, get_args

from cognic_agentos.sandbox.policy import _validate_egress_host

# ``ProxyAccessRecord`` + ``ProxyAccessOutcome`` are owned by
# :mod:`cognic_agentos.sandbox.protocol` (T3) so
# ``SandboxExecResult.proxy_log: tuple[ProxyAccessRecord, ...]`` can
# reference them without a circular import (protocol → proxy would
# pull policy/proxy into protocol module-load). T7 expanded the
# ProxyAccessRecord placeholder to its 6-field shape + T7 R10
# promoted the anonymous ``outcome: Literal[...]`` to the named
# ``ProxyAccessOutcome`` alias so the runtime closed-set check here
# can derive via ``typing.get_args``. We re-export both so callers
# can write ``from cognic_agentos.sandbox.proxy import ...``
# alongside the rest of the proxy public surface.
from cognic_agentos.sandbox.protocol import ProxyAccessOutcome, ProxyAccessRecord

__all__ = [
    "EgressProxyConfig",
    "ProxyAccessOutcome",
    "ProxyAccessRecord",
    "ProxyAccessRefusalReason",
    "proxy_log_to_chain_payload",
    "render_proxy_config",
]


# ---------------------------------------------------------------------------
# Closed-enum vocabularies
# ---------------------------------------------------------------------------

#: Wave-1 proxy-side refusal vocabulary (spec §10.4).
#:
#: Two values:
#:
#: * ``not_in_allow_list`` — host not on the per-call allow-list.
#: * ``non_http_connect_target`` — HTTP CONNECT to non-443 port or a
#:   non-HTTP method (proxy-observed class per spec §10.4).
#:
#: Wave-2 may add network-level telemetry surfacing new reasons (e.g.
#: ``raw_tcp_attempt``); those are deliberately NOT in the Wave-1
#: vocabulary per spec §10.4 ("no per-attempt audit record in Wave 1"
#: for raw-protocol attempts blocked at the network layer).
#:
#: Drift between this Literal and the chain-row consumer is caught by
#: the closed-enum self-test at
#: ``tests/unit/sandbox/test_egress_proxy_config.py``.
ProxyAccessRefusalReason = Literal[
    "not_in_allow_list",
    "non_http_connect_target",
]


#: Runtime-checkable mirror of :data:`ProxyAccessRefusalReason`. Derived
#: at module load via :func:`typing.get_args` so the closed-set check
#: in :func:`proxy_log_to_chain_payload` stays in lockstep with the
#: Literal vocabulary without a separate hand-maintained copy (the
#: drift-class :data:`feedback_drift_detector_test_only_no_runtime_import`
#: applies to cross-module mirrors, not intra-module derivations).
_VALID_REFUSAL_REASONS: frozenset[str] = frozenset(get_args(ProxyAccessRefusalReason))

#: Runtime-checkable mirror of :data:`ProxyAccessOutcome`. Same
#: derivation pattern as :data:`_VALID_REFUSAL_REASONS`. Used by
#: :func:`proxy_log_to_chain_payload` to closed-set-check
#: ``rec.outcome`` BEFORE the joint-invariant block dispatches on
#: it — Python does not enforce ``Literal`` values at runtime, so a
#: buggy upstream construction path (e.g. T10's sidecar-log parser
#: from dynamic input) can produce ``outcome="maybe"`` which would
#: otherwise fall through both branches of the joint check + land
#: in the chain payload unchanged.
_VALID_OUTCOMES: frozenset[str] = frozenset(get_args(ProxyAccessOutcome))


# ---------------------------------------------------------------------------
# EgressProxyConfig — sidecar-launch env contract
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EgressProxyConfig:
    """Sidecar-launch env contract per spec §10.2.

    The sidecar container reads two env vars at start:

    * ``ALLOW_LIST`` — JSON array of hostnames (the sidecar parses
      via ``json.loads`` on first request); empty array ⇒ refuse all
      external hosts.
    * ``SESSION_ID`` — the AgentOS session UUID; the sidecar tags
      every log line with this so the audit reader can correlate
      proxy_log entries with the chain row's session.

    The dataclass is frozen so the rendered config cannot be mutated
    after the backend has accepted it (which would silently change
    what the sidecar receives at next launch).
    """

    allow_list: tuple[str, ...]
    session_id: str

    def to_env(self) -> dict[str, str]:
        """Render the launch-time env-var dict the sidecar consumes.

        Returns:
            Dict with exactly the two keys the sidecar reads:
            ``ALLOW_LIST`` (JSON-encoded list of hostnames; order
            preserved from input for examiner-readable startup logs)
            and ``SESSION_ID`` (the session UUID for log
            correlation).
        """
        return {
            "ALLOW_LIST": json.dumps(list(self.allow_list)),
            "SESSION_ID": self.session_id,
        }


# ---------------------------------------------------------------------------
# render_proxy_config — pure projector + defence-in-depth gate
# ---------------------------------------------------------------------------


def render_proxy_config(
    *,
    egress_allow_list: tuple[str, ...],
    session_id: str,
) -> EgressProxyConfig:
    """Project a SandboxPolicy's ``egress_allow_list`` onto the
    sidecar-launch env contract.

    For each entry in ``egress_allow_list``:

    1. Re-run Stage-1's per-entry scheme + RFC 1123 validation via
       :func:`cognic_agentos.sandbox.policy._validate_egress_host`.
       This is the defence-in-depth gate — Stage-1
       ``validate_policy_shape`` runs first in the admission
       pipeline, but this module is the substantive enforcement
       point (spec §17 critical-controls promotion); a future code
       path that bypasses Stage-1 must still be unable to smuggle a
       non-HTTP entry through to the sidecar.
    2. Strip any ``http://`` / ``https://`` scheme prefix — the
       sidecar wants hostnames only (it enforces HTTPS CONNECT
       semantics itself).

    Args:
        egress_allow_list: hostnames the sandbox may reach via the
            proxy. Order preserved into the rendered env so operator
            log-diffing stays stable.
        session_id: the AgentOS session UUID; passed through to the
            ``SESSION_ID`` env var for proxy-log correlation.

    Returns:
        :class:`EgressProxyConfig` carrying the validated +
        scheme-stripped hostname tuple.

    Raises:
        :exc:`cognic_agentos.sandbox.SandboxLifecycleRefused` with
        ``sandbox_policy_egress_protocol_not_http`` if any entry
        carries a non-HTTP/HTTPS scheme, or
        ``sandbox_policy_egress_host_invalid`` if any entry has a
        malformed hostname. Short-circuits on the first failing
        entry (matching Stage-1 semantics).
    """
    normalised: list[str] = []
    for entry in egress_allow_list:
        # Defence-in-depth: re-run the Stage-1 per-entry gate. The
        # cross-module call into a "_"-prefixed helper is intentional
        # — this IS the defence-in-depth chain documented in spec
        # §17 (proxy module re-runs the validation Stage-1 already
        # ran). Inlining the regex here would create the drift class
        # the docstring warns about; the helper is the single source
        # of truth for both stages.
        _validate_egress_host(entry)
        # Strip scheme to hostname-only form. The sidecar's ALLOW_LIST
        # consumer expects bare hostnames; it enforces HTTPS CONNECT
        # itself per spec §10.2 ("the sidecar enforces https-CONNECT
        # itself").
        if "://" in entry:
            _, host_portion = entry.split("://", 1)
        else:
            host_portion = entry
        # Strip any path/query if present (allow-list is hostname-only;
        # mirrors the Stage-1 behaviour).
        host_portion = host_portion.split("/", 1)[0]
        normalised.append(host_portion)

    return EgressProxyConfig(
        allow_list=tuple(normalised),
        session_id=session_id,
    )


# ---------------------------------------------------------------------------
# proxy_log → chain row materialisation
# ---------------------------------------------------------------------------


def proxy_log_to_chain_payload(
    records: tuple[ProxyAccessRecord, ...],
) -> list[dict[str, object]]:
    """Materialise a tuple of :class:`ProxyAccessRecord` into the
    canonical-safe ``list[dict]`` the chain row's
    ``payload.proxy_log`` requires.

    Wire-format invariants:

    * ``core.canonical.canonical_bytes`` (the chain-row serialiser)
      rejects tuples at the top level to prevent the silent
      list/tuple ambiguity bug class. Returning a ``list`` (NOT
      ``tuple``) here is required for chain-row insert to succeed.
    * Each entry is a plain ``dict`` (NOT a dataclass / namedtuple)
      because canonical_bytes only descends through dict + list +
      primitives.
    * Input order is preserved into the rendered list so examiners
      reading the chain payload see the attempted-call sequence the
      sandbox actually generated.

    Evidence-boundary invariants (defence-in-depth — the runtime
    construction surface lands at T10 + Python does not enforce
    ``Literal`` values at runtime + ``ProxyAccessRecord.refusal_reason``
    is typed ``str | None`` to keep ``protocol.py`` free of an import
    on ``sandbox.proxy``, so this materialiser is the single seam
    where the spec §10.3 closed-enum + joint contracts can be
    enforced):

    * ``timestamp`` MUST be timezone-aware per Python's strict
      definition: ``tzinfo is not None`` AND ``utcoffset() is not
      None``. A ``tzinfo`` subclass whose ``utcoffset()`` returns
      ``None`` is "effectively naive" — its ``isoformat()`` emits
      no offset suffix, bypassing ``core.canonical``'s aware-datetime
      guard (the guard operates on ``datetime`` values, not on
      strings).
    * ``outcome`` MUST be one of :data:`ProxyAccessOutcome` closed-
      enum values (``"allowed"`` / ``"refused"``). Checked BEFORE
      the joint-invariant block dispatches on it so an unknown
      outcome cannot fall through both branches into the payload.
    * ``outcome == "allowed"`` ⇒ ``refusal_reason`` MUST be ``None``.
    * ``outcome == "refused"`` ⇒ ``refusal_reason`` MUST be one of
      the :data:`ProxyAccessRefusalReason` closed-enum values
      (Wave-1: ``"not_in_allow_list"`` / ``"non_http_connect_target"``).

    Violations of either contract raise :exc:`ValueError` fail-loud
    at evidence-emission time. The exception class is deliberately
    ``ValueError`` (not :exc:`cognic_agentos.sandbox.SandboxLifecycleRefused`)
    because these are programmer-error states — a buggy upstream
    proxy capture path constructed an inconsistent record — not
    admission-class refusals on external input.

    Args:
        records: the proxy access log captured during a sandbox
            session (T10 ``DockerSiblingSandboxBackend`` reads the
            sidecar's shared-mount log + builds these records on
            ``exec_completed``).

    Returns:
        ``list[dict]`` ready for inclusion in the chain row's
        ``payload.proxy_log`` key. Empty input ⇒ empty list (NOT
        absence-of-key — the chain consumer distinguishes
        "session ran, made no calls" from "session never ran").

    Raises:
        :exc:`ValueError` on any violation of the evidence-boundary
        invariants above. Short-circuits on the first failing record
        — earlier records in the same batch may have already been
        rendered into the in-flight payload list, but that list is
        discarded on the exception path so the chain row never sees
        a partial batch.
    """
    payload: list[dict[str, object]] = []
    for rec in records:
        # Invariant 1 — timestamp must be timezone-aware per Python's
        # actual aware/naive definition: aware iff BOTH
        # ``tzinfo is not None`` AND ``utcoffset() is not None``. A
        # ``tzinfo`` subclass whose ``utcoffset()`` returns ``None``
        # is "effectively naive" (Python docs §datetime); its
        # ``isoformat()`` emits no offset suffix, bypassing the same
        # canonical-form guard this check exists to mirror.
        if rec.timestamp.tzinfo is None or rec.timestamp.utcoffset() is None:
            raise ValueError(
                "ProxyAccessRecord.timestamp must be timezone-aware "
                "per spec §10.3 + canonical-form contract "
                "(tzinfo is not None AND utcoffset() is not None); "
                f"got effectively-naive timestamp {rec.timestamp!r} "
                f"for host={rec.host!r}"
            )
        # Invariant 2 — outcome must be one of the closed-enum values
        # BEFORE the joint-invariant block dispatches on it. A buggy
        # upstream construction (T10 sidecar-log parser fed dynamic
        # input) could produce ``outcome="maybe"``, which would
        # otherwise miss both branches below + land unchanged in the
        # chain payload.
        if rec.outcome not in _VALID_OUTCOMES:
            raise ValueError(
                "ProxyAccessRecord.outcome must be one of "
                f"{sorted(_VALID_OUTCOMES)} per the ProxyAccessOutcome "
                "closed-enum; "
                f"got {rec.outcome!r} for host={rec.host!r}"
            )
        # Invariant 3 — allowed records carry no refusal_reason.
        if rec.outcome == "allowed" and rec.refusal_reason is not None:
            raise ValueError(
                "ProxyAccessRecord with outcome='allowed' must have "
                "refusal_reason=None per spec §10.3; "
                f"got {rec.refusal_reason!r} for host={rec.host!r}"
            )
        # Invariant 4 — refused records carry exactly one closed-enum
        # refusal_reason.
        if rec.outcome == "refused":
            if rec.refusal_reason is None:
                raise ValueError(
                    "ProxyAccessRecord with outcome='refused' must "
                    "carry a non-None refusal_reason per spec §10.3; "
                    f"got None for host={rec.host!r}"
                )
            if rec.refusal_reason not in _VALID_REFUSAL_REASONS:
                raise ValueError(
                    "ProxyAccessRecord.refusal_reason must be one of "
                    f"{sorted(_VALID_REFUSAL_REASONS)} per the "
                    "ProxyAccessRefusalReason closed-enum (Wave-1); "
                    f"got {rec.refusal_reason!r} for host={rec.host!r}"
                )
        payload.append(
            {
                "host": rec.host,
                "method": rec.method,
                "timestamp": rec.timestamp.isoformat(),
                "policy_id": rec.policy_id,
                "outcome": rec.outcome,
                "refusal_reason": rec.refusal_reason,
            }
        )
    return payload
