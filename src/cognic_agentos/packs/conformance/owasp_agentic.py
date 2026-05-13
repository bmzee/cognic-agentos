"""OWASP conformance check implementations (Sprint 7B.2 T8 — CRITICAL CONTROLS).

Per ADR-012 §119 + BUILD_PLAN §628 + plan-of-record §1021-1059.

T8 user-locked contract:

- Deterministic + manifest-shape based. No filesystem reads, no network calls,
  no dependency downloads, no digest recomputation. The CLI validators
  (``cli/validators/identity.py`` etc.) own the file-system-touching checks at
  build/admission time; conformance checks duplicate only the small manifest-
  shape subset and never reach back into CLI plumbing.
- Each check returns one of ``pass`` / ``fail`` / ``not_applicable`` —
  **never ``yellow``**. The composite ``ConformanceReport.overall_status`` is
  the only surface that returns ``yellow``, and only when a checker raises
  (runner-level incompleteness, captured in
  ``ConformanceReport.errored_categories``).
- Fail findings carry stable field-path prefixes (``manifest.<path>: <reason>``)
  for examiner-traceability.
- The :data:`_APPLICABILITY` matrix is the examiner-visible declaration of
  which checks apply to which pack kinds; the runner short-circuits to
  ``not_applicable`` BEFORE invoking a check body when the kind is not in the
  category's applicability set.
- Yellow takes precedence over red: an incomplete suite (any checker raised)
  means the red/green verdict is not trustworthy.

Wire-protocol-public per ADR-006 — the 10-value :data:`OWASPCheckCategory`
Literal + the :class:`ConformanceReport` field shape are consumed by T9 chain-
payload writers + 7B.3 reviewer evidence + evidence-pack export readers.

Input shape per plan §1037: callers pass the parsed manifest dict (NOT a
``PackRecord`` — the full manifest is not persisted server-side in 7B.1).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from cognic_agentos.packs.conformance.checks import (
    ConformanceCheckResult,
    ConformanceCheckStatus,
    ConformanceOverallStatus,
    ConformanceReport,
    OWASPCheckCategory,
)

# ---------------------------------------------------------------------------
# Shared helpers (kept inline per user lock — no dependency on cli/validators).
# ---------------------------------------------------------------------------

_AUTHOR_FILL_PREFIX = "AUTHOR-FILL"


def _status_from_findings(findings: list[str]) -> ConformanceCheckStatus:
    """Return ``"fail"`` if any findings, ``"pass"`` otherwise.

    Used by every check to derive its pass/fail status from the accumulated
    findings list. The explicit ``ConformanceCheckStatus`` return type narrows
    the ternary's inferred ``str`` back to the closed-enum Literal so
    ``ConformanceCheckResult(status=...)`` type-checks at each call site
    without per-site casts."""
    return "fail" if findings else "pass"


def _is_missing_or_placeholder(value: Any) -> bool:
    """Mirror of ``cli/validators/identity._is_missing_or_placeholder``.

    Duplicated inline rather than imported per the user-locked T8 contract:
    the identity validator is CLI-shaped (``Path`` argument + CLI-only refusal
    enums) and a conformance-runtime → CLI dependency would inject build-time
    plumbing into a runtime path."""
    if not isinstance(value, str):
        return True
    stripped = value.strip()
    if not stripped:
        return True
    return stripped.startswith(_AUTHOR_FILL_PREFIX)


def _resolve_dual_path(
    manifest: dict[str, Any],
    canonical: str,
    legacy: tuple[str, ...],
) -> dict[str, Any] | None:
    """Dual-path block lookup per the Sprint-7A R23 doctrine.

    Tries the canonical top-level key first (``manifest[canonical]``); falls back
    to the legacy ``[tool.cognic.<canonical>]`` shape. Returns the first dict
    found, or ``None`` if neither path resolves to a dict."""
    block = manifest.get(canonical)
    if isinstance(block, dict):
        return block
    cursor: Any = manifest
    for segment in legacy:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(segment)
    return cursor if isinstance(cursor, dict) else None


def _pack_kind(manifest: dict[str, Any]) -> str | None:
    """Return ``[pack].kind`` as a string (or ``None`` if missing / non-string)."""
    pack_block = manifest.get("pack")
    if not isinstance(pack_block, dict):
        return None
    kind = pack_block.get("kind")
    return kind if isinstance(kind, str) else None


# ---------------------------------------------------------------------------
# Closed-vocabulary constants shared across checks.
# ---------------------------------------------------------------------------

_VALID_PACK_KINDS = frozenset({"tool", "skill", "agent", "hook"})

#: Canonical ADR-014 risk-tier vocabulary (8 values, single-sourced at
#: ``cli/_governance_vocab.py:117`` as the ``RiskTier`` Literal). Sprint-
#: 7B.2 R45 corrected an earlier T8 seed of the 3-value
#: ``{"low", "medium", "high"}`` set which diverged from ADR-014's
#: canonical authority ordering. Drift between this set and the
#: ``RiskTier`` Literal is pinned by
#: ``tests/unit/packs/conformance/test_owasp_risk_tier_vocab_drift.py``
#: — the test imports both surfaces and asserts they match
#: ``frozenset(typing.get_args(RiskTier))``; production code here MUST
#: NOT import from ``cognic_agentos.cli`` (the architectural arrow
#: runs cli → packs, not the reverse), so the values are inlined
#: here and the test enforces lockstep across the two source files.
_VALID_RISK_TIERS = frozenset(
    {
        "read_only",
        "internal_write",
        "customer_data_read",
        "customer_data_write",
        "payment_action",
        "regulator_communication",
        "cross_tenant",
        "high_risk_custom",
    }
)

# Injection-style escape sequences scanned by check_goal_hijacking +
# check_prompt_injected_skills. Pattern list is intentionally narrow:
# documented chat-template tokens + zero-width chars + ANSI escapes + the
# canonical "ignore previous" override phrase.
_INJECTION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE), "ignore-previous"),
    (re.compile(r"<\|im_start\|>"), "im_start-token"),
    (re.compile(r"<\|im_end\|>"), "im_end-token"),
    (re.compile(r"<\|endoftext\|>"), "endoftext-token"),
    (re.compile("​"), "zero-width-space"),
    (re.compile(r"\x1b\["), "ansi-escape"),
)

# Sensitive data classes (lowercase) that trigger the DLP-hook requirement
# in check_secret_exfiltration. Intentionally narrow — must match common
# banking-domain class names; future sprints may extend per-vocabulary doctrine.
_SENSITIVE_DATA_CLASSES = frozenset({"pii", "pci", "phi", "secret", "credential", "token"})

# Filesystem path patterns rejected by check_unsafe_filesystem.
_UNSAFE_FS_EXACT_PATHS = frozenset({"/", "/etc", "/home", "/root", "/var", "/usr", "/tmp", "~"})
_UNSAFE_FS_PATH_PREFIXES = ("/etc/", "/root/", "/home/", "/var/", "/usr/", "~/")


# ---------------------------------------------------------------------------
# OWASP A1 — Tool misuse.
# ---------------------------------------------------------------------------


def check_tool_misuse(manifest: dict[str, Any]) -> ConformanceCheckResult:
    """OWASP A1 — pack declares tools / capabilities that match its declared
    kind + risk tier per ADR-014.

    Manifest-shape probes (T8 user lock):

    1. ``manifest.pack.kind`` must exist and be one of
       ``{"tool", "skill", "agent", "hook"}``.
    2. ``manifest.risk_tier.tier`` must exist and be one of the
       canonical ADR-014 8-value ``RiskTier`` set (``read_only``
       through ``high_risk_custom``). Sprint-7B.2 R45 corrected an
       earlier T8 seed of the 3-value ``{"low", "medium", "high"}``
       set which diverged from ADR-014's canonical authority ordering;
       the drift detector at
       ``tests/unit/packs/conformance/test_owasp_risk_tier_vocab_drift.py``
       now pins lockstep with ``cli/_governance_vocab.RiskTier``.
    3. ``manifest.mcp`` block declaration MUST NOT appear on a non-tool pack
       (cross-kind constraint; mirrors the Sprint-7A2 hook-pack
       ``hook_pack_kind_constraint_violated`` refusal pattern).
    """
    findings: list[str] = []

    pack_kind = _pack_kind(manifest)
    if pack_kind is None or pack_kind not in _VALID_PACK_KINDS:
        findings.append(
            f"manifest.pack.kind: must be one of {sorted(_VALID_PACK_KINDS)} (got {pack_kind!r})"
        )

    risk_tier_block = _resolve_dual_path(manifest, "risk_tier", ("tool", "cognic", "risk_tier"))
    if risk_tier_block is None:
        findings.append("manifest.risk_tier: block missing — required per ADR-014 §risk_tier")
    else:
        tier = risk_tier_block.get("tier")
        if not isinstance(tier, str) or tier not in _VALID_RISK_TIERS:
            findings.append(
                f"manifest.risk_tier.tier: must be one of "
                f"{sorted(_VALID_RISK_TIERS)} (got {tier!r})"
            )

    mcp_block = _resolve_dual_path(manifest, "mcp", ("tool", "cognic", "mcp"))
    if mcp_block is not None and pack_kind in {"skill", "agent", "hook"}:
        findings.append(
            f"manifest.mcp: [mcp] block declared on non-tool pack "
            f"(kind={pack_kind!r}); MCP server capability is tool-pack-only per "
            "ADR-002 amendment"
        )

    status = _status_from_findings(findings)
    return ConformanceCheckResult(category="tool_misuse", status=status, findings=findings)


# ---------------------------------------------------------------------------
# OWASP A2 — Goal hijacking (prompt-injection escape-sequence scan).
# ---------------------------------------------------------------------------


def _collect_prompts(manifest: dict[str, Any]) -> list[tuple[str, str]]:
    """Walk known prompt-bearing manifest paths, return ``(field_path, text)``
    pairs for each prompt string found. Used by check_goal_hijacking +
    check_prompt_injected_skills."""
    out: list[tuple[str, str]] = []
    identity = _resolve_dual_path(manifest, "identity", ("tool", "cognic", "identity"))
    if isinstance(identity, dict):
        for field in ("system_prompt", "instructions"):
            value = identity.get(field)
            if isinstance(value, str):
                out.append((f"manifest.identity.{field}", value))
    agent = manifest.get("agent")
    if isinstance(agent, dict):
        for field in ("system_prompt", "instructions", "prompt"):
            value = agent.get(field)
            if isinstance(value, str):
                out.append((f"manifest.agent.{field}", value))
    skills = manifest.get("skills")
    if isinstance(skills, list):
        for i, skill in enumerate(skills):
            if not isinstance(skill, dict):
                continue
            for field in ("prompt", "description", "instructions"):
                value = skill.get(field)
                if isinstance(value, str):
                    out.append((f"manifest.skills[{i}].{field}", value))
    return out


def check_goal_hijacking(manifest: dict[str, Any]) -> ConformanceCheckResult:
    """OWASP A2 — manifest's prompt / system-prompt declarations don't contain
    injection-style escape sequences.

    Manifest-shape probes (T8 user lock): scan every prompt-bearing field for the
    documented injection patterns (chat-template tokens, zero-width space,
    ANSI escape, ``IGNORE PREVIOUS INSTRUCTIONS``). Not-applicable when no
    prompt field is declared anywhere in the manifest."""
    prompts = _collect_prompts(manifest)
    if not prompts:
        return ConformanceCheckResult(
            category="goal_hijacking",
            status="not_applicable",
            findings=["no prompt fields declared in manifest"],
        )

    findings: list[str] = []
    for field_path, text in prompts:
        for pattern, label in _INJECTION_PATTERNS:
            if pattern.search(text):
                findings.append(f"{field_path}: injection-style pattern detected ({label})")
                break  # one finding per field

    status = _status_from_findings(findings)
    return ConformanceCheckResult(category="goal_hijacking", status=status, findings=findings)


# ---------------------------------------------------------------------------
# OWASP A3 — Identity abuse (manifest-shape duplicate of identity validator).
# ---------------------------------------------------------------------------

#: Mirror of ``cli/validators/identity._UNIVERSAL_MANDATORY_FIELDS``. Duplicated
#: inline per the user-locked T8 contract — the CLI validator's tuple also
#: carries CLI-only refusal reason codes which are not part of the conformance
#: wire-protocol.
_IDENTITY_MANDATORY_FIELDS: tuple[str, ...] = (
    "agent_id",
    "display_name",
    "provider_organization",
    "provider_url",
)


def check_identity_abuse(manifest: dict[str, Any]) -> ConformanceCheckResult:
    """OWASP A3 — manifest's ``[identity]`` block fields are well-formed.

    T8 user-locked contract: duplicates the small mandatory-field shape subset of
    ``cli/validators/identity.py`` inline. Full validator (with JWS file
    resolution + Wave-1 agent-only branches) runs at build/admission time.
    """
    identity = _resolve_dual_path(manifest, "identity", ("tool", "cognic", "identity"))
    if identity is None:
        return ConformanceCheckResult(
            category="identity_abuse",
            status="fail",
            findings=["manifest.identity: block missing"],
        )

    findings: list[str] = []
    for field in _IDENTITY_MANDATORY_FIELDS:
        if _is_missing_or_placeholder(identity.get(field)):
            findings.append(
                f"manifest.identity.{field}: missing, AUTHOR-FILL placeholder, or empty string"
            )

    status = _status_from_findings(findings)
    return ConformanceCheckResult(category="identity_abuse", status=status, findings=findings)


# ---------------------------------------------------------------------------
# OWASP A4 — Prompt-injected skills (skill-pack-only).
# ---------------------------------------------------------------------------


def check_prompt_injected_skills(
    manifest: dict[str, Any],
) -> ConformanceCheckResult:
    """OWASP A4 — skill packs declare inputs that pass syntactic injection-
    pattern checks.

    Not-applicable for non-skill packs (The :data:`_APPLICABILITY` matrix formalises the 4-kind
    applicability matrix)."""
    pack_kind = _pack_kind(manifest)
    if pack_kind != "skill":
        return ConformanceCheckResult(
            category="prompt_injected_skills",
            status="not_applicable",
            findings=[f"pack kind {pack_kind!r} has no skill surface"],
        )

    skills = manifest.get("skills")
    if not isinstance(skills, list) or not skills:
        return ConformanceCheckResult(
            category="prompt_injected_skills",
            status="not_applicable",
            findings=["no skills declared"],
        )

    findings: list[str] = []
    for i, skill in enumerate(skills):
        if not isinstance(skill, dict):
            continue
        for field in ("prompt", "description", "instructions"):
            value = skill.get(field)
            if not isinstance(value, str):
                continue
            for pattern, label in _INJECTION_PATTERNS:
                if pattern.search(value):
                    findings.append(
                        f"manifest.skills[{i}].{field}: injection-style pattern detected ({label})"
                    )
                    break

    status = _status_from_findings(findings)
    return ConformanceCheckResult(
        category="prompt_injected_skills", status=status, findings=findings
    )


# ---------------------------------------------------------------------------
# OWASP A5 — Dependency poisoning (declaration shape; no digest recompute).
# ---------------------------------------------------------------------------

_PINNED_VERSION_PREFIXES: tuple[str, ...] = ("==", "~=")
_DEPENDENCY_PROVENANCE_FIELDS: tuple[str, ...] = ("digest", "hash", "provenance")


def _resolve_dependencies_list(manifest: dict[str, Any]) -> list[Any] | None:
    """Resolve the dependencies list from either top-level ``[dependencies]`` or
    nested ``[pack].dependencies``. Returns ``None`` if neither shape is a list."""
    deps = manifest.get("dependencies")
    if isinstance(deps, list):
        return deps
    pack_block = manifest.get("pack")
    if isinstance(pack_block, dict):
        nested = pack_block.get("dependencies")
        if isinstance(nested, list):
            return nested
    return None


def check_dependency_poisoning(manifest: dict[str, Any]) -> ConformanceCheckResult:
    """OWASP A5 — manifest declares dependencies with pinned versions + a
    declared digest/hash/provenance field.

    Per T8 user lock: declaration shape ONLY. T8 does not recompute
    artefact digests; that is T9 storage-side concern.
    """
    deps = _resolve_dependencies_list(manifest)
    if deps is None or not deps:
        return ConformanceCheckResult(
            category="dependency_poisoning",
            status="not_applicable",
            findings=["no [dependencies] declared"],
        )

    findings: list[str] = []
    for i, dep in enumerate(deps):
        if not isinstance(dep, dict):
            findings.append(
                f"manifest.dependencies[{i}]: must be a dict (got {type(dep).__name__})"
            )
            continue
        name = dep.get("name")
        if not isinstance(name, str) or not name.strip():
            findings.append(f"manifest.dependencies[{i}].name: missing or empty string")
        version = dep.get("version")
        if not isinstance(version, str) or not any(
            version.startswith(p) for p in _PINNED_VERSION_PREFIXES
        ):
            findings.append(
                f"manifest.dependencies[{i}].version: must be pinned "
                f"(prefix '==' or '~='); got {version!r}"
            )
        has_provenance = any(dep.get(k) for k in _DEPENDENCY_PROVENANCE_FIELDS)
        if not has_provenance:
            findings.append(f"manifest.dependencies[{i}]: missing digest/hash/provenance field")

    status = _status_from_findings(findings)
    return ConformanceCheckResult(category="dependency_poisoning", status=status, findings=findings)


# ---------------------------------------------------------------------------
# OWASP A6 — Secret exfiltration (egress allow-list + DLP hooks).
# ---------------------------------------------------------------------------


def check_secret_exfiltration(manifest: dict[str, Any]) -> ConformanceCheckResult:
    """OWASP A6 — manifest's ``[data_governance].egress_allow_list`` is non-empty
    + DLP hooks declared for sensitive data classes per Sprint 7A2
    ``cli/validators/data_governance.py``.

    Manifest-shape probes (T8 user lock):

    1. ``egress_allow_list`` is a non-empty list (drift would let any host be
       exfiltrated to under the DLP path).
    2. When ``data_classes`` includes a sensitive class
       (``{pii, pci, phi, secret, credential, token}``), at least one of
       ``dlp_pre_hooks`` / ``dlp_post_hooks`` MUST be a non-empty list.
    """
    gov = _resolve_dual_path(manifest, "data_governance", ("tool", "cognic", "data_governance"))
    if gov is None:
        return ConformanceCheckResult(
            category="secret_exfiltration",
            status="not_applicable",
            findings=["no [data_governance] block declared"],
        )

    findings: list[str] = []
    egress = gov.get("egress_allow_list")
    if not isinstance(egress, list) or not egress:
        findings.append("manifest.data_governance.egress_allow_list: must be a non-empty list")

    data_classes = gov.get("data_classes")
    sensitive: list[str] = []
    if isinstance(data_classes, list):
        sensitive = [
            c for c in data_classes if isinstance(c, str) and c.lower() in _SENSITIVE_DATA_CLASSES
        ]
    if sensitive:
        dlp_pre = gov.get("dlp_pre_hooks")
        dlp_post = gov.get("dlp_post_hooks")
        has_dlp = (isinstance(dlp_pre, list) and len(dlp_pre) > 0) or (
            isinstance(dlp_post, list) and len(dlp_post) > 0
        )
        if not has_dlp:
            findings.append(
                f"manifest.data_governance: sensitive data_classes "
                f"{sensitive!r} declared but no dlp_pre_hooks or dlp_post_hooks"
            )

    status = _status_from_findings(findings)
    return ConformanceCheckResult(category="secret_exfiltration", status=status, findings=findings)


# ---------------------------------------------------------------------------
# OWASP A7 — Unsafe filesystem (sandbox boundary per ADR-004).
# ---------------------------------------------------------------------------


def _is_unsafe_fs_path(path: str) -> tuple[bool, str | None]:
    """Return ``(is_unsafe, reason_label)`` for a filesystem path.

    Reason labels: ``"wildcard"`` for ``*``/``**`` in path; ``"root-path"`` for
    exact system roots; ``"system-prefix"`` for prefixes like ``/etc/``."""
    if "**" in path or "*" in path:
        return True, "wildcard"
    if path in _UNSAFE_FS_EXACT_PATHS:
        return True, "root-path"
    for prefix in _UNSAFE_FS_PATH_PREFIXES:
        if path.startswith(prefix):
            return True, "system-prefix"
    return False, None


def check_unsafe_filesystem(manifest: dict[str, Any]) -> ConformanceCheckResult:
    """OWASP A7 — manifest does not declare filesystem-read or filesystem-write
    capabilities outside the sandbox profile from ADR-004.

    Manifest-shape probes (T8 user lock): scan
    ``manifest.{permissions,capabilities}.filesystem.{read_paths,write_paths}``
    for wildcards or system-root paths."""
    fs_blocks: list[tuple[str, dict[str, Any]]] = []
    for parent_name in ("permissions", "capabilities"):
        parent = manifest.get(parent_name)
        if isinstance(parent, dict):
            fs = parent.get("filesystem")
            if isinstance(fs, dict):
                fs_blocks.append((f"manifest.{parent_name}.filesystem", fs))

    if not fs_blocks:
        return ConformanceCheckResult(category="unsafe_filesystem", status="pass", findings=[])

    findings: list[str] = []
    for prefix, fs in fs_blocks:
        for direction in ("read_paths", "write_paths"):
            paths = fs.get(direction)
            if not isinstance(paths, list):
                continue
            for j, p in enumerate(paths):
                if not isinstance(p, str):
                    continue
                unsafe, reason = _is_unsafe_fs_path(p)
                if unsafe:
                    findings.append(f"{prefix}.{direction}[{j}]: unsafe path ({reason}): {p!r}")

    status = _status_from_findings(findings)
    return ConformanceCheckResult(category="unsafe_filesystem", status=status, findings=findings)


# ---------------------------------------------------------------------------
# OWASP A8 — Unsafe network.
# ---------------------------------------------------------------------------


def check_unsafe_network(manifest: dict[str, Any]) -> ConformanceCheckResult:
    """OWASP A8 — manifest's network egress declarations match the
    ``[data_governance].egress_allow_list``.

    Manifest-shape probes (T8 user lock):

    1. ``manifest.{permissions,capabilities}.network.egress`` MUST NOT be ``"*"``
       (string) or contain ``"*"`` in a list form.
    2. ``manifest.{permissions,capabilities}.network.wildcard`` MUST NOT be
       ``True``.
    3. When ``[data_governance].egress_allow_list`` is declared, every host in
       ``network.egress`` (list form) MUST appear in the allow-list.
    """
    findings: list[str] = []

    gov = _resolve_dual_path(manifest, "data_governance", ("tool", "cognic", "data_governance"))
    declared_egress: list[str] = []
    if isinstance(gov, dict):
        allow = gov.get("egress_allow_list")
        if isinstance(allow, list):
            declared_egress = [e for e in allow if isinstance(e, str)]

    network_blocks: list[tuple[str, dict[str, Any]]] = []
    for parent_name in ("permissions", "capabilities"):
        parent = manifest.get(parent_name)
        if isinstance(parent, dict):
            net = parent.get("network")
            if isinstance(net, dict):
                network_blocks.append((f"manifest.{parent_name}.network", net))

    if not network_blocks:
        return ConformanceCheckResult(category="unsafe_network", status="pass", findings=[])

    for prefix, net in network_blocks:
        egress_val = net.get("egress")
        if egress_val == "*":
            findings.append(f"{prefix}.egress: wildcard egress is not allowed")
        elif isinstance(egress_val, list):
            if "*" in egress_val:
                findings.append(
                    f"{prefix}.egress: wildcard egress is not allowed (found '*' in list)"
                )
            if declared_egress:
                for j, host in enumerate(egress_val):
                    if host == "*":
                        continue  # already flagged above
                    if isinstance(host, str) and host not in declared_egress:
                        findings.append(
                            f"{prefix}.egress[{j}]: host {host!r} not in "
                            "manifest.data_governance.egress_allow_list"
                        )
        if net.get("wildcard") is True:
            findings.append(f"{prefix}.wildcard: wildcard network access is not allowed")

    status = _status_from_findings(findings)
    return ConformanceCheckResult(category="unsafe_network", status=status, findings=findings)


# ---------------------------------------------------------------------------
# OWASP A9 — Supply-chain integrity (declaration shape only per user lock).
# ---------------------------------------------------------------------------


def check_supply_chain_integrity(
    manifest: dict[str, Any],
) -> ConformanceCheckResult:
    """OWASP A9 — Sprint 7A ``cli/validators/supply_chain.py`` attestation
    paths are non-empty + reachable.

    T8 user lock: declaration shape ONLY. The CLI validator owns the
    file-existence + path-traversal checks at build time; conformance runtime
    duplicates only the manifest-shape subset.
    """
    sc = _resolve_dual_path(manifest, "supply_chain", ("tool", "cognic", "supply_chain"))
    if sc is None:
        return ConformanceCheckResult(
            category="supply_chain_integrity",
            status="fail",
            findings=["manifest.supply_chain: block missing"],
        )

    findings: list[str] = []
    paths = sc.get("attestation_paths")
    if not isinstance(paths, list):
        findings.append(
            f"manifest.supply_chain.attestation_paths: must be a list (got {type(paths).__name__})"
        )
    elif not paths:
        findings.append("manifest.supply_chain.attestation_paths: must be a non-empty list")
    else:
        for j, p in enumerate(paths):
            if not isinstance(p, str) or not p.strip():
                findings.append(
                    f"manifest.supply_chain.attestation_paths[{j}]: must be a non-empty string"
                )

    status = _status_from_findings(findings)
    return ConformanceCheckResult(
        category="supply_chain_integrity", status=status, findings=findings
    )


# ---------------------------------------------------------------------------
# OWASP composite — Agentic Skills Top 10 (4 named sub-probes per user lock).
# ---------------------------------------------------------------------------


def _check_skill_subprobes(skill: dict[str, Any], idx: int) -> list[str]:
    """Run the 4 named sub-probes per user lock on a single skill entry.

    Returns a list of finding strings (empty list = all sub-probes passed).
    Each finding uses the ``manifest.skills[<idx>].<subprobe>:`` field-path
    prefix so a single bad skill surfaces multiple distinct findings."""
    findings: list[str] = []

    # Sub-probe 1: prompt_isolation MUST be True.
    if skill.get("prompt_isolation") is not True:
        findings.append(
            f"manifest.skills[{idx}].prompt_isolation: must be true "
            f"(got {skill.get('prompt_isolation')!r})"
        )

    # Sub-probe 2: tool_allowlist MUST be a list, MUST NOT contain '*'.
    tool_allowlist = skill.get("tool_allowlist")
    if not isinstance(tool_allowlist, list):
        findings.append(
            f"manifest.skills[{idx}].tool_allowlist: must be a list "
            f"(got {type(tool_allowlist).__name__})"
        )
    elif "*" in tool_allowlist:
        findings.append(f"manifest.skills[{idx}].tool_allowlist: wildcard '*' is not allowed")

    # Sub-probe 3: secret_access MUST be False OR a non-empty list of strings.
    secret_access = skill.get("secret_access")
    secret_access_valid = secret_access is False or (
        isinstance(secret_access, list)
        and len(secret_access) > 0
        and all(isinstance(s, str) and s for s in secret_access)
    )
    if not secret_access_valid:
        findings.append(
            f"manifest.skills[{idx}].secret_access: must be false or a "
            "non-empty list of secret names"
        )

    # Sub-probe 4: network_policy MUST be 'deny' OR a non-empty string that
    # is not 'allow_all'.
    net_policy = skill.get("network_policy")
    net_policy_valid = net_policy == "deny" or (
        isinstance(net_policy, str) and len(net_policy) > 0 and net_policy != "allow_all"
    )
    if not net_policy_valid:
        findings.append(
            f"manifest.skills[{idx}].network_policy: must be 'deny' or a "
            f"specific policy name (not 'allow_all'); got {net_policy!r}"
        )

    return findings


def check_skills_top_10(manifest: dict[str, Any]) -> ConformanceCheckResult:
    """Agentic Skills Top 10 — composite skill-pack-specific check.

    Per T8 user lock: ONE check function with four named internal
    sub-probes:

    - ``manifest.skills[].prompt_isolation``
    - ``manifest.skills[].tool_allowlist``
    - ``manifest.skills[].secret_access``
    - ``manifest.skills[].network_policy``

    Sub-checks are NOT exposed as separate OWASP categories — only the composite
    ``skills_top_10`` category appears in :data:`OWASPCheckCategory`.
    """
    pack_kind = _pack_kind(manifest)
    if pack_kind != "skill":
        return ConformanceCheckResult(
            category="skills_top_10",
            status="not_applicable",
            findings=[f"pack kind {pack_kind!r} has no skills surface"],
        )

    skills = manifest.get("skills")
    if not isinstance(skills, list) or not skills:
        return ConformanceCheckResult(
            category="skills_top_10",
            status="not_applicable",
            findings=["no skills declared"],
        )

    findings: list[str] = []
    for i, skill in enumerate(skills):
        if not isinstance(skill, dict):
            findings.append(f"manifest.skills[{i}]: must be a dict (got {type(skill).__name__})")
            continue
        findings.extend(_check_skill_subprobes(skill, i))

    status = _status_from_findings(findings)
    return ConformanceCheckResult(category="skills_top_10", status=status, findings=findings)


# ---------------------------------------------------------------------------
# Runner — composite report assembly (applicability matrix + yellow precedence).
# ---------------------------------------------------------------------------

_CheckFn = Callable[[dict[str, Any]], ConformanceCheckResult]

_CHECK_REGISTRY: tuple[tuple[OWASPCheckCategory, _CheckFn], ...] = (
    ("tool_misuse", check_tool_misuse),
    ("goal_hijacking", check_goal_hijacking),
    ("identity_abuse", check_identity_abuse),
    ("prompt_injected_skills", check_prompt_injected_skills),
    ("dependency_poisoning", check_dependency_poisoning),
    ("secret_exfiltration", check_secret_exfiltration),
    ("unsafe_filesystem", check_unsafe_filesystem),
    ("unsafe_network", check_unsafe_network),
    ("supply_chain_integrity", check_supply_chain_integrity),
    ("skills_top_10", check_skills_top_10),
)
"""Ordered registry — 1:1 with :data:`OWASPCheckCategory` literal order.

The runner iterates this tuple in declaration order; ``ConformanceReport.results``
key-iteration AND ``errored_categories`` tuple order both inherit from this
ordering per the T8 user lock ("preserve _CHECK_REGISTRY /
OWASPCheckCategory order for report results and errored_categories")."""


_ALL_KINDS: frozenset[str] = frozenset({"tool", "skill", "agent", "hook"})

_APPLICABILITY: dict[OWASPCheckCategory, frozenset[str]] = {
    "tool_misuse": _ALL_KINDS,
    "goal_hijacking": frozenset({"agent", "skill"}),
    "identity_abuse": _ALL_KINDS,
    "prompt_injected_skills": frozenset({"skill"}),
    "dependency_poisoning": _ALL_KINDS,
    "secret_exfiltration": _ALL_KINDS,
    # ADR-004 — hook packs have no filesystem surface (their dispatch runtime
    # never touches FS); the FS check is meaningless for them.
    "unsafe_filesystem": frozenset({"tool", "skill", "agent"}),
    "unsafe_network": _ALL_KINDS,
    "supply_chain_integrity": _ALL_KINDS,
    "skills_top_10": frozenset({"skill"}),
}
"""Per-pack-kind applicability matrix (T8 user lock).

The runner consults this table BEFORE invoking each check. When ``pack.kind``
resolves to a known kind AND that kind is NOT in the category's applicability
set, the runner synthesises a ``not_applicable`` result without calling the
check body. The matrix is examiner-readable from this static table — T9 chain
payload consumers + 7B.3 reviewers can predict which checks will be N/A for a
given pack kind without running the suite.

When ``pack.kind`` is missing / unknown / not-a-string, the matrix gate
short-circuits OFF and every check body runs (the bodies handle their own
N/A logic + ``check_tool_misuse`` surfaces the missing-kind as ``fail``).
"""


def _derive_overall_status(
    results: dict[OWASPCheckCategory, ConformanceCheckResult],
    errored_categories: tuple[OWASPCheckCategory, ...],
) -> ConformanceOverallStatus:
    """Composite-status derivation per the T8 user-locked precedence:

    1. ``yellow`` — at least one checker raised (``errored_categories`` non-empty).
       Yellow takes precedence over red because a checker exception means the
       suite is incomplete and the red/green verdict is not trustworthy.
    2. ``red`` — no errored AND at least one check returned ``fail``.
    3. ``green`` — no errored AND every check returned ``pass`` or
       ``not_applicable``.
    """
    if errored_categories:
        return "yellow"
    if any(r.status == "fail" for r in results.values()):
        return "red"
    return "green"


def _format_summary(
    results: dict[OWASPCheckCategory, ConformanceCheckResult],
    errored_categories: tuple[OWASPCheckCategory, ...],
) -> str:
    """Format the per-status count summary string.

    Stable shape: ``"<P> pass / <F> fail / <N> not_applicable"`` always; when
    ``errored_categories`` is non-empty an ``" (<E> errored)"`` suffix is
    appended so human readers see the incompleteness signal alongside the
    counts. The errored count is a SUBSET of the N count (each errored result
    carries ``status="not_applicable"`` per the T8 user-locked synthetic
    shape), so the suffix is informational — examiners reading the structured
    ``ConformanceReport.errored_categories`` get the authoritative list.

    T9 + 7B.3 examiners consume this on the chain payload's
    ``payload.conformance.summary``."""
    counts = {"pass": 0, "fail": 0, "not_applicable": 0}
    for r in results.values():
        counts[r.status] += 1
    summary = (
        f"{counts['pass']} pass / {counts['fail']} fail / {counts['not_applicable']} not_applicable"
    )
    if errored_categories:
        summary += f" ({len(errored_categories)} errored)"
    return summary


def _synthesise_not_applicable_from_matrix(
    category: OWASPCheckCategory, pack_kind: str
) -> ConformanceCheckResult:
    """Build the matrix short-circuit result for a non-applicable (category, kind).

    Wire-shape: finding uses the ``manifest.pack.kind:`` field-path
    prefix so the cross-check finding-format invariant is preserved
    (``manifest.<path>: <reason>``)."""
    return ConformanceCheckResult(
        category=category,
        status="not_applicable",
        findings=[
            f"manifest.pack.kind: check {category!r} does not apply to pack kind {pack_kind!r}"
        ],
    )


def _synthesise_not_applicable_from_exception(
    category: OWASPCheckCategory, exc: BaseException
) -> ConformanceCheckResult:
    """Build the synthetic result for a checker that raised during dispatch.

    Per the T8 user lock: ``status="not_applicable"`` (the per-check enum
    is preserved at 3 values; yellow lives on the composite report) and the
    finding is the user-locked exact format
    ``"manifest: <category> checker raised <ExcType>: <message>"``."""
    return ConformanceCheckResult(
        category=category,
        status="not_applicable",
        findings=[f"manifest: {category} checker raised {type(exc).__name__}: {exc}"],
    )


def run_owasp_conformance(manifest: dict[str, Any]) -> ConformanceReport:
    """Dispatch every OWASP check and assemble a :class:`ConformanceReport`.

    **T8 user-locked contract:**

    1. Resolve ``pack.kind`` once via :func:`_pack_kind`.
    2. For each ``(category, check)`` in :data:`_CHECK_REGISTRY` (registry order
       preserved per user lock):

       a. **Applicability gate** — when ``pack_kind`` is one of the 4 known
          kinds AND ``pack_kind not in _APPLICABILITY[category]``: synthesise
          a ``not_applicable`` result via
          :func:`_synthesise_not_applicable_from_matrix` and skip the body.
       b. **Body invocation under try/except** — call ``check(manifest)``. On
          ANY exception: synthesise a ``not_applicable`` result via
          :func:`_synthesise_not_applicable_from_exception` and append the
          category to ``errored_categories``.

    3. Derive ``overall_status`` per the user-locked precedence: ``yellow`` if
       any errored; else ``red`` if any fail; else ``green``.
    4. Format the summary (with optional ``(N errored)`` suffix when applicable).
    """
    results: dict[OWASPCheckCategory, ConformanceCheckResult] = {}
    errored: list[OWASPCheckCategory] = []
    pack_kind = _pack_kind(manifest)

    for category, check in _CHECK_REGISTRY:
        if (
            isinstance(pack_kind, str)
            and pack_kind in _ALL_KINDS
            and pack_kind not in _APPLICABILITY[category]
        ):
            results[category] = _synthesise_not_applicable_from_matrix(category, pack_kind)
            continue
        try:
            results[category] = check(manifest)
        except Exception as exc:  # runner is the last-line wrapper per T8 lock
            results[category] = _synthesise_not_applicable_from_exception(category, exc)
            errored.append(category)

    errored_categories = tuple(errored)
    overall_status = _derive_overall_status(results, errored_categories)
    summary = _format_summary(results, errored_categories)
    return ConformanceReport(
        overall_status=overall_status,
        results=results,
        summary=summary,
        errored_categories=errored_categories,
    )
