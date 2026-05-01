"""Per-file coverage gate for critical-controls modules.

Reads ``coverage.json`` (produced by ``pytest --cov-report=json``)
and asserts that EACH listed file independently meets the coverage
threshold. Replaces the combined ``--cov-fail-under=95`` shape that
masks an under-covered file behind a well-covered sibling in the
same target set.

Usage:

    uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json
    uv run python tools/check_critical_coverage.py

Exits 0 if every critical file meets its line + branch thresholds,
1 otherwise. Prints a per-file summary so CI logs are scannable.

Per AGENTS.md amendment in PR #5: ``core/audit.py``,
``core/decision_history.py``, ``core/chain_verifier.py``, and
``core/canonical.py`` are the four critical-controls modules of
Sprint 2. Each one carries ``95%+ line + ≥90% branch`` per the plan;
this script enforces that as a CI gate. Sprint 2.5 added the SLA /
escalation / guardrails triplet at the same floor. Sprint 3 T11
extends the gate to the LLM-gateway-shape quintet (gateway, policy,
preflight, ledger, concurrency) at the same single strict floor —
all five sit on the cloud-policy / provider-honesty path that
ADR-007's authoritativeness contract depends on, and the rate-limit
primitive is small and stable enough to ride the strict gate without
churn. Sprint 4 T15 extends the gate further with the plugin-trust /
supply-chain / policy quartet — ``protocol/plugin_registry.py`` (the
admission orchestrator), ``protocol/trust_gate.py`` (cosign
subprocess gate per ADR-002), ``protocol/supply_chain.py`` (SLSA +
in-toto + SBOM + vuln + license + Sigstore-bundle persister per
ADR-016), and ``core/policy/engine.py`` (the OPA Rego decision
engine per ADR-015). All four are explicitly named on the AGENTS.md
critical-controls list and ride the same single strict floor; gate
size grows from 12 modules to 16.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

#: Critical files + their thresholds. Each entry: (path, line_floor,
#: branch_floor) — both as ratios in [0, 1]. Path is relative to the
#: repo root (matches the keys coverage.json emits).
_CRITICAL_FILES: tuple[tuple[str, float, float], ...] = (
    # Sprint 2 critical-controls quartet — chain-of-custody substrate.
    ("src/cognic_agentos/core/audit.py", 0.95, 0.90),
    ("src/cognic_agentos/core/canonical.py", 0.95, 0.90),
    ("src/cognic_agentos/core/chain_verifier.py", 0.95, 0.90),
    ("src/cognic_agentos/core/decision_history.py", 0.95, 0.90),
    # Sprint 2.5 critical-controls triplet — operational primitives
    # consuming the Sprint-2 substrate. All three named in AGENTS.md
    # critical-controls list; all three carry the same per-file
    # floors as Sprint 2 (95% line / 90% branch).
    ("src/cognic_agentos/core/sla.py", 0.95, 0.90),
    ("src/cognic_agentos/core/escalation.py", 0.95, 0.90),
    ("src/cognic_agentos/core/guardrails.py", 0.95, 0.90),
    # Sprint 3 T11 — LLM-gateway-shape critical-controls quintet.
    # ``llm/gateway.py`` is explicitly named on the AGENTS.md
    # critical-controls list (cloud-policy enforcer + provider-
    # honesty ledger feed). The other four are co-load-bearing for
    # the same surface and ride the same single strict floor:
    #   * ``policy.py`` is the cloud-policy decision engine the
    #     gateway delegates to — fail-closed denials on provenance
    #     gaps (ADR-007) live here.
    #   * ``preflight.py`` owns LiteLLM-alias → ResolvedUpstream
    #     resolution + the four-state provenance + the api_base-
    #     aware classifier; mis-classifications here become silent
    #     cloud-policy holes.
    #   * ``ledger.py`` is the authoritative writer for
    #     ``/effective-routing`` (ADR-007 §"two layers"); the
    #     "no successful return without persisted ledger row"
    #     contract is enforced here.
    #   * ``concurrency.py`` is the per-profile rate-limiter; small
    #     (~50 stmts) and stable, kept at the strict floor for
    #     consistency rather than carrying an operational tier.
    ("src/cognic_agentos/llm/gateway.py", 0.95, 0.90),
    ("src/cognic_agentos/llm/policy.py", 0.95, 0.90),
    ("src/cognic_agentos/llm/preflight.py", 0.95, 0.90),
    ("src/cognic_agentos/llm/ledger.py", 0.95, 0.90),
    ("src/cognic_agentos/llm/concurrency.py", 0.95, 0.90),
    # Sprint 4 T15 — plugin-trust / supply-chain / policy quartet.
    # All four are explicitly named on the AGENTS.md critical-controls
    # list (per the Sprint-4 ADR-002 / ADR-015 / ADR-016 amendments)
    # and ride the same single strict 95% line / 90% branch floor as
    # the Sprint-2/2.5/3 modules above:
    #   * ``plugin_registry.py`` is the admission orchestrator that
    #     calls every other verifier in sequence and emits the closed-
    #     enum ``RefusalReason`` on any deny path (fail-closed).
    #   * ``trust_gate.py`` is the cosign subprocess gate; the eight
    #     §2 secure-subprocess invariants live here (no shell, list-
    #     form argv, version+regex pinned, timeout, output ignored
    #     for parsing, etc.).
    #   * ``supply_chain.py`` verifies SBOM + SLSA L3+ + in-toto +
    #     vuln + license, then atomically persists the Sigstore bundle
    #     under 7-year retention per ADR-016 §"Retention".
    #   * ``core/policy/engine.py`` is the OPA Rego decision engine;
    #     fail-closed on every engine error path (ADR-015 §"Default-
    #     deny posture").
    ("src/cognic_agentos/protocol/plugin_registry.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/trust_gate.py", 0.95, 0.90),
    ("src/cognic_agentos/protocol/supply_chain.py", 0.95, 0.90),
    ("src/cognic_agentos/core/policy/engine.py", 0.95, 0.90),
)


def main() -> int:
    coverage_json = Path("coverage.json")
    if not coverage_json.exists():
        print(
            "::error::coverage.json not found in CWD. "
            "Run `uv run pytest --cov=cognic_agentos --cov-branch "
            "--cov-report=json` first."
        )
        return 1

    try:
        data = json.loads(coverage_json.read_text())
    except json.JSONDecodeError as exc:
        print(f"::error::failed to parse coverage.json: {exc}")
        return 1

    files = data.get("files", {})
    fail = False

    print("Per-file critical-controls coverage gate")
    print("=" * 72)

    for path, line_floor, branch_floor in _CRITICAL_FILES:
        entry = files.get(path)
        if entry is None:
            print(
                f"[FAIL] {path}: no coverage data — module not exercised "
                f"by the suite (or coverage.json was generated for a "
                f"different scope)"
            )
            print(f"::error file={path}::no coverage data for critical-controls module")
            fail = True
            continue

        summary = entry["summary"]
        # ``percent_covered`` is reported as a percentage, not a ratio.
        line_rate = summary["percent_covered"] / 100.0

        # Branch coverage is reported only when ``--cov-branch`` is
        # passed at run time. Calculate from the underlying counts so
        # this works on every coverage.py version.
        branches_covered = summary.get("covered_branches")
        branches_total = summary.get("num_branches")
        if branches_total is None or branches_total == 0:
            # No branches in this file → branch coverage is trivially 100%.
            branch_rate = 1.0
        else:
            branch_rate = branches_covered / branches_total

        ok_line = line_rate >= line_floor
        ok_branch = branch_rate >= branch_floor
        marker = "PASS" if (ok_line and ok_branch) else "FAIL"
        print(
            f"[{marker}] {path}: "
            f"line={line_rate:.2%} (floor {line_floor:.0%}) "
            f"branch={branch_rate:.2%} (floor {branch_floor:.0%})"
        )

        if not ok_line:
            print(
                f"::error file={path}::line coverage {line_rate:.2%} below floor {line_floor:.0%}"
            )
            fail = True
        if not ok_branch:
            print(
                f"::error file={path}::branch coverage {branch_rate:.2%} "
                f"below floor {branch_floor:.0%}"
            )
            fail = True

    print("=" * 72)
    if fail:
        print("Per-file critical-controls coverage gate: FAILED")
        return 1

    print("Per-file critical-controls coverage gate: passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
