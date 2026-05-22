# Sprint 9 — ISO 42001 Control Mapping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the ISO 42001 control-mapping evidence layer — a control registry, a signed tamper-evident evidence-pack export, two examiner portal endpoints, and honest control-tag coverage (3 ADR-006 controls evidenced canonically, 5 explicitly deferred per the T8 audit) — without modifying any `core/` critical-controls module.

**Architecture:** A new `compliance/iso42001/` package (registry + domain-separated Merkle + cosign signing + evidence-pack exporter) reads `decision_history` / `audit_event` through an injected `AsyncEngine` and the exported `_decision_history` / `_audit_event` Table objects — never touching `core/audit.py`, `core/decision_history.py`, or `core/canonical.py`. Two examiner endpoints ship in a new `portal/api/compliance/` route package; a new `ComplianceRBACScope` family gates them.

**Tech Stack:** Python 3.12, SQLAlchemy async, `cosign` (`sign-blob`), FastAPI, `tarfile`, pytest + pytest-asyncio, `uv`.

**Source spec:** `docs/superpowers/specs/2026-05-21-sprint-9-iso42001-control-mapping-design.md` (committed at `a37d83b`).

---

## Commit discipline

Per-action authorization, halt-before-commit. Each task ends with a **Commit** step
showing the exact command, but the executor MUST produce a halt-before-commit summary
and wait for the human's explicit token before running it. Stage files by **explicit
path** (never `git add -A`). Git identity `bmzee`. No push/PR/merge without a separate
explicit token. T0 (the design spec) is already committed at `a37d83b` on branch
`feat/sprint-9-iso42001-control-mapping`. This plan covers T1–T10.

## Stop-rule / critical-controls flags (read before executing)

- **T4 evidence-pack wire format is an AGENTS.md stop rule** — the `manifest.json`
  schema, the JSONL row shape, the Merkle byte-framing, and the tarball member names
  change how examiners audit. Every T4 halt summary must surface the exact wire shapes.
- **T5 RBAC change is a stop-rule touch across THREE RBAC files** —
  `portal/rbac/scopes.py` (wire-protocol-public — new `ComplianceRBACScope` family),
  `portal/rbac/actor.py` (`Actor.scopes` widens), and `portal/rbac/enforcement.py`
  (`RequireScope` `scope` param widens). The T5 halt summary must call for explicit RBAC
  stop-rule review of all three.
- **T9 reconciles ADR-006 evidence tags across three governance-visible files**
  (rescoped per the T8 audit) — `sandbox/audit.py` (sandbox enforcement boundary),
  `protocol/trust_gate.py` + `protocol/plugin_registry.py` (stop-rule / critical-control
  surfaces). String-only `iso_controls=` raw→canonical edits; the T9 halt summary must
  request explicit human stop-rule review of all three.
- **T10 promotes the 4 new `compliance/iso42001/` runtime modules to the
  critical-controls coverage gate** (95% line / 90% branch); gate count 73 → 77,
  verified against fresh `coverage.json` at promotion time.
- **NO edits to `core/audit.py`, `core/decision_history.py`, `core/canonical.py`.** The
  `iso_controls` field + columns + `append` persistence already exist; Sprint 9 reads
  these modules' exported Table objects but never modifies their source. T9 reconciles
  raw `iso_controls=` tags to canonical form at emission *call sites* in other modules
  (never `core/`).

## File Structure

| File | Created / Modified | Responsibility |
|---|---|---|
| `src/cognic_agentos/compliance/__init__.py` | Created | Package marker. |
| `src/cognic_agentos/compliance/iso42001/__init__.py` | Created | Package marker + public re-exports. |
| `src/cognic_agentos/compliance/iso42001/controls.py` | Created | Control registry — 8 ADR-006 controls, `ComplianceControlId` Literal, coverage helper. **CC-gate at T10.** |
| `src/cognic_agentos/compliance/iso42001/merkle.py` | Created | Domain-separated Merkle tree over chain hashes. **CC-gate at T10.** |
| `src/cognic_agentos/compliance/iso42001/signing.py` | Created | Evidence-pack manifest signing — key resolution + `cosign sign-blob` + fail-loud. **CC-gate at T10.** |
| `src/cognic_agentos/compliance/iso42001/evidence_pack.py` | Created | `export_evidence_pack(...)` orchestrator. **CC-gate at T10.** |
| `src/cognic_agentos/portal/api/compliance/__init__.py` | Created | Package marker. |
| `src/cognic_agentos/portal/api/compliance/evidence_pack_routes.py` | Created | `GET /api/v1/compliance/evidence-pack`. |
| `src/cognic_agentos/portal/api/compliance/trace_routes.py` | Created | `GET /api/v1/traces/{trace_id}`. |
| `src/cognic_agentos/portal/api/compliance/router.py` | Created | Composition factory + the `_require_adapters` request-time dependency. |
| `src/cognic_agentos/core/config.py` | Modified | `evidence_pack_signing_key_path` setting. |
| `src/cognic_agentos/portal/rbac/scopes.py` | Modified | `ComplianceRBACScope` family + `EXAMINER_COMPLIANCE_SCOPES`. **Stop-rule.** |
| `src/cognic_agentos/portal/rbac/actor.py` | Modified | `Actor.scopes` widened to include `ComplianceRBACScope`. **Stop-rule.** |
| `src/cognic_agentos/portal/rbac/enforcement.py` | Modified | `RequireScope` `scope` param widened to accept `ComplianceRBACScope`. **Stop-rule.** |
| `src/cognic_agentos/portal/api/app.py` | Modified | Mount the compliance router. |
| `tools/check_critical_coverage.py` | Modified | Gate 73 → 77 (T10). |
| `sandbox/audit.py`, `protocol/trust_gate.py`, `protocol/plugin_registry.py` | Modified | T9 — raw `iso_controls=` → canonical (3 governance-visible files; stop-rule). |
| `tests/unit/compliance/iso42001/*` | Created | Unit tests (per task). |
| `tests/unit/portal/api/compliance/*` | Created | Endpoint tests. |

---

## Task 1: Control registry — `controls.py`

**Files:**
- Create: `src/cognic_agentos/compliance/__init__.py`, `src/cognic_agentos/compliance/iso42001/__init__.py`, `src/cognic_agentos/compliance/iso42001/controls.py`
- Test: `tests/unit/compliance/__init__.py`, `tests/unit/compliance/iso42001/__init__.py`, `tests/unit/compliance/iso42001/test_control_registry.py`

- [ ] **Step 1: Write the failing test**

Create the four `__init__.py` files empty, then `tests/unit/compliance/iso42001/test_control_registry.py`:

```python
"""Sprint 9 T1 — ISO 42001 control registry."""

from __future__ import annotations

import typing

from cognic_agentos.compliance.iso42001.controls import (
    ISO42001_CONTROLS,
    ComplianceControlId,
    control_ids,
)

_EXPECTED = {
    "ISO42001.A.6.2.5",
    "ISO42001.A.6.2.6",
    "ISO42001.A.7.4",
    "ISO42001.A.7.6",
    "ISO42001.A.8.2",
    "ISO42001.A.8.5",
    "ISO42001.A.9.2",
    "ISO42001.A.10.2",
}


def test_registry_holds_exactly_the_eight_adr006_controls() -> None:
    assert control_ids() == _EXPECTED
    assert len(ISO42001_CONTROLS) == 8


def test_control_id_literal_matches_registry() -> None:
    assert set(typing.get_args(ComplianceControlId)) == _EXPECTED


def test_every_entry_has_canonical_id_display_and_intended_hooks() -> None:
    for entry in ISO42001_CONTROLS:
        assert entry.control_id.startswith("ISO42001.A.")
        assert entry.display == entry.control_id.removeprefix("ISO42001.")
        assert entry.title
        assert entry.intended_hooks  # non-empty tuple
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/compliance/iso42001/test_control_registry.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cognic_agentos.compliance'`.

- [ ] **Step 3: Write minimal implementation**

`src/cognic_agentos/compliance/iso42001/controls.py`:

```python
"""ISO/IEC 42001 control registry — Sprint 9 (ADR-006).

Single source of truth mapping the 8 ADR-006 Wave-1 Annex-A controls to
their intended Cognic governance hooks. The canonical control ID — the
value emitted into ``iso_controls`` and the registry's identity — is the
``ISO42001.``-prefixed form (e.g. ``ISO42001.A.6.2.5``); ``display``
carries the bare ``A.x.y`` for human-facing surfaces.

Dependency arrow: ``compliance/`` -> ``core/``, never the reverse. This
module is imported by the evidence-pack exporter and by tests; it is
NEVER imported by ``core/``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ComplianceControlId = Literal[
    "ISO42001.A.6.2.5",
    "ISO42001.A.6.2.6",
    "ISO42001.A.7.4",
    "ISO42001.A.7.6",
    "ISO42001.A.8.2",
    "ISO42001.A.8.5",
    "ISO42001.A.9.2",
    "ISO42001.A.10.2",
]


@dataclass(frozen=True, slots=True)
class ControlEntry:
    """One ADR-006 control and the Cognic hook(s) intended to tag it."""

    control_id: ComplianceControlId
    display: str
    title: str
    intended_hooks: tuple[str, ...]


ISO42001_CONTROLS: tuple[ControlEntry, ...] = (
    ControlEntry(
        "ISO42001.A.6.2.5",
        "A.6.2.5",
        "Operational responsibilities",
        ("escalation.transition", "rbac.check_scope", "sandbox.lifecycle.*"),
    ),
    ControlEntry(
        "ISO42001.A.6.2.6",
        "A.6.2.6",
        "Roles and responsibilities",
        ("rbac.role_scopes",),
    ),
    ControlEntry(
        "ISO42001.A.7.4",
        "A.7.4",
        "AI system impact assessment",
        ("decision_history.append",),
    ),
    ControlEntry(
        "ISO42001.A.7.6",
        "A.7.6",
        "AI system risk evaluation",
        ("auto_degradation.evaluate", "compliance_checker.score"),
    ),
    ControlEntry(
        "ISO42001.A.8.2",
        "A.8.2",
        "Data quality for AI systems",
        ("citation_verifier.verify",),
    ),
    ControlEntry(
        "ISO42001.A.8.5",
        "A.8.5",
        "AI system development",
        ("gateway.completion",),
    ),
    ControlEntry(
        "ISO42001.A.9.2",
        "A.9.2",
        "System and operational logging",
        ("audit.append", "chain_verifier.walk"),
    ),
    ControlEntry(
        "ISO42001.A.10.2",
        "A.10.2",
        "Stakeholder transparency",
        ("decision_history.export_for_subject",),
    ),
)


def control_ids() -> frozenset[str]:
    """The 8 canonical control-ID strings."""
    return frozenset(entry.control_id for entry in ISO42001_CONTROLS)


def audit_coverage(emitted: set[str]) -> dict[str, bool]:
    """Map each registry control_id -> whether ``emitted`` contains it.

    ``emitted`` is the set of canonical control IDs observed across the
    governance hooks (built by the T9 ``test_control_mapping`` suite from
    the real emission sites). A control is covered iff >=1 hook emits it.
    """
    return {entry.control_id: entry.control_id in emitted for entry in ISO42001_CONTROLS}
```

`src/cognic_agentos/compliance/iso42001/__init__.py`:

```python
"""ISO/IEC 42001 compliance evidence — control mapping + evidence-pack export (ADR-006)."""

from cognic_agentos.compliance.iso42001.controls import (
    ISO42001_CONTROLS,
    ComplianceControlId,
    ControlEntry,
    audit_coverage,
    control_ids,
)

__all__ = [
    "ISO42001_CONTROLS",
    "ComplianceControlId",
    "ControlEntry",
    "audit_coverage",
    "control_ids",
]
```

`src/cognic_agentos/compliance/__init__.py` and the two test `__init__.py` files are empty.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/compliance/iso42001/test_control_registry.py -v`
Expected: PASS — 3 tests.

- [ ] **Step 5: Commit (halt-before-commit first)**

```bash
git add src/cognic_agentos/compliance/ tests/unit/compliance/
git commit -m "feat(sprint-9): T1 — ISO 42001 control registry"
```

---

## Task 2: Domain-separated Merkle tree — `merkle.py`

**Files:**
- Create: `src/cognic_agentos/compliance/iso42001/merkle.py`
- Test: `tests/unit/compliance/iso42001/test_merkle.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/compliance/iso42001/test_merkle.py`:

```python
"""Sprint 9 T2 — domain-separated Merkle tree."""

from __future__ import annotations

import hashlib

import pytest

from cognic_agentos.compliance.iso42001.merkle import (
    inclusion_proof,
    merkle_root,
    verify_inclusion,
)

_A = b"\x11" * 32
_B = b"\x22" * 32
_C = b"\x33" * 32


def _leaf(h: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + h).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def test_empty_tree_root_is_sha256_of_empty() -> None:
    assert merkle_root([]) == hashlib.sha256(b"").digest()


def test_single_leaf_root_is_the_domain_separated_leaf() -> None:
    assert merkle_root([_A]) == _leaf(_A)


def test_two_leaf_root_is_node_of_two_leaves() -> None:
    assert merkle_root([_A, _B]) == _node(_leaf(_A), _leaf(_B))


def test_odd_leaf_promotes_lone_node_unchanged() -> None:
    # RFC-6962 style: the lone third leaf is promoted unchanged.
    expected = _node(_node(_leaf(_A), _leaf(_B)), _leaf(_C))
    assert merkle_root([_A, _B, _C]) == expected


def test_root_is_deterministic_and_order_sensitive() -> None:
    assert merkle_root([_A, _B]) == merkle_root([_A, _B])
    assert merkle_root([_A, _B]) != merkle_root([_B, _A])


def test_leaf_and_node_domains_are_separated() -> None:
    # A leaf hash must never collide with an internal node hash.
    assert _leaf(_A) != hashlib.sha256(b"\x01" + _A).digest()


@pytest.mark.parametrize("idx", [0, 1, 2, 3])
def test_inclusion_proof_round_trips(idx: int) -> None:
    leaves = [_A, _B, _C, b"\x44" * 32]
    root = merkle_root(leaves)
    proof = inclusion_proof(leaves, idx)
    assert verify_inclusion(leaves[idx], idx, proof, root) is True


def test_inclusion_proof_rejects_wrong_leaf() -> None:
    leaves = [_A, _B]
    root = merkle_root(leaves)
    proof = inclusion_proof(leaves, 0)
    assert verify_inclusion(_C, 0, proof, root) is False


def test_inclusion_proof_rejects_wrong_index() -> None:
    # Correct leaf, correct proof for position 2 — but the verifier is
    # told the leaf sits at position 0. The proof's L/R/P side sequence
    # encodes position 2; verify_inclusion MUST bind `index` and reject.
    leaves = [_A, _B, _C, b"\x44" * 32]
    root = merkle_root(leaves)
    proof = inclusion_proof(leaves, 2)
    assert verify_inclusion(_C, 0, proof, root) is False


@pytest.mark.parametrize("idx", [0, 1, 2])
def test_inclusion_proof_round_trips_odd_tree(idx: int) -> None:
    # A 3-leaf tree forces a lone-promotion level — exercises the "P"
    # proof element and index reconstruction across a skipped node.
    leaves = [_A, _B, _C]
    root = merkle_root(leaves)
    proof = inclusion_proof(leaves, idx)
    assert verify_inclusion(leaves[idx], idx, proof, root) is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/compliance/iso42001/test_merkle.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cognic_agentos.compliance.iso42001.merkle'`.

- [ ] **Step 3: Write minimal implementation**

`src/cognic_agentos/compliance/iso42001/merkle.py`:

```python
"""Domain-separated Merkle tree over evidence-pack chain hashes — Sprint 9 (ADR-006).

WIRE-PUBLIC — examiners recompute the root independently. RFC-6962-style
domain separation: leaf hash = SHA-256(0x00 || row_hash); internal node =
SHA-256(0x01 || left || right). A lone rightmost node is promoted
unchanged. The empty tree's root is SHA-256(b"").

Defined entirely here — never in ``core/canonical.py`` (the canonical
hash-chain framing is a separate, untouched stop-rule module).
"""

from __future__ import annotations

import hashlib

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _leaf_hash(row_hash: bytes) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + row_hash).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def merkle_root(row_hashes: list[bytes]) -> bytes:
    """Root over ``row_hashes`` (each a raw chain-row hash), in given order."""
    if not row_hashes:
        return hashlib.sha256(b"").digest()
    level = [_leaf_hash(h) for h in row_hashes]
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(_node_hash(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            nxt.append(level[-1])  # promote lone node unchanged
        level = nxt
    return level[0]


def inclusion_proof(row_hashes: list[bytes], index: int) -> list[tuple[bytes, str]]:
    """Sibling-path proof for leaf ``index``: one ``(sibling, side)`` entry
    per tree level. ``side`` is ``"L"`` (sibling on the left of the proven
    node), ``"R"`` (sibling on the right), or ``"P"`` (the proven node was
    the lone odd-one-out and was promoted unchanged — there is no sibling,
    so the entry's hash is ``b""``). Emitting an entry at *every* level —
    including lone-promotion levels — makes the side sequence an
    unambiguous encoding of ``index``, which ``verify_inclusion`` binds."""
    if not 0 <= index < len(row_hashes):
        raise IndexError(f"leaf index {index} out of range for {len(row_hashes)} leaves")
    level = [_leaf_hash(h) for h in row_hashes]
    proof: list[tuple[bytes, str]] = []
    pos = index
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(_node_hash(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        if pos % 2 == 1:
            proof.append((level[pos - 1], "L"))
        elif pos + 1 < len(level):
            proof.append((level[pos + 1], "R"))
        else:
            proof.append((b"", "P"))  # lone promoted node — no sibling
        pos //= 2
        level = nxt
    return proof


def verify_inclusion(
    row_hash: bytes, index: int, proof: list[tuple[bytes, str]], root: bytes
) -> bool:
    """True iff ``row_hash`` is the leaf at position ``index`` under
    ``root``. Binds all three: the proof's ``L``/``R``/``P`` sides are both
    folded into ``root`` AND reconstruct ``index`` — a proof generated for
    a different position fails the index check even when its sibling
    hashes are otherwise valid. A malformed side fails closed."""
    acc = _leaf_hash(row_hash)
    reconstructed = 0
    for bit, (sibling, side) in enumerate(proof):
        if side == "L":
            acc = _node_hash(sibling, acc)
            reconstructed |= 1 << bit
        elif side == "R":
            acc = _node_hash(acc, sibling)
        elif side == "P":
            pass  # lone promotion — acc unchanged, this index bit is 0
        else:
            return False  # malformed proof — fail closed
    return acc == root and reconstructed == index
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/compliance/iso42001/test_merkle.py -v`
Expected: PASS — 15 tests (8 non-parametrized + 7 parametrized: `round_trips` ×4,
`round_trips_odd_tree` ×3).

- [ ] **Step 5: Commit (halt-before-commit first)**

```bash
git add src/cognic_agentos/compliance/iso42001/merkle.py tests/unit/compliance/iso42001/test_merkle.py
git commit -m "feat(sprint-9): T2 — domain-separated evidence-pack Merkle tree"
```

---

## Task 3: Evidence-pack signing — `Settings` field + `signing.py`

**Files:**
- Modify: `src/cognic_agentos/core/config.py` (new field after `signing_key_path`, ~line 580)
- Create: `src/cognic_agentos/compliance/iso42001/signing.py`
- Test: `tests/unit/test_config.py` (one field test), `tests/unit/compliance/iso42001/test_signing.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_config.py` (near other Settings tests):

```python
def test_evidence_pack_signing_key_path_defaults_none() -> None:
    """#sprint-9 — evidence-pack signing identity is operator-provided;
    unset by default (export fails loud when unset)."""
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.evidence_pack_signing_key_path is None
```

Create `tests/unit/compliance/iso42001/test_signing.py`:

```python
"""Sprint 9 T3 — evidence-pack signing: identity resolution + fail-loud."""

from __future__ import annotations

from pathlib import Path

import pytest

from cognic_agentos.compliance.iso42001.signing import (
    CosignArtifacts,
    EvidencePackSigningError,
    SigningIdentity,
    cosign_sign_blob,
    resolve_signing_identity,
)
from tests.support.adapter_fixtures import InMemorySecretAdapter


async def test_resolve_raises_when_key_path_unset() -> None:
    with pytest.raises(EvidencePackSigningError, match="evidence_pack_signing_key_path"):
        await resolve_signing_identity(key_path=None, secret_adapter=None)


async def test_resolve_raises_on_unknown_uri_scheme() -> None:
    with pytest.raises(EvidencePackSigningError, match="scheme"):
        await resolve_signing_identity(key_path="s3://nope/key", secret_adapter=None)


async def test_resolve_vault_uri_requires_secret_adapter() -> None:
    with pytest.raises(EvidencePackSigningError, match="SecretAdapter"):
        await resolve_signing_identity(key_path="vault://secret/evidence-key", secret_adapter=None)


async def test_resolve_pem_path_reads_file_and_records_path_identity(
    tmp_path: Path,
) -> None:
    pem = tmp_path / "evidence-key.pem"
    pem.write_bytes(b"-----BEGIN PRIVATE KEY-----\nxxx\n-----END PRIVATE KEY-----\n")
    identity = await resolve_signing_identity(key_path=str(pem), secret_adapter=None)
    assert identity.identity == str(pem)
    assert identity.pem.startswith(b"-----BEGIN")


async def test_resolve_vault_records_the_uri_not_a_temp_path() -> None:
    # cli/sign.py's Vault contract: the `key` field (here a str).
    adapter = InMemorySecretAdapter()
    await adapter.write("secret/evidence-key", {"key": "-----BEGIN PRIVATE KEY-----\nyyy\n"})
    identity = await resolve_signing_identity(
        key_path="vault://secret/evidence-key", secret_adapter=adapter
    )
    # The auditable identity is the vault:// URI — never a /tmp path.
    assert identity.identity == "vault://secret/evidence-key"
    assert identity.pem.startswith(b"-----BEGIN")


async def test_resolve_vault_accepts_bytes_key_material() -> None:
    adapter = InMemorySecretAdapter()
    await adapter.write("secret/k", {"key": b"-----BEGIN PRIVATE KEY-----\nzzz\n"})
    identity = await resolve_signing_identity(key_path="vault://secret/k", secret_adapter=adapter)
    assert identity.pem == b"-----BEGIN PRIVATE KEY-----\nzzz\n"


async def test_cosign_sign_blob_fails_loud_when_cosign_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("cognic_agentos.compliance.iso42001.signing.shutil.which", lambda _: None)
    with pytest.raises(EvidencePackSigningError, match="cosign binary not found"):
        await cosign_sign_blob(b"{}", SigningIdentity(identity="x", pem=b"k"))


def test_validate_cosign_artifacts_rejects_empty_signature() -> None:
    from cognic_agentos.compliance.iso42001.signing import validate_cosign_artifacts

    with pytest.raises(EvidencePackSigningError, match="empty signature"):
        validate_cosign_artifacts(CosignArtifacts(signature=b"", bundle=b"bundle-bytes"))


def test_validate_cosign_artifacts_rejects_empty_bundle() -> None:
    from cognic_agentos.compliance.iso42001.signing import validate_cosign_artifacts

    with pytest.raises(EvidencePackSigningError, match="empty Sigstore bundle"):
        validate_cosign_artifacts(CosignArtifacts(signature=b"sig-bytes", bundle=b""))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/test_config.py::test_evidence_pack_signing_key_path_defaults_none tests/unit/compliance/iso42001/test_signing.py -v`
Expected: FAIL — `AttributeError` on the setting; `ModuleNotFoundError` for `signing`.

- [ ] **Step 3: Write the Settings field**

In `src/cognic_agentos/core/config.py`, immediately after the `signing_key_path` field
(ends ~line 588), add:

```python
    evidence_pack_signing_key_path: str | None = Field(
        default=None,
        description=(
            "#sprint-9 — operator-provided signing key for ISO 42001 "
            "evidence-pack manifests (ADR-006). DISTINCT from "
            "signing_key_path (pack-publisher identity for `agentos sign "
            "--bundle`): this is the AgentOS *instance* trust identity. "
            "Accepts `vault://secret/...` (production-preferred, resolved "
            "via SecretAdapter) or a filesystem PEM path (operator escape "
            "hatch). Unset => evidence-pack export fails loud; an unsigned "
            "examiner artifact is forbidden."
        ),
    )
```

- [ ] **Step 4: Write `signing.py`** (complete module)

`src/cognic_agentos/compliance/iso42001/signing.py`:

```python
"""Evidence-pack manifest signing — Sprint 9 (ADR-006).

cosign sign-blob over the evidence-pack manifest, mirroring the
cli/sign.py discipline (cosign resolved via shutil.which, list-form argv,
asyncio.create_subprocess_exec, .sig + .bundle.sigstore both preserved).
Fail-loud: a missing key OR a missing cosign binary raises
EvidencePackSigningError — there is no best-effort unsigned pack. When
the key is a vault:// URI the signing IDENTITY recorded in the manifest
is the URI, never the temp PEM path written for cosign.

On the critical-controls coverage gate (T10).
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cognic_agentos.db.adapters.protocols import SecretAdapter

_VAULT_SCHEME = "vault://"
_COSIGN_TIMEOUT_S = 60.0
#: Field within the Vault secret holding the signing-key material.
#: Matches cli/sign.py's Vault contract — the ``key`` field, str OR bytes.
_VAULT_KEY_FIELD = "key"


class EvidencePackSigningError(RuntimeError):
    """Any evidence-pack signing failure — fail-loud; never a best-effort
    unsigned pack."""


@dataclass(frozen=True, slots=True)
class SigningIdentity:
    """Resolved signing material. ``identity`` is the auditable string
    recorded in the manifest (the vault:// URI or the PEM path); ``pem``
    is the private-key bytes cosign consumes."""

    identity: str
    pem: bytes


@dataclass(frozen=True, slots=True)
class CosignArtifacts:
    """The two cosign sign-blob outputs preserved into the evidence pack."""

    signature: bytes
    bundle: bytes


async def resolve_signing_identity(
    *, key_path: str | None, secret_adapter: SecretAdapter | None
) -> SigningIdentity:
    """Resolve ``Settings.evidence_pack_signing_key_path`` to signing
    material. Fail-loud on every error path."""
    if not key_path:
        raise EvidencePackSigningError(
            "evidence_pack_signing_key_path is unset; an unsigned evidence "
            "pack is forbidden (ADR-006). Configure a vault:// URI or a PEM path."
        )
    if key_path.startswith(_VAULT_SCHEME):
        return await _resolve_vault(key_path, secret_adapter)
    if "://" in key_path:
        raise EvidencePackSigningError(
            f"unsupported signing-key URI scheme in {key_path!r}; "
            "use vault://... or a filesystem PEM path."
        )
    return _resolve_pem_path(key_path)


async def _resolve_vault(key_path: str, secret_adapter: SecretAdapter | None) -> SigningIdentity:
    if secret_adapter is None:
        raise EvidencePackSigningError(
            f"{key_path} requires a SecretAdapter to resolve; none is wired."
        )
    vault_path = key_path[len(_VAULT_SCHEME) :]
    try:
        secret = await secret_adapter.read(vault_path)
    except Exception as exc:  # adapter-specific errors collapse to fail-loud
        raise EvidencePackSigningError(
            f"failed to read evidence-pack signing key from {key_path}: {exc}"
        ) from exc
    raw = secret.get(_VAULT_KEY_FIELD)
    # cli/sign.py's Vault contract: the `key` field is bytes, or str
    # coerced to bytes. Either is accepted; anything else fails loud.
    if isinstance(raw, bytes) and raw:
        pem = raw
    elif isinstance(raw, str) and raw:
        pem = raw.encode("utf-8")
    else:
        raise EvidencePackSigningError(
            f"{key_path} secret has no non-empty {_VAULT_KEY_FIELD!r} field "
            "(expected str or bytes)."
        )
    # Auditable identity = the vault:// URI, NOT any temp path.
    return SigningIdentity(identity=key_path, pem=pem)


def _resolve_pem_path(key_path: str) -> SigningIdentity:
    path = Path(key_path)
    if not path.is_file():
        raise EvidencePackSigningError(
            f"evidence-pack signing key {key_path} is not a readable file."
        )
    try:
        pem = path.read_bytes()
    except OSError as exc:
        raise EvidencePackSigningError(
            f"failed to read evidence-pack signing key {key_path}: {exc}"
        ) from exc
    if not pem:
        raise EvidencePackSigningError(f"evidence-pack signing key {key_path} is empty.")
    return SigningIdentity(identity=key_path, pem=pem)


async def cosign_sign_blob(manifest: bytes, identity: SigningIdentity) -> CosignArtifacts:
    """``cosign sign-blob`` over ``manifest``. Fail-loud if cosign is
    absent, times out, exits non-zero, or fails to produce both outputs.

    argv mirrors cli/sign.py's _exec_cosign_sign_blob:
      cosign sign-blob --yes --key <key> --output-signature <sig>
        --bundle <bundle> <blob>
    """
    cosign = shutil.which("cosign")
    if cosign is None:
        raise EvidencePackSigningError(
            "cosign binary not found on PATH; cannot sign the evidence pack "
            "(an unsigned examiner artifact is forbidden, ADR-006)."
        )
    with tempfile.TemporaryDirectory(prefix="cognic-evidence-sign-") as tmp:
        tmp_dir = Path(tmp)
        key_file = tmp_dir / "evidence-key.pem"
        blob_file = tmp_dir / "manifest.json"
        sig_file = tmp_dir / "manifest.json.sig"
        bundle_file = tmp_dir / "manifest.json.bundle.sigstore"
        key_file.write_bytes(identity.pem)
        key_file.chmod(0o600)
        blob_file.write_bytes(manifest)
        proc = await asyncio.create_subprocess_exec(
            cosign,
            "sign-blob",
            "--yes",
            "--key",
            str(key_file),
            "--output-signature",
            str(sig_file),
            "--bundle",
            str(bundle_file),
            str(blob_file),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=_COSIGN_TIMEOUT_S)
        except TimeoutError as exc:
            proc.kill()
            await proc.wait()
            raise EvidencePackSigningError("cosign sign-blob timed out.") from exc
        if proc.returncode != 0:
            raise EvidencePackSigningError(
                f"cosign sign-blob failed (exit {proc.returncode}): "
                f"{stderr.decode('utf-8', 'replace').strip()}"
            )
        if not sig_file.is_file() or not bundle_file.is_file():
            raise EvidencePackSigningError(
                "cosign sign-blob exited 0 but did not produce both the "
                "signature and the Sigstore bundle."
            )
        signature = sig_file.read_bytes()
        bundle = bundle_file.read_bytes()
        # tempdir (incl. the key file) is removed on context exit.
        artifacts = CosignArtifacts(signature=signature, bundle=bundle)
        validate_cosign_artifacts(artifacts)
        return artifacts


def validate_cosign_artifacts(artifacts: CosignArtifacts) -> None:
    """Reject empty signing outputs — an empty .sig / .bundle.sigstore is
    a structurally-complete but UNVERIFIABLE examiner artifact. cli/sign.py
    treats empty signing outputs as a failure; mirror that, fail-loud
    (cosign can exit 0 yet leave a zero-byte output on some error paths).

    Public so the evidence-pack exporter can re-validate ANY injected
    signer's output — the ``signer`` seam in evidence_pack.py accepts
    test / custom signers, not only cosign_sign_blob's own output."""
    if not artifacts.signature:
        raise EvidencePackSigningError("cosign produced an empty signature.")
    if not artifacts.bundle:
        raise EvidencePackSigningError("cosign produced an empty Sigstore bundle.")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_config.py::test_evidence_pack_signing_key_path_defaults_none tests/unit/compliance/iso42001/test_signing.py -v`
Expected: PASS.

- [ ] **Step 6: Commit (halt-before-commit first)**

```bash
git add src/cognic_agentos/core/config.py src/cognic_agentos/compliance/iso42001/signing.py tests/unit/test_config.py tests/unit/compliance/iso42001/test_signing.py
git commit -m "feat(sprint-9): T3 — evidence-pack signing key setting + signing.py"
```

> **Note for the executor:** `core/config.py` adds one additive `Field`; this is *not*
> one of the forbidden `core/audit.py` / `core/decision_history.py` / `core/canonical.py`
> edits. `core/config.py` is the standard Settings home and is routinely extended.

---

## Task 4: Evidence-pack exporter — `evidence_pack.py`  **(STOP-RULE: wire format)**

**Files:**
- Create: `src/cognic_agentos/compliance/iso42001/evidence_pack.py`
- Test: `tests/unit/compliance/iso42001/test_evidence_pack.py`, `tests/unit/compliance/iso42001/test_evidence_pack_completeness.py`

- [ ] **Step 1: Write the failing tests**

Both test files seed real chain rows via `AuditStore.append` / `DecisionHistoryStore.append`
(file-backed sqlite — `:memory:` isolates per-connection and the exporter opens its own
connection) and stub cosign via the `signer` injection seam.

`tests/unit/compliance/iso42001/test_evidence_pack.py`:

```python
"""Sprint 9 T4 — evidence-pack exporter: wire shape, Merkle, tenant isolation."""

from __future__ import annotations

import io
import json
import tarfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.compliance.iso42001.controls import ISO42001_CONTROLS
from cognic_agentos.compliance.iso42001.evidence_pack import export_evidence_pack
from cognic_agentos.compliance.iso42001.merkle import merkle_root
from cognic_agentos.compliance.iso42001.signing import (
    CosignArtifacts,
    EvidencePackSigningError,
    SigningIdentity,
)
from cognic_agentos.core.audit import AuditEvent, AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord

_WIDE = (datetime(2000, 1, 1, tzinfo=UTC), datetime(2100, 1, 1, tzinfo=UTC))

#: The 12 wire-public manifest.json keys (stop-rule contract).
_MANIFEST_KEYS = {
    "schema_version",
    "agentos_version",
    "tenant_id",
    "period_start",
    "period_end",
    "generated_at",
    "merkle_algorithm",
    "merkle_root",
    "audit_event_row_count",
    "decision_history_row_count",
    "signing_identity",
    "per_control_coverage",
}

#: The DB-column key set of one serialised chain row (audit_event and
#: decision_history carry the identical 15 column names).
_ROW_COLUMNS = {
    "record_id",
    "sequence",
    "schema_version",
    "tenant_id",
    "prev_hash",
    "hash",
    "created_at",
    "event_type",
    "request_id",
    "trace_id",
    "span_id",
    "langfuse_trace_id",
    "provider_label",
    "iso_controls",
    "payload",
}


async def _fake_signer(manifest: bytes, identity: SigningIdentity) -> CosignArtifacts:
    return CosignArtifacts(signature=b"fake-sig", bundle=b"fake-bundle")


async def _seeded_engine(
    tmp_path: Path,
) -> tuple[AsyncEngine, AuditStore, DecisionHistoryStore]:
    """File-backed sqlite engine with the governance schema + chain heads,
    plus AuditStore / DecisionHistoryStore for seeding."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'ev.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    return engine, AuditStore(engine), DecisionHistoryStore(engine)


def _pem(tmp_path: Path) -> str:
    key = tmp_path / "evidence-key.pem"
    key.write_bytes(b"-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----\n")
    return str(key)


def _members(tar_bytes: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        out: dict[str, bytes] = {}
        for m in tar.getmembers():
            f = tar.extractfile(m)
            assert f is not None
            out[m.name] = f.read()
        return out


def _assert_row_encoding(row: dict[str, object]) -> None:
    """Pin the wire encoding of one serialised chain row (stop-rule)."""
    assert set(row) == _ROW_COLUMNS
    for col in ("prev_hash", "hash"):
        value = row[col]
        assert isinstance(value, str)
        assert len(value) == 64
        assert value == value.lower()
        bytes.fromhex(value)  # raises if not lowercase hex
    created_at = row["created_at"]
    assert isinstance(created_at, str)
    datetime.fromisoformat(created_at)  # raises if not ISO-8601
    record_id = row["record_id"]
    assert isinstance(record_id, str)
    uuid.UUID(record_id)  # raises if not a UUID string
    assert isinstance(row["payload"], dict)
    assert isinstance(row["iso_controls"], list)


async def test_export_produces_signed_tarball_with_pinned_members(tmp_path: Path) -> None:
    engine, audit, dh = await _seeded_engine(tmp_path)
    await audit.append(
        AuditEvent(
            event_type="audit.test",
            request_id="r1",
            payload={},
            tenant_id="t-1",
            iso_controls=("ISO42001.A.9.2",),
        )
    )
    await dh.append(
        DecisionRecord(
            decision_type="d.test",
            request_id="r2",
            payload={"k": "v"},
            tenant_id="t-1",
            iso_controls=("ISO42001.A.7.4",),
        )
    )
    tar_bytes = await export_evidence_pack(
        engine=engine,
        tenant_id="t-1",
        period_start=_WIDE[0],
        period_end=_WIDE[1],
        signing_key_path=_pem(tmp_path),
        secret_adapter=None,
        signer=_fake_signer,
    )
    members = _members(tar_bytes)
    assert set(members) == {
        "manifest.json",
        "manifest.json.sig",
        "manifest.json.bundle.sigstore",
        "audit_event.jsonl",
        "decision_history.jsonl",
    }
    # The cosign artifact members are the signer's outputs verbatim.
    assert members["manifest.json.sig"] == b"fake-sig"
    assert members["manifest.json.bundle.sigstore"] == b"fake-bundle"

    manifest = json.loads(members["manifest.json"])
    # manifest.json IS the canonical compact form (sorted keys, tight separators).
    assert members["manifest.json"] == json.dumps(
        manifest, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    # Exactly the 12 wire-public manifest keys — no more, no fewer.
    assert set(manifest) == _MANIFEST_KEYS
    assert manifest["schema_version"] == 1
    assert manifest["tenant_id"] == "t-1"
    assert manifest["merkle_algorithm"] == "iso42001-evidence-merkle-v1"
    assert manifest["signing_identity"] == _pem(tmp_path)
    assert manifest["audit_event_row_count"] == 1
    assert manifest["decision_history_row_count"] == 1

    # per_control_coverage carries all 8 registry controls verbatim, with
    # display + title from the registry and the seeded controls counted.
    coverage = manifest["per_control_coverage"]
    assert set(coverage) == {entry.control_id for entry in ISO42001_CONTROLS}
    for entry in ISO42001_CONTROLS:
        cell = coverage[entry.control_id]
        assert cell["display"] == entry.display
        assert cell["title"] == entry.title
    seeded = {"ISO42001.A.9.2", "ISO42001.A.7.4"}
    for cid, cell in coverage.items():
        assert cell["tagged_row_count"] == (1 if cid in seeded else 0)


async def test_jsonl_row_encoding_is_pinned(tmp_path: Path) -> None:
    engine, audit, dh = await _seeded_engine(tmp_path)
    await audit.append(
        AuditEvent(
            event_type="a",
            request_id="r1",
            payload={"x": 1},
            tenant_id="t-1",
            iso_controls=("ISO42001.A.9.2",),
        )
    )
    await audit.append(
        AuditEvent(
            event_type="a",
            request_id="r2",
            payload={"x": 2},
            tenant_id="t-1",
            iso_controls=("ISO42001.A.9.2",),
        )
    )
    await dh.append(
        DecisionRecord(
            decision_type="d",
            request_id="r3",
            payload={"y": 3},
            tenant_id="t-1",
            iso_controls=("ISO42001.A.7.4",),
        )
    )
    tar_bytes = await export_evidence_pack(
        engine=engine,
        tenant_id="t-1",
        period_start=_WIDE[0],
        period_end=_WIDE[1],
        signing_key_path=_pem(tmp_path),
        secret_adapter=None,
        signer=_fake_signer,
    )
    members = _members(tar_bytes)
    audit_jsonl = members["audit_event.jsonl"]
    dh_jsonl = members["decision_history.jsonl"]
    # Non-empty JSONL is newline-terminated.
    assert audit_jsonl.endswith(b"\n")
    assert dh_jsonl.endswith(b"\n")
    audit_rows = [json.loads(line) for line in audit_jsonl.splitlines()]
    dh_rows = [json.loads(line) for line in dh_jsonl.splitlines()]
    for row in (*audit_rows, *dh_rows):
        _assert_row_encoding(row)
    # The audit chain exports sequence-ascending (deterministic Merkle order).
    sequences = [row["sequence"] for row in audit_rows]
    assert len(sequences) == 2
    assert sequences == sorted(sequences)


async def test_export_merkle_root_recomputes_from_bundled_rows(tmp_path: Path) -> None:
    engine, audit, dh = await _seeded_engine(tmp_path)
    await audit.append(AuditEvent(event_type="a", request_id="r1", payload={}, tenant_id="t-1"))
    await dh.append(DecisionRecord(decision_type="d", request_id="r2", payload={}, tenant_id="t-1"))
    tar_bytes = await export_evidence_pack(
        engine=engine,
        tenant_id="t-1",
        period_start=_WIDE[0],
        period_end=_WIDE[1],
        signing_key_path=_pem(tmp_path),
        secret_adapter=None,
        signer=_fake_signer,
    )
    members = _members(tar_bytes)
    manifest = json.loads(members["manifest.json"])
    audit_hashes = [
        bytes.fromhex(json.loads(line)["hash"])
        for line in members["audit_event.jsonl"].splitlines()
    ]
    dh_hashes = [
        bytes.fromhex(json.loads(line)["hash"])
        for line in members["decision_history.jsonl"].splitlines()
    ]
    # audit_event chain then decision_history chain, each sequence-ordered.
    assert merkle_root(audit_hashes + dh_hashes).hex() == manifest["merkle_root"]


async def test_export_excludes_other_tenant_rows(tmp_path: Path) -> None:
    engine, audit, dh = await _seeded_engine(tmp_path)
    await audit.append(AuditEvent(event_type="a", request_id="r1", payload={}, tenant_id="t-1"))
    await audit.append(AuditEvent(event_type="a", request_id="r2", payload={}, tenant_id="t-2"))
    await dh.append(DecisionRecord(decision_type="d", request_id="r3", payload={}, tenant_id="t-2"))
    tar_bytes = await export_evidence_pack(
        engine=engine,
        tenant_id="t-1",
        period_start=_WIDE[0],
        period_end=_WIDE[1],
        signing_key_path=_pem(tmp_path),
        secret_adapter=None,
        signer=_fake_signer,
    )
    members = _members(tar_bytes)
    audit_lines = members["audit_event.jsonl"].splitlines()
    assert len(audit_lines) == 1
    assert json.loads(audit_lines[0])["tenant_id"] == "t-1"
    assert members["decision_history.jsonl"] == b""  # no t-1 decision rows


async def test_export_rejects_signer_returning_empty_signature(tmp_path: Path) -> None:
    engine, *_ = await _seeded_engine(tmp_path)

    async def _empty_sig_signer(manifest: bytes, identity: SigningIdentity) -> CosignArtifacts:
        return CosignArtifacts(signature=b"", bundle=b"bundle")

    with pytest.raises(EvidencePackSigningError, match="empty signature"):
        await export_evidence_pack(
            engine=engine,
            tenant_id="t-1",
            period_start=_WIDE[0],
            period_end=_WIDE[1],
            signing_key_path=_pem(tmp_path),
            secret_adapter=None,
            signer=_empty_sig_signer,
        )


async def test_export_rejects_signer_returning_empty_bundle(tmp_path: Path) -> None:
    engine, *_ = await _seeded_engine(tmp_path)

    async def _empty_bundle_signer(manifest: bytes, identity: SigningIdentity) -> CosignArtifacts:
        return CosignArtifacts(signature=b"sig", bundle=b"")

    with pytest.raises(EvidencePackSigningError, match="empty Sigstore bundle"):
        await export_evidence_pack(
            engine=engine,
            tenant_id="t-1",
            period_start=_WIDE[0],
            period_end=_WIDE[1],
            signing_key_path=_pem(tmp_path),
            secret_adapter=None,
            signer=_empty_bundle_signer,
        )
```

`tests/unit/compliance/iso42001/test_evidence_pack_completeness.py`:

```python
"""Sprint 9 T4 — evidence-pack window completeness."""

from __future__ import annotations

import io
import json
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import update
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.compliance.iso42001.evidence_pack import export_evidence_pack
from cognic_agentos.compliance.iso42001.signing import CosignArtifacts, SigningIdentity
from cognic_agentos.core.audit import (
    AuditEvent,
    AuditStore,
    _audit_event,
    _chain_heads,
    _metadata,
)
from cognic_agentos.core.canonical import ZERO_HASH


async def _fake_signer(manifest: bytes, identity: SigningIdentity) -> CosignArtifacts:
    return CosignArtifacts(signature=b"s", bundle=b"b")


def _pem(tmp_path: Path) -> str:
    key = tmp_path / "k.pem"
    key.write_bytes(b"-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n")
    return str(key)


async def test_pack_contains_exactly_the_in_window_rows(tmp_path: Path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'c.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    audit = AuditStore(engine)
    # Seed 3 t-1 audit rows; created_at is server-set on append, so UPDATE
    # each to a controlled timestamp keyed by its (unique) request_id.
    for rid in ("in-a", "in-b", "out"):
        await audit.append(AuditEvent(event_type="a", request_id=rid, payload={}, tenant_id="t-1"))
    base = datetime(2026, 6, 1, tzinfo=UTC)
    stamps = {
        "in-a": base,
        "in-b": base + timedelta(hours=1),
        "out": base + timedelta(days=30),
    }
    async with engine.begin() as conn:
        for rid, ts in stamps.items():
            await conn.execute(
                update(_audit_event).where(_audit_event.c.request_id == rid).values(created_at=ts)
            )
    tar_bytes = await export_evidence_pack(
        engine=engine,
        tenant_id="t-1",
        period_start=base,
        period_end=base + timedelta(days=1),
        signing_key_path=_pem(tmp_path),
        secret_adapter=None,
        signer=_fake_signer,
    )
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        f = tar.extractfile("audit_event.jsonl")
        assert f is not None
        audit_jsonl = f.read()
    request_ids = {json.loads(line)["request_id"] for line in audit_jsonl.splitlines()}
    assert request_ids == {"in-a", "in-b"}  # the out-of-window row is excluded
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/compliance/iso42001/test_evidence_pack.py tests/unit/compliance/iso42001/test_evidence_pack_completeness.py -v`
Expected: FAIL — `ModuleNotFoundError` for `evidence_pack`.

- [ ] **Step 3: Write `evidence_pack.py`** (complete module)

`src/cognic_agentos/compliance/iso42001/evidence_pack.py`:

```python
"""ISO 42001 evidence-pack exporter — Sprint 9 (ADR-006).

WIRE-PUBLIC / STOP-RULE — examiners consume the tarball, manifest, and
JSONL shapes produced here. Reads the exported `_audit_event` /
`_decision_history` Table objects through an injected AsyncEngine; never
imports or mutates `core/audit.py` / `core/decision_history.py` source.

On the critical-controls coverage gate (T10).
"""

from __future__ import annotations

import io
import json
import tarfile
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Table, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from cognic_agentos import __version__
from cognic_agentos.compliance.iso42001.controls import ISO42001_CONTROLS
from cognic_agentos.compliance.iso42001.merkle import merkle_root
from cognic_agentos.compliance.iso42001.signing import (
    CosignArtifacts,
    SigningIdentity,
    cosign_sign_blob,
    resolve_signing_identity,
    validate_cosign_artifacts,
)
from cognic_agentos.core.audit import _audit_event
from cognic_agentos.core.decision_history import _decision_history

#: Manifest schema version + the Merkle scheme identifier (wire-public).
_SCHEMA_VERSION = 1
_MERKLE_ALGORITHM = "iso42001-evidence-merkle-v1"

#: Signer seam — production default is real cosign; tests inject a stub.
Signer = Callable[[bytes, SigningIdentity], Awaitable[CosignArtifacts]]


def _row_to_json(row: Any) -> dict[str, Any]:
    """Serialise one chain row to the spec §6.2.1 wire shape — bytes
    columns (`prev_hash`, `hash`) as lowercase hex, datetimes ISO-8601,
    UUIDs as strings; field names match the DB columns exactly."""
    out: dict[str, Any] = {}
    for key, value in row._mapping.items():
        if isinstance(value, bytes):
            out[key] = value.hex()
        elif isinstance(value, datetime):
            out[key] = value.isoformat()
        elif isinstance(value, uuid.UUID):
            out[key] = str(value)
        else:
            out[key] = value
    return out


async def _query_chain(
    conn: AsyncConnection,
    table: Table,
    tenant_id: str,
    period_start: datetime,
    period_end: datetime,
) -> list[Any]:
    """In-scope rows for one chain — tenant-filtered, half-open window
    [start, end), sequence-ordered (the deterministic Merkle order)."""
    stmt = (
        select(table)
        .where(table.c.tenant_id == tenant_id)
        .where(table.c.created_at >= period_start)
        .where(table.c.created_at < period_end)
        .order_by(table.c.sequence)
    )
    result = await conn.execute(stmt)
    return list(result.fetchall())


def _jsonl(rows: list[Any]) -> bytes:
    """One row per line, deterministic key order."""
    return b"".join(
        (json.dumps(_row_to_json(r), separators=(",", ":"), sort_keys=True) + "\n").encode()
        for r in rows
    )


def _per_control_coverage(rows: list[Any]) -> dict[str, dict[str, Any]]:
    """Registry-driven coverage section — every ADR-006 control plus the
    count of in-scope rows tagged with it."""
    observed: dict[str, int] = {}
    for row in rows:
        for cid in row._mapping["iso_controls"] or ():
            observed[cid] = observed.get(cid, 0) + 1
    return {
        entry.control_id: {
            "display": entry.display,
            "title": entry.title,
            "tagged_row_count": observed.get(entry.control_id, 0),
        }
        for entry in ISO42001_CONTROLS
    }


def _build_tarball(
    *,
    manifest: bytes,
    signature: bytes,
    bundle: bytes,
    audit_jsonl: bytes,
    decision_history_jsonl: bytes,
) -> bytes:
    """The five-member `.tar.gz` (member names are wire-public)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in (
            ("manifest.json", manifest),
            ("manifest.json.sig", signature),
            ("manifest.json.bundle.sigstore", bundle),
            ("audit_event.jsonl", audit_jsonl),
            ("decision_history.jsonl", decision_history_jsonl),
        ):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


async def export_evidence_pack(
    *,
    engine: AsyncEngine,
    tenant_id: str,
    period_start: datetime,
    period_end: datetime,
    signing_key_path: str | None,
    secret_adapter: Any = None,
    signer: Signer = cosign_sign_blob,
) -> bytes:
    """Produce a signed ISO 42001 evidence-pack `.tar.gz` for one tenant
    over [period_start, period_end). Fail-loud on any signing failure —
    an unsigned examiner artifact is never returned."""
    identity = await resolve_signing_identity(
        key_path=signing_key_path, secret_adapter=secret_adapter
    )
    async with engine.connect() as conn:
        audit_rows = await _query_chain(conn, _audit_event, tenant_id, period_start, period_end)
        dh_rows = await _query_chain(conn, _decision_history, tenant_id, period_start, period_end)

    # Merkle leaves: audit_event chain THEN decision_history chain, each
    # already sequence-ordered; leaf input = the row's raw `hash` bytes.
    leaves = [r._mapping["hash"] for r in audit_rows] + [r._mapping["hash"] for r in dh_rows]
    root = merkle_root(leaves)

    manifest = {
        "schema_version": _SCHEMA_VERSION,
        "agentos_version": __version__,
        "tenant_id": tenant_id,
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "generated_at": datetime.now(UTC).isoformat(),
        "merkle_algorithm": _MERKLE_ALGORITHM,
        "merkle_root": root.hex(),
        "audit_event_row_count": len(audit_rows),
        "decision_history_row_count": len(dh_rows),
        "signing_identity": identity.identity,
        "per_control_coverage": _per_control_coverage([*audit_rows, *dh_rows]),
    }
    manifest_bytes = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")

    artifacts = await signer(manifest_bytes, identity)
    # The `signer` seam accepts test / custom signers, not only the
    # default cosign_sign_blob — re-validate the output here so no signer
    # path can produce a structurally-complete but unverifiable pack.
    validate_cosign_artifacts(artifacts)

    return _build_tarball(
        manifest=manifest_bytes,
        signature=artifacts.signature,
        bundle=artifacts.bundle,
        audit_jsonl=_jsonl(audit_rows),
        decision_history_jsonl=_jsonl(dh_rows),
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/compliance/iso42001/test_evidence_pack.py tests/unit/compliance/iso42001/test_evidence_pack_completeness.py -v`
Expected: PASS.

- [ ] **Step 5: Commit (halt-before-commit first — STOP-RULE summary)**

The halt summary MUST surface the exact wire shapes: `manifest.json` field list, the
JSONL row encoding, the Merkle `merkle_algorithm` identifier + byte framing, and the
five tarball member names — flagged as evidence-pack-format stop-rule material for
explicit human review.

```bash
git add src/cognic_agentos/compliance/iso42001/evidence_pack.py tests/unit/compliance/iso42001/test_evidence_pack.py tests/unit/compliance/iso42001/test_evidence_pack_completeness.py
git commit -m "feat(sprint-9): T4 — ISO 42001 evidence-pack exporter (STOP-RULE: wire format)"
```

---

## Task 5: RBAC scopes  **(STOP-RULE: `scopes.py` + `actor.py` + `enforcement.py`)**

**Files:**
- Modify: `src/cognic_agentos/portal/rbac/scopes.py` (new `ComplianceRBACScope` family + `EXAMINER_COMPLIANCE_SCOPES`) — **RBAC stop-rule**
- Modify: `src/cognic_agentos/portal/rbac/actor.py` (`Actor.scopes` widening) — **RBAC stop-rule**
- Modify: `src/cognic_agentos/portal/rbac/enforcement.py` (`RequireScope` `scope` param widening) — **RBAC stop-rule**
- Test: `tests/unit/portal/rbac/test_compliance_scopes.py`

All three RBAC files are stop-rule modules — the T5 halt summary must request explicit RBAC stop-rule review of **all three**.

- [ ] **Step 1: Write the failing test**

```python
"""Sprint 9 T5 — compliance RBAC scope family."""

from __future__ import annotations

import typing

from cognic_agentos.portal.rbac.scopes import (
    EXAMINER_COMPLIANCE_SCOPES,
    ComplianceRBACScope,
)


def test_compliance_scope_family_has_exactly_two_values() -> None:
    assert set(typing.get_args(ComplianceRBACScope)) == {
        "compliance.evidence_pack.read",
        "compliance.trace.read",
    }


def test_examiner_compliance_scopes_holds_both() -> None:
    assert (
        frozenset({"compliance.evidence_pack.read", "compliance.trace.read"})
        == EXAMINER_COMPLIANCE_SCOPES
    )


def test_actor_can_carry_a_compliance_scope() -> None:
    from cognic_agentos.portal.rbac.actor import Actor

    actor = Actor(
        subject="examiner-1",
        tenant_id="t-1",
        scopes=frozenset({"compliance.evidence_pack.read"}),
        actor_type="human",
    )
    assert "compliance.evidence_pack.read" in actor.scopes


def test_require_scope_signature_accepts_compliance_scopes() -> None:
    """Pins the `enforcement.py` widening at TEST time, not just mypy:
    `RequireScope`'s `scope` parameter must accept the compliance-scope
    family. Without the Step-4 enforcement widening this fails."""
    from cognic_agentos.portal.rbac import enforcement

    hints = typing.get_type_hints(enforcement.RequireScope)
    accepted: set[str] = set()
    for member in typing.get_args(hints["scope"]):
        accepted |= set(typing.get_args(member))
    assert {"compliance.evidence_pack.read", "compliance.trace.read"} <= accepted


def test_require_scope_constructs_for_each_compliance_scope() -> None:
    """Smoke — `RequireScope` builds a usable dependency for both
    compliance scopes (end-to-end 403/200 behaviour is pinned by the
    T6/T7 endpoint tests)."""
    from cognic_agentos.portal.rbac.enforcement import RequireScope

    assert callable(RequireScope("compliance.evidence_pack.read"))
    assert callable(RequireScope("compliance.trace.read"))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/portal/rbac/test_compliance_scopes.py -v`
Expected: FAIL — `ImportError` for `ComplianceRBACScope`.

- [ ] **Step 3: Implement — `scopes.py`**

In `src/cognic_agentos/portal/rbac/scopes.py`, after the `UIRBACScope` Literal block,
add the new family + examiner set (mirroring the `PackRBACScope` / `UIRBACScope`
plain-`Literal` convention):

```python
#: #sprint-9 — ISO 42001 compliance evidence scopes (ADR-006). Two atoms:
#: bulk evidence-pack disclosure vs targeted forensic trace lookup.
ComplianceRBACScope = Literal[
    "compliance.evidence_pack.read",
    "compliance.trace.read",
]

#: Examiner-role compliance grant. Bank-overlay examiner binders grant
#: EXAMINER_SCOPES | EXAMINER_COMPLIANCE_SCOPES.
EXAMINER_COMPLIANCE_SCOPES: frozenset[ComplianceRBACScope] = frozenset(
    {
        "compliance.evidence_pack.read",
        "compliance.trace.read",
    }
)
```

- [ ] **Step 4: Widen the scope-union types — `actor.py` + `enforcement.py`**

Adding `ComplianceRBACScope` requires widening **two** scope-union types so an examiner
`Actor` can carry — and `RequireScope` can gate on — the compliance scopes:

1. `src/cognic_agentos/portal/rbac/actor.py` — import `ComplianceRBACScope` from
   `scopes.py`; widen `Actor.scopes` from `frozenset[PackRBACScope | UIRBACScope]` to
   `frozenset[PackRBACScope | UIRBACScope | ComplianceRBACScope]`, updating the adjacent
   comment to record the Sprint-9 widening (mirroring the Sprint-7B.4 `UIRBACScope`
   widening comment already there).
2. `src/cognic_agentos/portal/rbac/enforcement.py` — widen the `RequireScope` factory's
   parameter from `def RequireScope(scope: PackRBACScope | UIRBACScope)` to
   `def RequireScope(scope: PackRBACScope | UIRBACScope | ComplianceRBACScope)`, with a
   one-line comment recording the Sprint-9 widening + the import of `ComplianceRBACScope`.
   Without this, `RequireScope("compliance.evidence_pack.read")` in T6/T7 is a `mypy`
   error. `enforcement.py` is an RBAC stop-rule module — this widening is part of the
   T5 stop-rule review surface.

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/unit/portal/rbac/test_compliance_scopes.py -v`
Then: `uv run pytest tests/unit/portal/rbac/ -q`
Expected: PASS — new test + no RBAC regression.

- [ ] **Step 6: Commit (halt-before-commit first — STOP-RULE summary)**

The halt summary MUST flag this as an RBAC stop-rule change across **three** RBAC
files: `portal/rbac/scopes.py` (wire-protocol-public — new `ComplianceRBACScope`
family), `portal/rbac/actor.py` (`Actor.scopes` type widens), and
`portal/rbac/enforcement.py` (`RequireScope` `scope` param widens). Request explicit
RBAC stop-rule review of all three.

```bash
git add src/cognic_agentos/portal/rbac/scopes.py src/cognic_agentos/portal/rbac/actor.py src/cognic_agentos/portal/rbac/enforcement.py tests/unit/portal/rbac/test_compliance_scopes.py
git commit -m "feat(sprint-9): T5 — ComplianceRBACScope family + scope-union widening (STOP-RULE)"
```

---

## Task 6: Evidence-pack endpoint + `portal/api/compliance/` route package

**Files:**
- Create: `src/cognic_agentos/portal/api/compliance/__init__.py`, `evidence_pack_routes.py`, `router.py`
- Modify: `src/cognic_agentos/portal/api/app.py` (mount the compliance router)
- Test: `tests/unit/portal/api/compliance/__init__.py`, `tests/unit/portal/api/compliance/test_evidence_pack_endpoint.py`

> **Endpoint-test decomposition (read first).** `InMemoryRelationalAdapter` uses
> `sqlite+aiosqlite:///:memory:` with **no `StaticPool`** — each connection gets its own
> empty DB. The exporter opens its *own* `engine.connect()`, so it cannot see rows a
> route test seeded on a different connection. Therefore the T6 endpoint test
> **monkeypatches `export_evidence_pack`** — it covers routing (auth, tenant, 503, wire
> shape); the exporter's real data behaviour is covered by T4's file-backed-engine
> tests. This decomposition is forced by the infrastructure, not a style choice.

- [ ] **Step 1: Write the failing test**

`tests/unit/portal/api/compliance/__init__.py` is empty. `tests/unit/portal/api/compliance/test_evidence_pack_endpoint.py`:

```python
"""Sprint 9 T6 — evidence-pack endpoint: RBAC, tenant isolation, 503."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from cognic_agentos.core.config import Settings
from cognic_agentos.db.adapters import AdapterRegistry
from cognic_agentos.db.adapters.local_object_store_adapter import LocalObjectStoreAdapter
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.scopes import (
    ComplianceRBACScope,
    PackRBACScope,
    UIRBACScope,
)
from tests.support.adapter_fixtures import (
    InMemoryEmbeddingAdapter,
    InMemoryObservabilityAdapter,
    InMemoryRelationalAdapter,
    InMemorySecretAdapter,
    InMemoryVectorAdapter,
)

_PARAMS = {"from": "2026-01-01T00:00:00Z", "to": "2026-12-31T00:00:00Z", "scope": "t-1"}

#: The externally visible evidence-pack route path (Pin 1 / Pin 2 contract).
_ROUTE = "/api/v1/compliance/evidence-pack"

_Scope = PackRBACScope | UIRBACScope | ComplianceRBACScope


class _StubBinder:
    """Test ActorBinder — bind(*, request) is sync per the protocol."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: object) -> Actor:
        return self._actor


def _examiner(*, scopes: frozenset[_Scope], tenant_id: str = "t-1") -> Actor:
    return Actor(subject="examiner@bank", tenant_id=tenant_id, scopes=scopes, actor_type="human")


def _memory_registry() -> AdapterRegistry:
    r = AdapterRegistry()
    r.register("relational", "memory", InMemoryRelationalAdapter)
    r.register("vector", "memory", InMemoryVectorAdapter)
    r.register("secret", "memory", InMemorySecretAdapter)
    r.register("embedding", "memory", InMemoryEmbeddingAdapter)
    r.register("observability", "memory", InMemoryObservabilityAdapter)
    r.register("object_store", "local_fs", LocalObjectStoreAdapter)
    return r


def _settings(tmp_path: Path, *, signing_key_path: str | None = None) -> Settings:
    return Settings(  # type: ignore[call-arg]
        _env_file=None,
        db_driver="memory",
        vector_driver="memory",
        secret_driver="memory",
        embed_driver="memory",
        obs_driver="memory",
        database_url=None,
        qdrant_url=None,
        vault_addr=None,
        embedding_base_url=None,
        langfuse_host=None,
        object_store_driver="local_fs",
        local_object_store_root=tmp_path,
        evidence_pack_signing_key_path=signing_key_path,
    )


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def _route_paths(app: FastAPI) -> set[str]:
    return {getattr(route, "path", "") for route in app.routes}


async def test_evidence_pack_endpoint_200_threads_engine_and_secret_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pin 1 — 200 path externally visible contract: route path, gzip
    content-type, attachment Content-Disposition, AND the route threads
    the configured signing key + a live SecretAdapter + engine + tenant
    into the exporter (a vault:// key cannot resolve without the
    SecretAdapter; the captured kwargs fail the test if the route ever
    drops one)."""
    captured: dict[str, object] = {}

    async def _fake_export(**kwargs: object) -> bytes:
        captured.update(kwargs)
        return b"FAKE-TARBALL"

    monkeypatch.setattr(
        "cognic_agentos.portal.api.compliance.evidence_pack_routes.export_evidence_pack",
        _fake_export,
    )
    actor = _examiner(scopes=frozenset({"compliance.evidence_pack.read"}))
    app = create_app(
        _settings(tmp_path, signing_key_path="vault://secret/evidence-key"),
        adapter_registry=_memory_registry(),
        actor_binder=_StubBinder(actor),
    )
    assert _ROUTE in _route_paths(app)
    async with app.router.lifespan_context(app), _client(app) as client:
        resp = await client.get(_ROUTE, params=_PARAMS)
    assert resp.status_code == 200
    assert resp.content == b"FAKE-TARBALL"
    assert resp.headers["content-type"] == "application/gzip"
    assert resp.headers["content-disposition"] == 'attachment; filename="evidence-pack-t-1.tar.gz"'
    assert captured["tenant_id"] == "t-1"
    assert captured["engine"] is not None
    assert captured["secret_adapter"] is not None
    assert captured["signing_key_path"] == "vault://secret/evidence-key"


async def test_evidence_pack_endpoint_500_on_signing_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fail-loud signing error (e.g. unset/missing key) surfaces as a
    500 with the closed-enum reason — never a silent unsigned pack."""
    from cognic_agentos.compliance.iso42001.signing import EvidencePackSigningError

    async def _boom_export(**kwargs: object) -> bytes:
        raise EvidencePackSigningError("evidence_pack_signing_key_path is unset")

    monkeypatch.setattr(
        "cognic_agentos.portal.api.compliance.evidence_pack_routes.export_evidence_pack",
        _boom_export,
    )
    actor = _examiner(scopes=frozenset({"compliance.evidence_pack.read"}))
    app = create_app(
        _settings(tmp_path),
        adapter_registry=_memory_registry(),
        actor_binder=_StubBinder(actor),
    )
    async with app.router.lifespan_context(app), _client(app) as client:
        resp = await client.get(_ROUTE, params=_PARAMS)
    assert resp.status_code == 500
    assert resp.json()["detail"]["reason"] == "evidence_pack_signing_failed"


async def test_evidence_pack_endpoint_403_without_scope(tmp_path: Path) -> None:
    actor = _examiner(scopes=frozenset())  # no compliance scope held
    app = create_app(
        _settings(tmp_path),
        adapter_registry=_memory_registry(),
        actor_binder=_StubBinder(actor),
    )
    async with app.router.lifespan_context(app), _client(app) as client:
        resp = await client.get(_ROUTE, params=_PARAMS)
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert detail["reason"] == "scope_not_held"
    assert detail["required_scope"] == "compliance.evidence_pack.read"


async def test_evidence_pack_endpoint_404_cross_tenant(tmp_path: Path) -> None:
    actor = _examiner(scopes=frozenset({"compliance.evidence_pack.read"}), tenant_id="t-1")
    app = create_app(
        _settings(tmp_path),
        adapter_registry=_memory_registry(),
        actor_binder=_StubBinder(actor),
    )
    async with app.router.lifespan_context(app), _client(app) as client:
        resp = await client.get(_ROUTE, params={**_PARAMS, "scope": "t-2"})
    assert resp.status_code == 404  # cross-tenant — never a 403 hint
    assert resp.json()["detail"]["reason"] == "evidence_pack_not_found"


async def test_evidence_pack_endpoint_503_when_adapters_unavailable(
    tmp_path: Path,
) -> None:
    actor = _examiner(scopes=frozenset({"compliance.evidence_pack.read"}))
    # No adapter_registry => the lifespan sets app.state.adapters = None.
    app = create_app(_settings(tmp_path), actor_binder=_StubBinder(actor))
    async with app.router.lifespan_context(app), _client(app) as client:
        resp = await client.get(_ROUTE, params=_PARAMS)
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "compliance_adapters_unavailable"


def test_compliance_router_not_mounted_without_actor_binder(tmp_path: Path) -> None:
    """Pin 2 — the mount boundary. create_app WITHOUT an actor_binder
    must NOT mount the compliance router: the route is absent from the
    table entirely. A structural route-table check — a request-level 404
    could not distinguish 'not mounted' from 'mounted, path mismatch'."""
    app = create_app(_settings(tmp_path), adapter_registry=_memory_registry())
    assert _ROUTE not in _route_paths(app)
```

- [ ] **Step 2: Run test to verify it fails** — FAIL: `ModuleNotFoundError` /
  unrouted 404 for `cognic_agentos.portal.api.compliance`.

- [ ] **Step 3: Implement the route package**

`src/cognic_agentos/portal/api/compliance/__init__.py` is empty.

`src/cognic_agentos/portal/api/compliance/router.py`:

```python
"""Sprint 9 — compliance route-package composition + shared deps (ADR-006).

`from __future__ import annotations` is DELIBERATELY OMITTED — FastAPI
resolves `Annotated[..., Depends(<closure-local>)]` via inspect.signature;
PEP-563 string annotations break that (standing portal-route invariant —
see portal/api/ui/router.py).
"""

from fastapi import APIRouter, HTTPException, Request

from cognic_agentos.core.config import Settings
from cognic_agentos.db.adapters import Adapters


def _require_adapters(request: Request) -> Adapters:
    """Request-time resolver for the live adapter pool. `app.state.adapters`
    is populated by the lifespan AFTER router mount, so it cannot be
    closure-captured at build time. Fails loud 503 when adapters are not
    built (e.g. create_app called without an adapter_registry). The
    evidence-pack exporter needs both adapters.relational.engine AND
    adapters.secret (vault:// signing-key resolution), so the dependency
    resolves the whole pool per spec §7's request-time adapter dependency."""
    adapters: Adapters | None = getattr(request.app.state, "adapters", None)
    if adapters is None:
        raise HTTPException(status_code=503, detail={"reason": "compliance_adapters_unavailable"})
    return adapters


def build_compliance_routes(*, settings: Settings) -> APIRouter:
    """Compose the examiner compliance endpoints into one router. T6
    wires the evidence-pack endpoint; T7 extends this with the trace
    explorer (the `build_trace_routes` include is added in T7 Step 3)."""
    from cognic_agentos.portal.api.compliance.evidence_pack_routes import (
        build_evidence_pack_routes,
    )

    router = APIRouter()
    router.include_router(build_evidence_pack_routes(settings=settings))
    return router
```

`src/cognic_agentos/portal/api/compliance/evidence_pack_routes.py`:

```python
"""Sprint 9 — GET /api/v1/compliance/evidence-pack (ADR-006).

`from __future__ import annotations` OMITTED — standing portal-route invariant.
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from cognic_agentos.compliance.iso42001.evidence_pack import export_evidence_pack
from cognic_agentos.compliance.iso42001.signing import EvidencePackSigningError
from cognic_agentos.core.config import Settings
from cognic_agentos.db.adapters import Adapters
from cognic_agentos.portal.api.compliance.router import _require_adapters
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope


def build_evidence_pack_routes(*, settings: Settings) -> APIRouter:
    router = APIRouter()
    _require_evidence_scope = RequireScope("compliance.evidence_pack.read")

    @router.get(f"{settings.api_prefix}/compliance/evidence-pack")
    async def evidence_pack(
        actor: Annotated[Actor, Depends(_require_evidence_scope)],
        adapters: Annotated[Adapters, Depends(_require_adapters)],
        scope: Annotated[str, Query()],
        from_: Annotated[datetime, Query(alias="from")],
        to: Annotated[datetime, Query(alias="to")],
    ) -> Response:
        # Cross-tenant invisible: an examiner exports ONLY their own
        # tenant's pack. A scope mismatch returns 404 — never a 403 hint
        # that would let a probe enumerate tenant IDs.
        if actor.tenant_id != scope:
            raise HTTPException(status_code=404, detail={"reason": "evidence_pack_not_found"})
        try:
            tarball = await export_evidence_pack(
                engine=adapters.relational.engine,
                tenant_id=scope,
                period_start=from_,
                period_end=to,
                signing_key_path=settings.evidence_pack_signing_key_path,
                secret_adapter=adapters.secret,
            )
        except EvidencePackSigningError as exc:
            # Signing misconfiguration is a server/operator fault — 500,
            # fail-loud; never a silently-unsigned pack.
            raise HTTPException(
                status_code=500,
                detail={"reason": "evidence_pack_signing_failed", "message": str(exc)},
            ) from exc
        return Response(
            content=tarball,
            media_type="application/gzip",
            headers={
                "Content-Disposition": (f'attachment; filename="evidence-pack-{scope}.tar.gz"')
            },
        )

    return router
```

In `src/cognic_agentos/portal/api/app.py`, mount the compliance router — mirroring the
`build_packs_router` mount, gated on `actor_binder` (the RBAC'd endpoints need a bound
actor). Add inside `create_app`, near the other `app.include_router(...)` calls:

```python
    # Sprint 9 T6: compliance route-package mount (ADR-006). Gated on
    # ``actor_binder is not None`` — the examiner evidence-pack / trace
    # endpoints declare per-route ``RequireScope(...)`` deps that need a
    # bound Actor identity; no ``pack_record_store`` dependency (the
    # compliance surface reads governance chains via the adapter pool,
    # not the pack store).
    if actor_binder is not None:
        from cognic_agentos.portal.api.compliance.router import build_compliance_routes

        app.include_router(build_compliance_routes(settings=settings))
```

- [ ] **Step 4: Run test to verify it passes** — PASS — 5 tests.

- [ ] **Step 5: Commit (halt-before-commit first)**

```bash
git add src/cognic_agentos/portal/api/compliance/__init__.py src/cognic_agentos/portal/api/compliance/evidence_pack_routes.py src/cognic_agentos/portal/api/compliance/router.py src/cognic_agentos/portal/api/app.py tests/unit/portal/api/compliance/
git commit -m "feat(sprint-9): T6 — evidence-pack endpoint + compliance route package"
```

---

## Task 7: Trace explorer endpoint — `trace_routes.py`

**Files:**
- Create: `src/cognic_agentos/portal/api/compliance/trace_routes.py`
- Modify: `src/cognic_agentos/portal/api/compliance/router.py` (include the trace routes)
- Test: `tests/unit/portal/api/compliance/test_trace_explorer.py`

The trace logic is the module-level `walk_trace(engine, *, trace_id, tenant_id)` — a
pure read function unit-tested against a file-backed engine with real seeded rows. The
endpoint-wiring tests (403 / 200 / 503) monkeypatch `walk_trace` (the `:memory:`
isolation reason from T6 applies equally).

- [ ] **Step 1: Write the failing test**

`tests/unit/portal/api/compliance/test_trace_explorer.py`:

```python
"""Sprint 9 T7 — trace explorer: walk_trace data behaviour + endpoint wiring."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditEvent, AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.db.adapters import AdapterRegistry
from cognic_agentos.db.adapters.local_object_store_adapter import LocalObjectStoreAdapter
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.api.compliance.trace_routes import walk_trace
from cognic_agentos.portal.rbac.actor import Actor
from tests.support.adapter_fixtures import (
    InMemoryEmbeddingAdapter,
    InMemoryObservabilityAdapter,
    InMemoryRelationalAdapter,
    InMemorySecretAdapter,
    InMemoryVectorAdapter,
)

#: The trace-explorer route-table path — carries the {trace_id} path-param
#: placeholder, distinct from a concrete request path like /traces/trace-x.
_TRACE_ROUTE = "/api/v1/traces/{trace_id}"

# --- walk_trace data behaviour (file-backed engine, real seeded rows) ---


async def _seeded(
    tmp_path: Path,
) -> tuple[AsyncEngine, AuditStore, DecisionHistoryStore]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'tr.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    return engine, AuditStore(engine), DecisionHistoryStore(engine)


async def test_walk_trace_returns_ordered_timeline(tmp_path: Path) -> None:
    engine, audit, dh = await _seeded(tmp_path)
    await audit.append(
        AuditEvent(
            event_type="a1", request_id="r1", payload={}, tenant_id="t-1", trace_id="trace-x"
        )
    )
    await dh.append(
        DecisionRecord(
            decision_type="d1", request_id="r2", payload={}, tenant_id="t-1", trace_id="trace-x"
        )
    )
    await audit.append(
        AuditEvent(
            event_type="a2", request_id="r3", payload={}, tenant_id="t-1", trace_id="trace-x"
        )
    )
    events = await walk_trace(engine, trace_id="trace-x", tenant_id="t-1")
    assert len(events) == 3
    assert events == sorted(
        events, key=lambda e: (e["created_at"], e["source_chain"], e["sequence"])
    )
    assert {e["event_type"] for e in events} == {"a1", "a2", "d1"}
    assert all("record_id" in e for e in events)  # provenance preserved
    # Hash-chain linkage is exposed, hex-encoded (spec §6.2.1 shape) — an
    # examiner can verify the chain walk, not just read a sorted list.
    for e in events:
        assert len(e["hash"]) == 64 and len(e["prev_hash"]) == 64
        bytes.fromhex(e["hash"])  # valid hex — raises otherwise
        bytes.fromhex(e["prev_hash"])


async def test_walk_trace_excludes_other_tenant_rows(tmp_path: Path) -> None:
    engine, audit, _dh = await _seeded(tmp_path)
    await audit.append(
        AuditEvent(
            event_type="mine", request_id="r1", payload={}, tenant_id="t-1", trace_id="shared"
        )
    )
    await audit.append(
        AuditEvent(
            event_type="theirs", request_id="r2", payload={}, tenant_id="t-2", trace_id="shared"
        )
    )
    events = await walk_trace(engine, trace_id="shared", tenant_id="t-1")
    assert [e["event_type"] for e in events] == ["mine"]


async def test_walk_trace_empty_for_trace_in_other_tenant(tmp_path: Path) -> None:
    engine, audit, _dh = await _seeded(tmp_path)
    await audit.append(
        AuditEvent(event_type="x", request_id="r1", payload={}, tenant_id="t-2", trace_id="only-t2")
    )
    # A t-1 examiner asking for a trace that lives only under t-2 sees
    # nothing — cross-tenant invisible.
    assert await walk_trace(engine, trace_id="only-t2", tenant_id="t-1") == []


# --- endpoint wiring (walk_trace monkeypatched — :memory: isolation) ---


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: object) -> Actor:
        return self._actor


def _memory_registry() -> AdapterRegistry:
    r = AdapterRegistry()
    r.register("relational", "memory", InMemoryRelationalAdapter)
    r.register("vector", "memory", InMemoryVectorAdapter)
    r.register("secret", "memory", InMemorySecretAdapter)
    r.register("embedding", "memory", InMemoryEmbeddingAdapter)
    r.register("observability", "memory", InMemoryObservabilityAdapter)
    r.register("object_store", "local_fs", LocalObjectStoreAdapter)
    return r


def _settings(tmp_path: Path) -> Settings:
    return Settings(  # type: ignore[call-arg]
        _env_file=None,
        db_driver="memory",
        vector_driver="memory",
        secret_driver="memory",
        embed_driver="memory",
        obs_driver="memory",
        database_url=None,
        qdrant_url=None,
        vault_addr=None,
        embedding_base_url=None,
        langfuse_host=None,
        object_store_driver="local_fs",
        local_object_store_root=tmp_path,
    )


def _route_paths(app: FastAPI) -> set[str]:
    return {getattr(route, "path", "") for route in app.routes}


async def test_trace_endpoint_200_with_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """200 path — route path pinned AND the route threads the path-param
    trace_id + the AUTHENTICATED actor's tenant + the live engine into
    walk_trace. The captured kwargs fail the test if the route ever
    swaps actor.tenant_id for client-supplied input (the tenant-
    isolation contract) or drops the engine."""
    captured: dict[str, object] = {}

    async def _fake_walk(
        engine: object, *, trace_id: str, tenant_id: str
    ) -> list[dict[str, object]]:
        captured["engine"] = engine
        captured["trace_id"] = trace_id
        captured["tenant_id"] = tenant_id
        return [
            {
                "source_chain": "audit_event",
                "event_type": "x",
                "sequence": 1,
                "record_id": "rid",
                "created_at": "2026-01-01T00:00:00+00:00",
                "request_id": "r1",
                "prev_hash": "00" * 32,
                "hash": "11" * 32,
                "iso_controls": [],
            }
        ]

    monkeypatch.setattr("cognic_agentos.portal.api.compliance.trace_routes.walk_trace", _fake_walk)
    actor = Actor(
        subject="e",
        tenant_id="t-1",
        scopes=frozenset({"compliance.trace.read"}),
        actor_type="human",
    )
    app = create_app(
        _settings(tmp_path),
        adapter_registry=_memory_registry(),
        actor_binder=_StubBinder(actor),
    )
    assert _TRACE_ROUTE in _route_paths(app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        resp = await client.get("/api/v1/traces/trace-x")
    assert resp.status_code == 200
    body = resp.json()
    assert body["trace_id"] == "trace-x"
    assert body["tenant_id"] == "t-1"
    assert len(body["events"]) == 1
    # Response-field contract: exactly the 3 top-level keys, and each
    # event carries the full 9-field walk_trace record shape verbatim
    # (the route passes walk_trace's output through unreshaped).
    assert set(body) == {"trace_id", "tenant_id", "events"}
    assert set(body["events"][0]) == {
        "source_chain",
        "sequence",
        "record_id",
        "created_at",
        "event_type",
        "request_id",
        "prev_hash",
        "hash",
        "iso_controls",
    }
    # Chain-link values survive the route verbatim — prev_hash / hash are
    # the examiner-critical hash-chain linkage.
    event = body["events"][0]
    assert event["prev_hash"] == "00" * 32
    assert event["hash"] == "11" * 32
    # walk_trace call contract: path-param trace_id, the authenticated
    # actor's tenant (NOT client input), and the live engine.
    assert captured["trace_id"] == "trace-x"
    assert captured["tenant_id"] == "t-1"
    assert captured["engine"] is not None


async def test_trace_endpoint_403_without_scope(tmp_path: Path) -> None:
    actor = Actor(subject="e", tenant_id="t-1", scopes=frozenset(), actor_type="human")
    app = create_app(
        _settings(tmp_path),
        adapter_registry=_memory_registry(),
        actor_binder=_StubBinder(actor),
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        resp = await client.get("/api/v1/traces/trace-x")
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert detail["reason"] == "scope_not_held"
    assert detail["required_scope"] == "compliance.trace.read"


async def test_trace_endpoint_503_when_adapters_unavailable(tmp_path: Path) -> None:
    actor = Actor(
        subject="e",
        tenant_id="t-1",
        scopes=frozenset({"compliance.trace.read"}),
        actor_type="human",
    )
    app = create_app(_settings(tmp_path), actor_binder=_StubBinder(actor))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        resp = await client.get("/api/v1/traces/trace-x")
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "compliance_adapters_unavailable"


def test_trace_router_not_mounted_without_actor_binder(tmp_path: Path) -> None:
    """Mount boundary — create_app WITHOUT an actor_binder must NOT mount
    the compliance router, so the trace route is structurally absent from
    the route table (mirrors the T6 evidence-pack mount-boundary pin)."""
    app = create_app(_settings(tmp_path), adapter_registry=_memory_registry())
    assert _TRACE_ROUTE not in _route_paths(app)
```

- [ ] **Step 2: Run test to verify it fails** — FAIL: `ModuleNotFoundError` for
  `trace_routes`.

- [ ] **Step 3: Implement `trace_routes.py`** (complete module)

`src/cognic_agentos/portal/api/compliance/trace_routes.py`:

```python
"""Sprint 9 — GET /api/v1/traces/{trace_id} (ADR-006).

`from __future__ import annotations` OMITTED — standing portal-route invariant.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.audit import _audit_event
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.db.adapters import Adapters
from cognic_agentos.portal.api.compliance.router import _require_adapters
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope


async def walk_trace(engine: AsyncEngine, *, trace_id: str, tenant_id: str) -> list[dict[str, Any]]:
    """Chain-walk one run's timeline from _audit_event + _decision_history.

    Rows are tenant-filtered — a trace_id present only under another
    tenant yields an empty list (cross-tenant invisible). Ordered by
    (created_at, source_chain, sequence) for an examiner-readable
    timeline. Read-only; no new event store.
    """
    events: list[dict[str, Any]] = []
    async with engine.connect() as conn:
        for source_chain, table in (
            ("audit_event", _audit_event),
            ("decision_history", _decision_history),
        ):
            stmt = (
                select(table)
                .where(table.c.trace_id == trace_id)
                .where(table.c.tenant_id == tenant_id)
            )
            result = await conn.execute(stmt)
            for row in result.fetchall():
                m = row._mapping
                events.append(
                    {
                        "source_chain": source_chain,
                        "sequence": m["sequence"],
                        "record_id": str(m["record_id"]),
                        "created_at": m["created_at"].isoformat(),
                        "event_type": m["event_type"],
                        "request_id": m["request_id"],
                        # Hash-chain linkage — hex-encoded, same shape as
                        # the evidence-pack JSONL (spec §6.2.1). prev_hash
                        # is the predecessor link, hash is this row's hash;
                        # together they let an examiner verify the chain
                        # walk rather than trust a bare sorted list.
                        "prev_hash": m["prev_hash"].hex(),
                        "hash": m["hash"].hex(),
                        "iso_controls": list(m["iso_controls"] or ()),
                    }
                )
    events.sort(key=lambda e: (e["created_at"], e["source_chain"], e["sequence"]))
    return events


def build_trace_routes(*, settings: Settings) -> APIRouter:
    router = APIRouter()
    _require_trace_scope = RequireScope("compliance.trace.read")

    @router.get(f"{settings.api_prefix}/traces/{{trace_id}}")
    async def trace(
        trace_id: str,
        actor: Annotated[Actor, Depends(_require_trace_scope)],
        adapters: Annotated[Adapters, Depends(_require_adapters)],
    ) -> dict[str, Any]:
        # Rows are filtered by the authenticated actor's tenant; a
        # trace_id existing only under another tenant returns an empty
        # timeline — cross-tenant invisible, never a forbidden hint.
        events = await walk_trace(
            adapters.relational.engine, trace_id=trace_id, tenant_id=actor.tenant_id
        )
        return {"trace_id": trace_id, "tenant_id": actor.tenant_id, "events": events}

    return router
```

Then extend `build_compliance_routes` in `router.py` to include the trace router — the
full function becomes:

```python
def build_compliance_routes(*, settings: Settings) -> APIRouter:
    """Compose the examiner compliance endpoints into one router. T6
    wires the evidence-pack endpoint; T7 extends this with the trace
    explorer (the `build_trace_routes` include is added in T7 Step 3)."""
    from cognic_agentos.portal.api.compliance.evidence_pack_routes import (
        build_evidence_pack_routes,
    )
    from cognic_agentos.portal.api.compliance.trace_routes import build_trace_routes

    router = APIRouter()
    router.include_router(build_evidence_pack_routes(settings=settings))
    router.include_router(build_trace_routes(settings=settings))
    return router
```

- [ ] **Step 4: Run test to verify it passes** — PASS — 6 tests (3 `walk_trace` + 3
  endpoint).

- [ ] **Step 5: Commit (halt-before-commit first)**

```bash
git add src/cognic_agentos/portal/api/compliance/trace_routes.py src/cognic_agentos/portal/api/compliance/router.py tests/unit/portal/api/compliance/test_trace_explorer.py
git commit -m "feat(sprint-9): T7 — trace-explorer endpoint"
```

---

## Task 8: ISO-control source-of-truth audit  **(research task — halt for review)**

No code. Produce the authoritative audit of the 8 ADR-006 controls before any tagging
edit (strict requirement #5).

- [ ] **Step 1: Audit each of the 8 controls**

For each `ControlEntry.intended_hooks` entry, grep the codebase for the emission site
and record: does a hook emit the **canonical** `ISO42001.A.x.y` string into
`iso_controls`? In what form (canonical / raw `A.x.y` / absent)?

```bash
grep -rnE "iso_controls *=" src/cognic_agentos/ | grep -v test
grep -rn "ISO42001.A.6.2.5\|ISO42001.A.6.2.6\|ISO42001.A.7.6\|ISO42001.A.8.2\|ISO42001.A.8.5\|ISO42001.A.10.2" src/
```

Known starting points from the spec-phase survey: `A.9.2` covered canonically
(`llm/gateway.py`); `A.7.4` covered canonically (`core/guardrails.py`,
`core/policy/engine.py`) **and** present raw (`A.7.4`) in `protocol/trust_gate.py:672`,
`protocol/plugin_registry.py:616`. The other six (`A.6.2.5`, `A.6.2.6`, `A.7.6`,
`A.8.2`, `A.8.5`, `A.10.2`) require confirmation.

- [ ] **Step 2: Record the audit table**

Write the findings into this plan's Task 8 section (or `docs/superpowers/notes/`): per
control — `covered-canonical` / `covered-raw-needs-reconcile` / `gap`. For each `gap` or
`raw`, name the exact file:line emission site T9 will edit.

- [ ] **Step 3: HALT for review**

Present the audit table to the human. T9's tagging edits are scoped strictly to the
sites this audit names — no casual edits beyond them. No commit (research only).

### T8 outcome (2026-05-22) — Option 1 approved

The audit found the "8/8 hook coverage" premise unachievable: 5 of 8 controls have no
built emission surface, and 3 of those reference code that does not exist
(`core/auto_degradation.py`, `retrieval/citation_verifier.py`, a `compliance_checker`,
`decision_history.export_for_subject`). The authoritative audit table is recorded in
the spec at §9.1.

| Control | `hook_status` | T9 action |
|---|---|---|
| `A.9.2` | `implemented` | none — already canonical (`llm/gateway.py`). |
| `A.7.4` | `implemented` | reconcile raw → canonical: `protocol/trust_gate.py:672`, `protocol/plugin_registry.py:616`, `:638`. |
| `A.6.2.5` | `implemented` | reconcile raw → canonical: `sandbox/audit.py:191`. |
| `A.6.2.6` | `deferred` | none — `portal/rbac/` has no chain-emission surface. |
| `A.7.6` | `deferred` | none — `core/auto_degradation.py` / `compliance_checker` do not exist. |
| `A.8.2` | `deferred` | none — `retrieval/citation_verifier.py` does not exist. |
| `A.8.5` | `deferred` | none — no A.8.5 emission on the gateway completion path. |
| `A.10.2` | `deferred` | none — no `decision_history.export_for_subject`. |

**Decision:** human approved **Option 1** — Sprint 9 ships honest partial coverage
(registry 8/8, evidenced 3/8 + 5 explicit `deferred`). The spec was amended first (§2,
§4, §9, §10, §11, AC6); T9 is rescoped below. The 5 `deferred` controls are wired in the
sprints that build their hook surfaces — NOT retrofitted here, NOT faked.

---

## Task 9: Control-tagging — canonicalize evidence tags + `hook_status`  **(STOP-RULE: governance-tag edits)**

Rescoped per the T8 audit + Option-1 decision (see the T8 outcome above + spec §9). T9
canonicalizes the 4 raw-form emission sites of the 3 `implemented` controls and adds the
registry `hook_status` field — it does **not** fake 8/8.

**Files:**
- Modify: `src/cognic_agentos/compliance/iso42001/controls.py` — add `hook_status` to `ControlEntry` + the 8 entries (amends T1)
- Modify: `src/cognic_agentos/compliance/iso42001/__init__.py` — re-export `HookStatus`
- Modify: `src/cognic_agentos/sandbox/audit.py` — raw `A.6.2.5` → canonical (**sandbox enforcement boundary**)
- Modify: `src/cognic_agentos/protocol/trust_gate.py` — raw `A.7.4` → canonical (**stop-rule / critical-control**)
- Modify: `src/cognic_agentos/protocol/plugin_registry.py` — raw `A.7.4` ×2 → canonical (**stop-rule / critical-control**)
- Test: `tests/unit/compliance/iso42001/test_control_mapping.py`

The three emission-site files are governance-visible — string-only evidence-tag edits,
but the T9 halt summary MUST request explicit human stop-rule review of all three.

- [ ] **Step 1: Rework the registry — `controls.py`**

Add a closed-enum `HookStatus = Literal["implemented", "deferred"]` + two fields on
`ControlEntry` — `hook_status` and `deferred_reason: str` (a short reason on every
`deferred` entry, `""` for `implemented`; the registry-resident form of §9.1's reason).
Mark A.9.2 / A.7.4 / A.6.2.5 `"implemented"` (`deferred_reason=""`); A.6.2.6 / A.7.6 /
A.8.2 / A.8.5 / A.10.2 `"deferred"` with their §9.1 reason.

Rework `audit_coverage` to the implemented/deferred model — the T1 form
(`audit_coverage(emitted) -> dict[str, bool]`, "covered iff emitted") wrongly reports
every `deferred` control as `False`, indistinguishable from a real gap. Replace it with
a frozen `ControlCoverage` (`control_id`, `hook_status`, `emitted: bool`,
`deferred_reason`) and `audit_coverage(emitted: set[str]) -> dict[str, ControlCoverage]`
— one honest record per control. An `implemented` control is correctly covered iff
`emitted`; a `deferred` control is correctly recorded iff NOT `emitted` AND
`deferred_reason` is non-empty.

All four new names are **registry-only** — NOT added to the evidence-pack manifest;
`evidence_pack._per_control_coverage` is untouched. Re-export `HookStatus` +
`ControlCoverage` from `__init__.py`.

- [ ] **Step 2: Write the failing test — `test_control_mapping.py`**

`test_control_mapping.py`:
- builds the observed canonical-emission set by reading the actual emission sites the
  T8 audit named (NOT by re-reading the registry — so a raw-form regression is caught);
- drives the assertions through `audit_coverage(observed)`: every `implemented` control
  has `emitted is True`; every `deferred` control has `emitted is False`,
  `hook_status == "deferred"`, and a non-empty `deferred_reason`; every `implemented`
  control has `deferred_reason == ""`;
- asserts the registry still holds all 8 controls (`control_ids()` unchanged);
- asserts no raw `("A.x.y",)` form survives at the 4 audited sites.

- [ ] **Step 3: Run test to verify it fails** — FAIL: the 3 raw sites still emit
  `("A.x.y",)`; `hook_status` does not exist.

- [ ] **Step 4: Reconcile the 4 raw emission sites**

String-only edits, explicit at each call site:
- `sandbox/audit.py:191` — `iso_controls=("A.6.2.5",)` → `iso_controls=("ISO42001.A.6.2.5",)`
- `protocol/trust_gate.py:672` — `iso_controls=("A.7.4",)` → `iso_controls=("ISO42001.A.7.4",)`
- `protocol/plugin_registry.py:616` + `:638` — `iso_controls=("A.7.4",)` → `iso_controls=("ISO42001.A.7.4",)`

Do **not** touch non-ADR-006 codes (`A.5.31` / `A.5.32` in `protocol/ui_events.py` /
`packs/lifecycle.py`). No auto-lookup added to `AuditStore` / `DecisionHistoryStore`.

- [ ] **Step 5: Run test to verify it passes** — PASS — 3 implemented canonical, 5
  deferred recorded, registry 8/8.

- [ ] **Step 6: Commit (halt-before-commit first — STOP-RULE summary)**

The halt summary MUST flag the 3 governance-visible emission-site files
(`sandbox/audit.py`, `protocol/trust_gate.py`, `protocol/plugin_registry.py`) for
explicit human stop-rule review.

```bash
git add src/cognic_agentos/compliance/iso42001/controls.py src/cognic_agentos/compliance/iso42001/__init__.py src/cognic_agentos/sandbox/audit.py src/cognic_agentos/protocol/trust_gate.py src/cognic_agentos/protocol/plugin_registry.py tests/unit/compliance/iso42001/test_control_mapping.py
git commit -m "feat(sprint-9): T9 — canonicalize ADR-006 evidence tags + hook_status (STOP-RULE)"
```

---

## Task 10: Gate ladder + critical-controls promotion + BUILD_PLAN status

**Files:**
- Modify: `tools/check_critical_coverage.py` (4 new entries), `docs/BUILD_PLAN.md` §752

- [ ] **Step 1: Add the 4 compliance modules to the coverage gate**

In `tools/check_critical_coverage.py`, append to `_CRITICAL_FILES`:

```python
    ("src/cognic_agentos/compliance/iso42001/controls.py", 0.95, 0.90),
    ("src/cognic_agentos/compliance/iso42001/merkle.py", 0.95, 0.90),
    ("src/cognic_agentos/compliance/iso42001/signing.py", 0.95, 0.90),
    ("src/cognic_agentos/compliance/iso42001/evidence_pack.py", 0.95, 0.90),
```

Update any count-guard test for `_CRITICAL_FILES` length (73 → 77).

- [ ] **Step 2: Run the full lint + type gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`
Expected: all clean.

- [ ] **Step 3: Run the full suite with fresh coverage data**

Run: `uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json -m "not postgres and not oracle" -q`
Expected: PASS; writes fresh `coverage.json`.

- [ ] **Step 4: Run the critical-controls coverage gate**

Run: `uv run python tools/check_critical_coverage.py`
Expected: PASS — all 77 modules meet 95/90, including the 4 new compliance modules. If
any of the 4 is below floor, add focused negative-path tests in the SAME task and re-run
(per `feedback_verify_promotion_meets_floor_at_promotion_time`).

- [ ] **Step 5: Update `docs/BUILD_PLAN.md` §752**

Flip the Sprint 9 entry to CLOSED with the branch + critical-controls 73→77 note.

- [ ] **Step 6: Verify acceptance criteria AC1–AC9** (spec §12), each backed by a passing
  test or gate result.

- [ ] **Step 7: Commit (halt-before-commit first)**

```bash
git add tools/check_critical_coverage.py docs/BUILD_PLAN.md <count-guard test if changed>
git commit -m "chore(sprint-9): T10 — critical-controls gate uplift 73->77 + BUILD_PLAN close"
```

---

## Self-Review

**1. Spec coverage.** §3 module structure → T1-T4, T6-T7; §4 registry → T1; §5 Merkle →
T2; §6 evidence pack + signing → T3-T4; §7 read seam (`engine: AsyncEngine`,
`_require_adapters`) → T6; §8 endpoints + RBAC → T5-T7; §9 tagging reconciliation →
T8-T9 (rescoped per the T8 audit — canonicalize-what-exists + explicit deferrals);
§10 critical-controls/stop-rule → T4/T5/T9/T10 flags; §11 testing → tests in every
task; §12 AC1-AC9 → T10 Step 6. No gaps.

**2. Placeholder scan.** Every code task carries literal complete code — the registry
(T1), Merkle (T2), `signing.py` (T3, all functions incl. `_resolve_vault` /
`_resolve_pem_path` / `cosign_sign_blob` with tempfile handling + subprocess argv +
output validation), `evidence_pack.py` (T4, all helpers + the exporter), RBAC (T5),
endpoints (T6-T7) — and literal test snippets for the T4 happy path + tenant/window
completeness. T8 is a research task with an exact grep procedure. No "handle edge cases"
/ "similar to Task N" / bare TODOs / "written when executed" / "executor reads X".

**3. Type consistency.** `ComplianceControlId` (T1) ↔ `control_ids()` ↔ `audit_coverage`
(T1, T9). `merkle_root` / `inclusion_proof` / `verify_inclusion` signatures consistent
T2 ↔ T4. `ComplianceRBACScope` / `EXAMINER_COMPLIANCE_SCOPES` (T5) ↔ endpoint guards
(T6, T7) ↔ `RequireScope` param widening (T5 Step 4). `export_evidence_pack` signature
(T4) ↔ endpoint call (T6). `_require_adapters` (T6 `router.py`) ↔ reuse (T7).
`walk_trace` (T7) defined + monkeypatched consistently. `evidence_pack_signing_key_path`
(T3) ↔ `export_evidence_pack` (T4). `_VAULT_KEY_FIELD = "key"` (T3) ↔ the vault test
fixture (T3). Consistent.
