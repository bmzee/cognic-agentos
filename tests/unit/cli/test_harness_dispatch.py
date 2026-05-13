"""Sprint-7B.1 T6b — per-kind dry-run dispatch regressions.

Pins the four-kind harness dispatch table now that T6b wired Skill /
Agent / Hook dispatch through public SDK seams (Tool was the only
green-path kind pre-T6b; T6a widened the kind gate but left dispatch
non-green for skill / agent / hook until T6b's per-kind impls landed).

Coverage:

  Section A — green-path per-kind dispatch (4 tests; one per kind):
    - tool reference pack dispatch dry-run succeeds.
    - skill reference pack dispatch dry-run succeeds via
      ``Skill.__init__(*, tools=ToolRegistry)`` + ``await
      skill.execute()``.
    - agent reference pack dispatch dry-run succeeds via
      ``await agent.handle(payload, task=TaskRecord)``.
    - hook reference pack dispatch dry-run succeeds via the public
      ``await hook.invoke(context, payload)`` seam (NOT the abstract
      ``_invoke`` directly).

  Section B — Hook public-seam validator harness-seam pinning (3 tests):
    These regressions pin the HARNESS dispatch path's correct routing
    of SDK validator exceptions. Each goes through ``run_harness``
    (not direct ``Hook.invoke`` calls) so the harness's
    ``harness_dispatch_failed`` routing + ``failure_message``
    exception-name surfacing are pinned alongside the SDK validator's
    invariants.

      - pre-``_invoke`` context validation: monkeypatch
        ``_DISPATCH_HOOK_CONTEXT`` to ``None``; instrumented
        ``_invoke`` MUST NOT be called; ``failure_message`` contains
        ``"HookContextError"``.
      - pre-``_invoke`` payload validation: same shape against
        ``_DISPATCH_HOOK_PAYLOAD``; ``failure_message`` contains
        ``"HookPayloadError"``.
      - post-``_invoke`` result-shape validation: synthetic hook pack
        whose ``_invoke`` returns a malformed ``HookResult`` (e.g.,
        ``decision="redact"`` with ``redacted_payload=None``); the
        SDK's post-``_invoke`` validator fires AFTER ``_invoke``
        returns; ``failure_message`` contains ``"HookResultShapeError"``.

  Section C — payload-never-logged regression (1 test):
    Pins the ADR-017 + Doctrine Lock E invariant (Sprint-7A2 T7
    AST-walk regression at ``tests/architecture/
    test_hook_payload_never_logged.py``) at the harness layer: when a
    hook returns ``HookResult(decision="mask", redacted_payload=
    <sensitive bytes>)``, the harness's conformance report MUST NOT
    serialize the raw payload bytes — only safe metadata indicators
    (decision / policy_reason / redacted_payload_present / audit-key-
    names).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import cognic_agentos.cli.test_harness as harness_module
from cognic_agentos.cli import app
from cognic_agentos.cli.test_harness import run_harness

# Reference packs shipped under examples/ (single-sourced — mirrors
# tests/unit/cli/test_reference_packs_full_lifecycle_green.py).
_REPO_ROOT: Path = Path(__file__).resolve().parents[3]
_EXAMPLES_ROOT: Path = _REPO_ROOT / "examples"
_TOOL_PACK: Path = _EXAMPLES_ROOT / "cognic-tool-example-minimal"
_SKILL_PACK: Path = _EXAMPLES_ROOT / "cognic-skill-example-minimal"
_AGENT_PACK: Path = _EXAMPLES_ROOT / "cognic-agent-example-minimal"
_HOOK_PACK: Path = _EXAMPLES_ROOT / "cognic-hook-example-minimal"


# ---------------------------------------------------------------------------
# Helper: synthesize a hook pack on disk with a custom hook.py body
# ---------------------------------------------------------------------------


def _stage_reference_pack_clone(source_pack: Path, target_root: Path) -> Path:
    """Copy a reference pack into ``target_root`` so the dispatch
    test runs against an isolated copy. The harness's
    :func:`_dispatch_one` snapshots ``sys.modules`` at entry +
    pops every key added during the dispatch on exit, so repeated
    in-process invocations against distinct cloned trees stay
    clean."""
    import shutil

    cloned = target_root / source_pack.name
    shutil.copytree(source_pack, cloned)
    return cloned


def _write_synthetic_hook_pack(
    target_dir: Path,
    *,
    hook_module_body: str,
    pack_id: str = "cognic-hook-synthetic",
    module_name: str = "cognic_hook_synthetic",
    class_name: str = "SyntheticHook",
) -> Path:
    """Materialise a synthetic hook pack on disk with a custom
    hook.py body. Used by Section-B pinning regressions to load hooks
    whose ``_invoke`` is instrumented (counter-writing) or
    malformed (returns invalid HookResult shapes). The pack is NOT
    sign-stamped or validate-clean; tests monkeypatch
    ``run_validators`` to return ``[]`` so the harness reaches Step
    1.5 + Step 4 dispatch in isolation."""
    target_dir.mkdir(parents=True, exist_ok=True)

    manifest = f'[pack]\npack_id = "{pack_id}"\nschema_version = 1\nkind = "hook"\n'
    (target_dir / "cognic-pack-manifest.toml").write_text(manifest)

    pyproject = (
        "[project]\n"
        f'name = "{pack_id}"\n'
        'version = "0.0.0"\n'
        "\n"
        f'[project.entry-points."cognic.hooks"]\n'
        f'synthetic_hook = "{module_name}.hook:{class_name}"\n'
    )
    (target_dir / "pyproject.toml").write_text(pyproject)

    module_dir = target_dir / "src" / module_name
    module_dir.mkdir(parents=True, exist_ok=True)
    (module_dir / "__init__.py").write_text(f"from {module_name}.hook import {class_name}\n")
    (module_dir / "hook.py").write_text(hook_module_body)
    return target_dir


def _write_synthetic_agent_pack(
    target_dir: Path,
    *,
    agent_module_body: str,
    pack_id: str = "cognic-agent-synthetic",
    module_name: str = "cognic_agent_synthetic",
    class_name: str = "SyntheticAgent",
) -> Path:
    """Materialise a synthetic agent pack on disk with a custom
    agent.py body. Used by the R1-round payload-digest regression
    to load an agent whose ``handle()`` asserts the harness threaded
    the correct ``sha256(payload)`` digest into the TaskRecord."""
    target_dir.mkdir(parents=True, exist_ok=True)

    manifest = f'[pack]\npack_id = "{pack_id}"\nschema_version = 1\nkind = "agent"\n'
    (target_dir / "cognic-pack-manifest.toml").write_text(manifest)

    pyproject = (
        "[project]\n"
        f'name = "{pack_id}"\n'
        'version = "0.0.0"\n'
        "\n"
        f'[project.entry-points."cognic.agents"]\n'
        f'synthetic_agent = "{module_name}.agent:{class_name}"\n'
    )
    (target_dir / "pyproject.toml").write_text(pyproject)

    module_dir = target_dir / "src" / module_name
    module_dir.mkdir(parents=True, exist_ok=True)
    (module_dir / "__init__.py").write_text(f"from {module_name}.agent import {class_name}\n")
    (module_dir / "agent.py").write_text(agent_module_body)
    return target_dir


def _write_synthetic_skill_pack(
    target_dir: Path,
    *,
    skill_module_body: str,
    pack_id: str = "cognic-skill-synthetic",
    module_name: str = "cognic_skill_synthetic",
    class_name: str = "SyntheticSkill",
) -> Path:
    """Materialise a synthetic skill pack on disk with a custom
    skill.py body. Used by the R1-round per-name-identity regression
    to load a multi-tool skill whose ``execute()`` asserts each
    ``self._tools.get(name).name`` matches the requested key."""
    target_dir.mkdir(parents=True, exist_ok=True)

    manifest = f'[pack]\npack_id = "{pack_id}"\nschema_version = 1\nkind = "skill"\n'
    (target_dir / "cognic-pack-manifest.toml").write_text(manifest)

    pyproject = (
        "[project]\n"
        f'name = "{pack_id}"\n'
        'version = "0.0.0"\n'
        "\n"
        f'[project.entry-points."cognic.skills"]\n'
        f'synthetic_skill = "{module_name}.skill:{class_name}"\n'
    )
    (target_dir / "pyproject.toml").write_text(pyproject)

    module_dir = target_dir / "src" / module_name
    module_dir.mkdir(parents=True, exist_ok=True)
    (module_dir / "__init__.py").write_text(f"from {module_name}.skill import {class_name}\n")
    (module_dir / "skill.py").write_text(skill_module_body)
    return target_dir


# Body templates for synthetic hook subclasses
# ---------------------------------------------------------------------------


def _instrumented_hook_body(counter_file: Path, *, class_name: str = "SyntheticHook") -> str:
    """Hook body whose ``_invoke`` writes to a counter file each time
    it is called. Used by pre-``_invoke`` context/payload validator
    regressions: after dispatch with bad context/payload, the counter
    file MUST still read "0" because the SDK validator fires BEFORE
    ``_invoke`` runs."""
    return f"""from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from cognic_agentos.cli._governance_vocab import HookPhase
from cognic_agentos.sdk.hook import Hook, HookContext, HookResult


_COUNTER_FILE = Path({str(counter_file)!r})


class {class_name}(Hook):
    hook_id: ClassVar[str] = "synthetic_instrumented"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        # File-based counter so the increment survives the harness's
        # sys.modules cleanup between dispatch slots.
        current = int(_COUNTER_FILE.read_text() or "0")
        _COUNTER_FILE.write_text(str(current + 1))
        return HookResult(
            decision="pass",
            redacted_payload=None,
            policy_reason=None,
        )
"""


def _malformed_result_hook_body(*, class_name: str = "SyntheticHook") -> str:
    """Hook body whose ``_invoke`` returns a malformed HookResult:
    ``decision="redact"`` with ``redacted_payload=None`` violates the
    decision-↔-fields invariant. The SDK's post-``_invoke`` validator
    fires AFTER ``_invoke`` returns + raises ``HookResultShapeError``."""
    return f"""from __future__ import annotations

from typing import ClassVar

from cognic_agentos.cli._governance_vocab import HookPhase
from cognic_agentos.sdk.hook import Hook, HookContext, HookResult


class {class_name}(Hook):
    hook_id: ClassVar[str] = "synthetic_malformed_result"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        del context, payload
        # decision="redact" REQUIRES redacted_payload to be bytes;
        # passing None violates the SDK invariant + the post-_invoke
        # validator raises HookResultShapeError.
        return HookResult(
            decision="redact",
            redacted_payload=None,
            policy_reason=None,
        )
"""


def _mask_hook_with_sensitive_payload_body(*, class_name: str = "SyntheticHook") -> str:
    """Hook body whose ``_invoke`` returns a well-formed HookResult
    with ``decision="mask"`` + a ``redacted_payload`` carrying
    deterministic sentinel bytes. Used by the payload-never-logged
    regression: the harness MUST NOT serialize the sentinel bytes
    into the conformance report's response_keys / JSON payload."""
    return f"""from __future__ import annotations

from typing import ClassVar

from cognic_agentos.cli._governance_vocab import HookPhase
from cognic_agentos.sdk.hook import Hook, HookContext, HookResult


class {class_name}(Hook):
    hook_id: ClassVar[str] = "synthetic_mask"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        del context, payload
        # The sentinel bytes must NEVER appear in any serialised
        # form of the harness conformance report. Pinned by the
        # Section-C regression in this file.
        return HookResult(
            decision="mask",
            redacted_payload=b"SENTINEL_HARNESS_DISPATCH_REDACTED_PAYLOAD_BYTES",
            policy_reason=None,
        )
"""


# ---------------------------------------------------------------------------
# Section A — green-path per-kind dispatch (one per kind)
# ---------------------------------------------------------------------------


def test_run_harness_against_tool_reference_pack_dispatches_green(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tool reference pack — Wave-1 dispatch path unchanged by T6b.
    Pinned here so the regression suite catches an accidental break
    of the tool path when per-kind dispatch branches landed.
    Monkeypatches ``run_validators`` to return ``[]`` so this test
    isolates dispatch from validate (the lifecycle-green suite
    covers the full validate+sign+harness+verify pipeline; this is
    the unit-level dispatch slice)."""
    monkeypatch.setattr(harness_module, "run_validators", lambda _pack_path: [])
    cloned = _stage_reference_pack_clone(_TOOL_PACK, tmp_path)
    report = run_harness(cloned)
    assert report.overall_status == "pass", report
    assert report.pack_kind == "tool"
    assert len(report.dispatch_results) == 1
    assert report.dispatch_results[0].status == "pass"


def test_run_harness_against_skill_reference_pack_dispatches_green(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Skill reference pack — T6b green path. Instantiates
    ``ExampleMinimalSkill(tools=<no-op-registry>)`` (Skill.__init__
    cross-checks declared_tools against the registry per R5 P2 #3),
    awaits ``skill.execute()`` (the reference skill calls its
    declared tool via ``self._tools.get("example_minimal")`` +
    returns ``{"composed": <tool-result>}``)."""
    monkeypatch.setattr(harness_module, "run_validators", lambda _pack_path: [])
    cloned = _stage_reference_pack_clone(_SKILL_PACK, tmp_path)
    report = run_harness(cloned)
    assert report.overall_status == "pass", report
    assert report.pack_kind == "skill"
    assert len(report.dispatch_results) == 1
    assert report.dispatch_results[0].status == "pass"


def test_run_harness_against_agent_reference_pack_dispatches_green(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Agent reference pack — T6b green path. Instantiates the agent
    (abc.ABC no-arg ``__init__``), awaits ``agent.handle(payload=b"",
    task=<synthetic TaskRecord>)`` (the reference agent ignores both
    + returns ``{"text": "ok"}``)."""
    monkeypatch.setattr(harness_module, "run_validators", lambda _pack_path: [])
    cloned = _stage_reference_pack_clone(_AGENT_PACK, tmp_path)
    report = run_harness(cloned)
    assert report.overall_status == "pass", report
    assert report.pack_kind == "agent"
    assert len(report.dispatch_results) == 1
    assert report.dispatch_results[0].status == "pass"


def test_run_harness_against_hook_reference_pack_dispatches_green(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hook reference pack — T6b green path. Instantiates the hook
    (abc.ABC no-arg ``__init__``), awaits ``hook.invoke(context,
    payload)`` (the PUBLIC seam at sdk/hook.py:347 that runs the
    three SDK validator phases before + after ``_invoke``). The
    reference hook returns ``HookResult(decision="pass", ...)`` which
    clears the post-``_invoke`` decision-↔-fields invariant."""
    monkeypatch.setattr(harness_module, "run_validators", lambda _pack_path: [])
    cloned = _stage_reference_pack_clone(_HOOK_PACK, tmp_path)
    report = run_harness(cloned)
    assert report.overall_status == "pass", report
    assert report.pack_kind == "hook"
    assert len(report.dispatch_results) == 1
    assert report.dispatch_results[0].status == "pass"


# ---------------------------------------------------------------------------
# Section B — Hook public-seam validator harness-seam pinning
# ---------------------------------------------------------------------------


def test_hook_dispatch_with_invalid_context_fires_hook_context_error_before_invoke(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Harness-seam pin — when the harness's
    ``_DISPATCH_HOOK_CONTEXT`` is somehow ``None`` (typo /
    monkeypatch-from-test / future bug), the SDK's
    ``_validate_hook_context`` at sdk/hook.py:221-231 raises
    ``HookContextError`` BEFORE the subclass's ``_invoke`` runs.

    The harness's exception-handling path catches the exception +
    routes to ``failure_reason="harness_dispatch_failed"`` with the
    exception class name in ``failure_message``. ``_invoke`` is
    instrumented via a file-based counter; after dispatch the
    counter MUST read "0" (proves the SDK validator short-circuited
    before ``_invoke`` was reached)."""
    monkeypatch.setattr(harness_module, "run_validators", lambda _pack_path: [])
    monkeypatch.setattr(harness_module, "_DISPATCH_HOOK_CONTEXT", None)

    counter_file = tmp_path / "invoke_counter.txt"
    counter_file.write_text("0")
    pack_dir = tmp_path / "synthetic_pack"
    _write_synthetic_hook_pack(
        pack_dir,
        hook_module_body=_instrumented_hook_body(counter_file),
    )

    report = run_harness(pack_dir)

    assert counter_file.read_text() == "0", (
        "instrumented _invoke was called despite invalid context; the SDK's "
        "pre-_invoke context validator should have raised HookContextError "
        "before _invoke ran."
    )
    assert len(report.dispatch_results) == 1
    failed = report.dispatch_results[0]
    assert failed.status == "fail"
    assert failed.failure_reason == "harness_dispatch_failed"
    assert failed.failure_message is not None
    assert "HookContextError" in failed.failure_message, failed.failure_message


def test_hook_dispatch_with_invalid_payload_fires_hook_payload_error_before_invoke(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Harness-seam pin — when the harness's
    ``_DISPATCH_HOOK_PAYLOAD`` is somehow ``None``, the SDK's
    ``_validate_hook_payload`` at sdk/hook.py:234-241 raises
    ``HookPayloadError`` BEFORE ``_invoke`` runs. Same shape as the
    context-validation pin: instrumented ``_invoke`` counter MUST
    read "0" + harness routes via ``harness_dispatch_failed`` +
    ``failure_message`` contains ``"HookPayloadError"``."""
    monkeypatch.setattr(harness_module, "run_validators", lambda _pack_path: [])
    monkeypatch.setattr(harness_module, "_DISPATCH_HOOK_PAYLOAD", None)

    counter_file = tmp_path / "invoke_counter.txt"
    counter_file.write_text("0")
    pack_dir = tmp_path / "synthetic_pack"
    _write_synthetic_hook_pack(
        pack_dir,
        hook_module_body=_instrumented_hook_body(counter_file),
    )

    report = run_harness(pack_dir)

    assert counter_file.read_text() == "0", (
        "instrumented _invoke was called despite invalid payload; the SDK's "
        "pre-_invoke payload validator should have raised HookPayloadError "
        "before _invoke ran."
    )
    assert len(report.dispatch_results) == 1
    failed = report.dispatch_results[0]
    assert failed.status == "fail"
    assert failed.failure_reason == "harness_dispatch_failed"
    assert failed.failure_message is not None
    assert "HookPayloadError" in failed.failure_message, failed.failure_message


def test_hook_dispatch_with_malformed_invoke_result_fires_hook_result_shape_error_after_invoke(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Harness-seam pin — when the loaded hook's ``_invoke`` returns
    a malformed ``HookResult`` (``decision="redact"`` with
    ``redacted_payload=None`` violates the decision-↔-fields
    invariant), the SDK's ``_validate_hook_result`` at
    sdk/hook.py:244-288 fires AFTER ``_invoke`` returns + raises
    ``HookResultShapeError``. The harness routes via
    ``harness_dispatch_failed`` + ``failure_message`` contains
    ``"HookResultShapeError"``. NOT monkeypatching dispatch
    constants — this is the SDK's post-``_invoke`` validator firing
    against a real malformed subclass return."""
    monkeypatch.setattr(harness_module, "run_validators", lambda _pack_path: [])

    pack_dir = tmp_path / "synthetic_pack"
    _write_synthetic_hook_pack(
        pack_dir,
        hook_module_body=_malformed_result_hook_body(),
    )

    report = run_harness(pack_dir)

    assert len(report.dispatch_results) == 1
    failed = report.dispatch_results[0]
    assert failed.status == "fail"
    assert failed.failure_reason == "harness_dispatch_failed"
    assert failed.failure_message is not None
    assert "HookResultShapeError" in failed.failure_message, failed.failure_message


# ---------------------------------------------------------------------------
# Section C — payload-never-logged regression (ADR-017 + Doctrine Lock E)
# ---------------------------------------------------------------------------


def test_hook_dispatch_report_never_carries_redacted_payload_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Payload-never-logged invariant pin at the harness layer.

    ADR-017 + Doctrine Lock E forbid hook payload bytes from
    appearing in audit / telemetry / report surfaces. The Sprint-7A2
    T7 AST-walk regression at
    ``tests/architecture/test_hook_payload_never_logged.py`` enforces
    this on the runtime dispatcher; T6b extends the invariant to the
    harness's conformance report:

      - The harness's hook dispatch dry-run MUST NOT serialize the
        raw ``redacted_payload`` bytes into ``DispatchResult.outcome``,
        nor into the CLI's ``--json`` payload.
      - Safe metadata indicators are acceptable: ``decision`` (closed-
        enum string), ``policy_reason`` (string), ``redacted_payload_present``
        (bool), ``audit_metadata_keys`` (tuple of key names, not values).
      - The sentinel byte string returned by the synthetic hook MUST
        NOT appear anywhere in the rendered JSON payload."""
    monkeypatch.setattr(harness_module, "run_validators", lambda _pack_path: [])

    pack_dir = tmp_path / "synthetic_pack"
    _write_synthetic_hook_pack(
        pack_dir,
        hook_module_body=_mask_hook_with_sensitive_payload_body(),
    )

    # Run via the Typer CLI so the JSON serialisation path runs end-
    # to-end (the in-process run_harness() builds the report; the
    # CLI's --json renders it for downstream CI parsers; both
    # surfaces must honor the invariant).
    runner = CliRunner()
    result = runner.invoke(app, ["test-harness", "--json", str(pack_dir)])
    assert result.exit_code == 0, (
        f"harness rejected mask-decision hook: exit={result.exit_code} "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )

    sentinel = "SENTINEL_HARNESS_DISPATCH_REDACTED_PAYLOAD_BYTES"
    assert sentinel not in result.stdout, (
        "harness JSON payload leaked redacted_payload bytes into the "
        "conformance report — ADR-017 + Doctrine Lock E forbid hook "
        "payload bytes from appearing in audit / telemetry / report "
        "surfaces."
    )
    payload = json.loads(result.stdout)
    dispatch_results = payload.get("dispatch_results", [])
    assert len(dispatch_results) == 1
    outcome = dispatch_results[0].get("outcome", {})
    response_keys = outcome.get("response_keys", [])
    # The safe-metadata keys are acceptable; the raw bytes-carrying
    # key ``redacted_payload`` MUST NOT appear.
    assert "redacted_payload" not in response_keys, (
        f"response_keys carries the raw bytes-key name 'redacted_payload'; "
        f"safe report shape uses 'redacted_payload_present' indicator only. "
        f"response_keys={response_keys!r}"
    )
    # Positive presence: the safe indicator key + the closed-enum decision
    # MUST appear so downstream consumers can route on them.
    assert "decision" in response_keys, response_keys
    assert "redacted_payload_present" in response_keys, response_keys


# ---------------------------------------------------------------------------
# Section D — R1 reviewer regressions: payload-digest + per-name identity
# ---------------------------------------------------------------------------


def test_agent_dispatch_task_record_payload_digest_matches_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R1 reviewer P2 pin — the harness's
    ``_DISPATCH_AGENT_TASK_RECORD.payload_digest`` MUST equal
    ``hashlib.sha256(_DISPATCH_AGENT_PAYLOAD).hexdigest()`` to match
    the A2A source-of-truth contract at
    ``protocol/a2a_endpoint.py:436`` + ``:662``. Earlier draft
    initialised the digest to ``""`` regardless of payload — a
    reasonable production agent that cross-checks the envelope
    against the supplied payload would refuse the call.

    Synthetic agent asserts the lockstep inside ``handle()``: if
    the digest drifts, ``AssertionError`` propagates → harness
    routes to ``harness_dispatch_failed``. Green dispatch proves
    the contract holds end-to-end."""
    monkeypatch.setattr(harness_module, "run_validators", lambda _pack_path: [])

    agent_body = """from __future__ import annotations

import hashlib
from typing import Any, ClassVar

from cognic_agentos.protocol.a2a_capability_negotiation import A2ACapabilities
from cognic_agentos.protocol.a2a_endpoint import TaskRecord
from cognic_agentos.sdk.agent import Agent


class SyntheticAgent(Agent):
    name: ClassVar[str] = "synthetic_digest_check"
    declared_capabilities: ClassVar[A2ACapabilities] = A2ACapabilities(
        capabilities_supported=(),
        streaming=False,
        push_notifications=False,
        extended_agent_card=False,
        artifacts_supported=False,
        extensions=(),
        deferred_wave2_features=(),
    )

    async def handle(self, payload: bytes, *, task: TaskRecord) -> dict[str, Any]:
        expected = hashlib.sha256(payload).hexdigest()
        if task.payload_digest != expected:
            raise AssertionError(
                f"task.payload_digest={task.payload_digest!r} does not match "
                f"hashlib.sha256(payload).hexdigest()={expected!r}; the harness "
                f"violated the A2A payload-digest contract."
            )
        return {"digest_matched": True}
"""

    pack_dir = tmp_path / "synthetic_agent_pack"
    _write_synthetic_agent_pack(pack_dir, agent_module_body=agent_body)
    report = run_harness(pack_dir)

    assert report.overall_status == "pass", (
        f"agent dispatch failed; payload_digest likely drifted. report={report!r}"
    )
    assert len(report.dispatch_results) == 1
    assert report.dispatch_results[0].status == "pass"


def test_skill_dispatch_multi_tool_registry_returns_per_name_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R1 reviewer P3 pin — each declared tool name resolves to a
    :class:`Tool` whose ``.name`` matches the requested key EXACTLY.
    Earlier draft returned a singleton ``_HarnessFixtureNoOpTool``
    whose ``name`` was a constant regardless of key; a future skill
    calling ``self._tools.get(name).name`` would have seen wrong
    identity (e.g., ``self._tools.get("alpha").name ==
    "harness_dispatch_no_op_tool"`` instead of ``"alpha"``).

    Synthetic multi-tool skill asserts identity inside
    ``execute()``: if the registry returns wrong-named tools for
    any declared name, ``AssertionError`` propagates → harness
    routes to ``harness_dispatch_failed``. Green dispatch proves
    the contract holds for both declared tools (``alpha`` +
    ``beta``)."""
    monkeypatch.setattr(harness_module, "run_validators", lambda _pack_path: [])

    skill_body = """from __future__ import annotations

from typing import Any, ClassVar

from cognic_agentos.sdk.skill import Skill


class SyntheticSkill(Skill):
    name: ClassVar[str] = "synthetic_multi_tool"
    declared_tools: ClassVar[tuple[str, ...]] = ("alpha", "beta")

    async def execute(self, **kwargs: Any) -> dict[str, Any]:
        for declared in self.declared_tools:
            tool = self._tools.get(declared)
            if tool.name != declared:
                raise AssertionError(
                    f"registry returned tool with name={tool.name!r} for key "
                    f"{declared!r}; expected name to match the requested key. "
                    f"Future skill code that asserts identity via .name would "
                    f"see wrong tool under the harness."
                )
        return {"per_name_identity_verified": True}
"""

    pack_dir = tmp_path / "synthetic_skill_pack"
    _write_synthetic_skill_pack(pack_dir, skill_module_body=skill_body)
    report = run_harness(pack_dir)

    assert report.overall_status == "pass", (
        f"skill dispatch failed; per-name identity likely drifted. report={report!r}"
    )
    assert len(report.dispatch_results) == 1
    assert report.dispatch_results[0].status == "pass"
