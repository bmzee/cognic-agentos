"""Synthetic agent-pack fixtures for the kernel conformance suite.

The pack is deliberately BORING: one requested skill, one requested tool (a real
``<server_id>/<tool_name>`` identity), a
two-line persona. Its only job is to be trivially correct so that any failure
in a conformance run is attributable to the KERNEL and never to pack quality.

REAL here (versus the unit suite's stubs):

* the manifest and ``AGENT.md`` are real bytes on disk, parsed by the real
  ``extract_pack_manifest`` / ``extract_agent_md`` — their ``package_name``
  identifier guard, path resolution, filesystem existence check and read, TOML
  parse and frontmatter validation all run for real, and no pack code is
  imported. (They do NOT walk ``dist.files``: neither extractor consults RECORD
  despite documenting that it does — see the separately-recorded forward item;
  do not restate the RECORD claim here.);
* the record loader is the real :func:`_build_agent_records` walk;
* :func:`candidate` constructs the REAL ``RegisteredPackCandidate`` type.

SUBSTITUTED — every seam, named:

* **distribution lookup** — ``importlib.metadata.distribution`` is redirected;
* **``locate_file``** — :meth:`FakeDist.locate_file` is a two-line
  ``root / relative`` join. The stdlib implementation is NOT exercised;
* **the registry** — :class:`Registry` yields hand-built candidates, proving the
  candidate SHAPE and not ``PluginRegistry``'s projection SEMANTICS. The real
  registry and ``registry_boot`` trust registration are NOT exercised here;
* **the model and the MCP tool proxy** — absent, and NOT YET REACHED: no
  dispatch occurs in this package today. They become inputs to the governed
  decisions when the dispatch-conformance packet lands.

Do not narrow this list when describing the module. Understating a seam is how
a suite gets cited for more than it proves.
"""

from __future__ import annotations

import importlib.metadata as _im
import shutil
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cognic_agentos.protocol.plugin_registry import RegisteredPackCandidate

MANIFEST_BASENAME = "cognic-pack-manifest.toml"
AGENT_MD_BASENAME = "AGENT.md"

DEFAULT_DIST = "cognic-agent-conformance"
DEFAULT_PACKAGE = "cognic_agent_conformance"
DEFAULT_AGENT_ID = "conformance-agent"
DEFAULT_VERSION = "0.1.0"
DEFAULT_SIGNATURE_DIGEST = "0" * 64

#: The persona body EXACTLY as ``parse_skill_md`` returns it — the leading
#: newline after the closing frontmatter delimiter is retained, and the digest
#: below is taken over these exact bytes.
DEFAULT_PERSONA_BODY = "\nAnswer using only assigned capabilities.\n"
DEFAULT_PERSONA_SHA256 = "731a35b77710017ef42d6826a6449017158f11c741c9be4d66387ef38443f623"


class FakeDist:
    """An ``importlib.metadata.Distribution``-shaped stand-in whose
    ``locate_file`` resolves against a real tmp-path root.

    Mirrors the shape used by
    ``tests/unit/protocol/test_plugin_registry_manifest_discovery.py`` so both
    suites exercise the same resolution contract.
    """

    def __init__(
        self,
        *,
        name: str,
        version: str,
        root: Path,
        files: list[str] | None,
    ) -> None:
        self._name = name
        self.version = version
        self._root = root
        self._files = files

    @property
    def metadata(self) -> dict[str, Any]:
        return {"Name": self._name}

    @property
    def entry_points(self) -> tuple[Any, ...]:
        return ()

    @property
    def files(self) -> list[_im.PackagePath] | None:
        if self._files is None:
            return None
        return [_im.PackagePath(f) for f in self._files]

    def locate_file(self, relative: Any) -> Path:
        return self._root / str(relative)


def agent_manifest_toml(
    *,
    agent_id: str = DEFAULT_AGENT_ID,
    requested_skills: tuple[str, ...] = ("conformance-skill",),
    requested_tools: tuple[str, ...] = ("conformance-server/conformance_query",),
    max_steps: int | None = 4,
    risk_tier: str = "read_only",
) -> str:
    """Canonical-path ``[agent]`` manifest for a synthetic agent pack.

    ``agent_id`` is accepted for symmetry with the AGENT.md builder but is NOT
    written here: the kernel derives the agent id from the AGENT.md frontmatter
    ``name``, and duplicating it in the manifest would let a fixture drift from
    the contract it is meant to pin.
    """
    del agent_id
    lines = [
        "[pack]",
        f'pack_id = "{DEFAULT_DIST}"',
        'kind = "agent"',
        "",
        "[risk_tier]",
        f'tier = "{risk_tier}"',
        "",
        "[agent]",
        f"requested_skills = {list(requested_skills)!r}".replace("'", '"'),
        f"requested_tools = {list(requested_tools)!r}".replace("'", '"'),
    ]
    if max_steps is not None:
        lines.append(f"max_steps = {max_steps}")
    return "\n".join(lines) + "\n"


def agent_md(
    *,
    agent_id: str = DEFAULT_AGENT_ID,
    description: str = "Synthetic conformance agent. Not a product pack.",
    body: str = "Answer using only assigned capabilities.",
) -> str:
    """Minimal valid agentskills.io frontmatter + non-blank body.

    ``name`` becomes the kernel-side agent id (``_build_agent_records``).
    """
    return f"---\nname: {agent_id}\ndescription: {description}\n---\n\n{body}\n"


def write_agent_pack(
    root: Path,
    *,
    package: str = DEFAULT_PACKAGE,
    agent_id: str = DEFAULT_AGENT_ID,
    requested_skills: tuple[str, ...] = ("conformance-skill",),
    requested_tools: tuple[str, ...] = ("conformance-server/conformance_query",),
    max_steps: int | None = 4,
    risk_tier: str = "read_only",
    write_agent_md: bool = True,
) -> Path:
    """Write a real synthetic agent pack under ``root`` and return its package dir.

    ``write_agent_md=False`` produces the negative fixture for the
    ``agent.agent_md_not_found`` warn-skip arm.
    """
    pkg_dir = root / package
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / MANIFEST_BASENAME).write_text(
        agent_manifest_toml(
            agent_id=agent_id,
            requested_skills=requested_skills,
            requested_tools=requested_tools,
            max_steps=max_steps,
            risk_tier=risk_tier,
        ),
        encoding="utf-8",
    )
    if write_agent_md:
        (pkg_dir / AGENT_MD_BASENAME).write_text(agent_md(agent_id=agent_id), encoding="utf-8")
    return pkg_dir


def pack_record_files(package: str = DEFAULT_PACKAGE) -> list[str]:
    """RECORD-style file list for a synthetic agent pack."""
    return [
        f"{package}/{MANIFEST_BASENAME}",
        f"{package}/{AGENT_MD_BASENAME}",
        f"{package}/__init__.py",
    ]


def candidate(
    *,
    distribution_name: str = DEFAULT_DIST,
    package_name: str = DEFAULT_PACKAGE,
    signature_digest: str | None = DEFAULT_SIGNATURE_DIGEST,
) -> RegisteredPackCandidate:
    """A registered-pack row for the loader walk.

    Deliberately builds the REAL :class:`RegisteredPackCandidate` rather than a
    look-alike: if the projection gains or renames a field, this suite fails
    loudly instead of passing against a stale shape.
    """
    return RegisteredPackCandidate(
        distribution_name=distribution_name,
        package_name=package_name,
        signature_digest=signature_digest,
    )


class Registry:
    """``_RegistryCandidates`` conformer over a fixed candidate list."""

    def __init__(self, candidates: list[RegisteredPackCandidate]) -> None:
        self._candidates = list(candidates)

    def iter_registered_pack_candidates(self) -> Iterator[RegisteredPackCandidate]:
        return iter(list(self._candidates))


# --- build_agent_loop composition seams ------------------------------------ #


@dataclass
class LoopSettings:
    """``_AgentLoopSettings`` conformer with production-shaped defaults.

    Field names and types mirror the Protocol exactly; the real ``Settings``
    conforms structurally, so a Protocol change breaks this at type-check time.
    """

    # Mirrors the real Settings default (core/config.py:2099) — the FILE, not
    # the directory: OPAEngine requires ``bundle_path.is_file()``.
    agents_policy_bundle: Path = Path("policies/_default/agents.rego")
    agent_query_context_signing_key_path: str | None = None
    agent_query_context_ttl_s: float = 30.0
    agent_max_steps: int = 4
    agent_run_token_budget: int = 100_000
    agent_run_wall_clock_s: float = 60.0
    # Resolved from PATH so the composition uses the REAL binary. ``None`` when
    # opa is absent, which is what ``@opa_required`` skips on.
    opa_path: str | None = field(default_factory=lambda: shutil.which("opa"))
    opa_eval_timeout_s: float = 5.0
    sandbox_canonical_runtime_python_image: str = "cognic/sandbox-runtime-python:test"


@dataclass
class LoopRuntime:
    """``_AgentLoopRuntime`` conformer.

    The four members are read as plain attributes by ``build_agent_loop``'s
    dependency gate, so ``None`` on any of them exercises a real
    partial-configuration arm rather than a synthetic one.
    """

    llm_gateway: Any = None
    memory_api_factory: Any = None
    audit_store: Any = None
    decision_history_store: Any = None


class ScriptedGateway:
    """Deterministic stand-in for ``LLMGateway``.

    Determinism is the POINT: a scripted model removes the non-determinism that
    makes model-driven bars unusable as gates. It records every call so the
    prompt-assembly side of the loop stays observable.
    """

    def __init__(self, responses: list[Any] | None = None) -> None:
        self._responses = list(responses or [])
        self.calls: list[dict[str, Any]] = []

    async def completion(self, **kwargs: Any) -> Any:
        recorded = dict(kwargs)
        # The loop appends to a LIVE message list; snapshot or later rounds
        # mutate what was already recorded.
        recorded["messages"] = [dict(m) for m in kwargs.get("messages", [])]
        self.calls.append(recorded)
        assert self._responses, "ScriptedGateway script exhausted"
        return self._responses.pop(0)


# --- synthetic TOOL pack (for the capability-class map) --------------------- #

TOOL_DIST = "conformance-server"
TOOL_PACKAGE = "conformance_server"
TOOL_NAME = "conformance_query"
TOOL_REF = f"{TOOL_DIST}/{TOOL_NAME}"


def write_tool_pack(
    root: Path,
    *,
    package: str = TOOL_PACKAGE,
    tool_name: str = TOOL_NAME,
    capability_class: str = "data_query",
) -> Path:
    """A signed-manifest tool pack contributing ONE capability-class entry.

    ``build_tool_capability_classes`` keys the map ``<distribution>/<name>``, so
    the distribution name is what makes the agent pack's requested
    ``conformance-server/conformance_query`` resolvable.
    """
    pkg_dir = root / package
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / MANIFEST_BASENAME).write_text(
        "\n".join(
            [
                "[pack]",
                f'pack_id = "{TOOL_DIST}"',
                'kind = "tool"',
                "",
                "[[tool.cognic.tools]]",
                f'name = "{tool_name}"',
                f'capability_class = "{capability_class}"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return pkg_dir


def tool_pack_record_files(package: str = TOOL_PACKAGE) -> list[str]:
    return [f"{package}/{MANIFEST_BASENAME}", f"{package}/__init__.py"]


def tool_candidate(
    *,
    distribution_name: str = TOOL_DIST,
    package_name: str = TOOL_PACKAGE,
    signature_digest: str | None = DEFAULT_SIGNATURE_DIGEST,
) -> RegisteredPackCandidate:
    return RegisteredPackCandidate(
        distribution_name=distribution_name,
        package_name=package_name,
        signature_digest=signature_digest,
    )
