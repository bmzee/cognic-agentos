"""M6 Task A4 (ADR-025) — the generic in-sandbox skill-runner.

The harness baked into the immutable, cosign-verified skill runtime
image (ADR-025 §"Security model" — the action NEVER loads into the
kernel process). The Task-A5 executor ``session.exec(...)``'s
``python -m cognic_agentos.sdk.skill_runner`` with the invocation
parameters in env; the runner, INSIDE the sandbox:

1. resolves the target skill action via its ``cognic.skills`` entry
   point (``EntryPoint.load()`` runs sandbox-side only);
2. binds a broker-backed :class:`BrokerToolRegistry` — the existing
   ``Skill.__init__`` ``declared_tools`` cross-check runs unmodified
   against the executor-granted identity list;
3. ``await``s ``Skill.execute(**kwargs)`` — every tool call becomes a
   broker RPC the kernel-side broker governs per call;
4. writes the outcome as ONE final length-framed JSON frame on stdout
   (mirroring the broker wire arms: ``{"ok": true, "result": ...}`` on
   success; ``{"ok": false, "refused": true, "reason": ...}`` when a
   tool call was refused). Any other failure propagates as a loud
   traceback + non-zero exit — the executor maps it to
   ``skill_runtime_error``.

SDK-light: stdlib + ``cognic_agentos.sdk.*`` ONLY (no kernel imports,
no third-party deps) — pinned by the AST fence in
``tests/unit/sdk/test_skill_runner.py``.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Sequence
from importlib.metadata import entry_points
from typing import Any

from cognic_agentos.sdk.skill import Skill
from cognic_agentos.sdk.skill_transport import (
    BrokerToolRegistry,
    SkillToolRefused,
    encode_frame,
)

_ENTRY_POINT_GROUP = "cognic.skills"

#: The five-env-var invocation contract the Task-A5 executor passes.
#: Names are wire-public between the kernel and every deployed skill
#: runtime image — pinned literally in the A4 test suite.
ENV_BROKER_SOCKET = "COGNIC_SKILL_BROKER_SOCKET"
ENV_BROKER_SESSION_TOKEN = "COGNIC_SKILL_BROKER_SESSION_TOKEN"
ENV_ENTRY_POINT = "COGNIC_SKILL_ENTRY_POINT"
ENV_DECLARED_TOOLS_JSON = "COGNIC_SKILL_DECLARED_TOOLS_JSON"
ENV_ARGUMENTS_JSON = "COGNIC_SKILL_ARGUMENTS_JSON"

__all__ = [
    "ENV_ARGUMENTS_JSON",
    "ENV_BROKER_SESSION_TOKEN",
    "ENV_BROKER_SOCKET",
    "ENV_DECLARED_TOOLS_JSON",
    "ENV_ENTRY_POINT",
    "run_skill",
]


async def run_skill(
    *,
    entry_point_name: str,
    sock_path: str,
    session_token: str,
    declared_tools: Sequence[str],
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    """Resolve + construct + execute one skill action, broker-bound.

    Raises ``LookupError`` on an absent or ambiguous entry point,
    ``TypeError`` when the entry point does not resolve to a ``Skill``
    subclass, ``SkillUnregisteredToolError`` when the action's ClassVar
    ``declared_tools`` exceeds the executor's grant, and lets
    :class:`SkillToolRefused` (a broker refusal at call time) propagate
    to the caller.
    """
    matches = [ep for ep in entry_points(group=_ENTRY_POINT_GROUP) if ep.name == entry_point_name]
    if not matches:
        raise LookupError(
            f"no {_ENTRY_POINT_GROUP!r} entry point named {entry_point_name!r} is installed"
        )
    if len(matches) > 1:
        raise LookupError(
            f"ambiguous {_ENTRY_POINT_GROUP!r} entry point {entry_point_name!r}: "
            f"{len(matches)} candidates"
        )
    skill_cls = matches[0].load()
    if not (isinstance(skill_cls, type) and issubclass(skill_cls, Skill)):
        raise TypeError(
            f"entry point {entry_point_name!r} does not resolve to a Skill subclass "
            f"(got {skill_cls!r})"
        )
    registry = BrokerToolRegistry(
        sock_path=sock_path, session_token=session_token, declared_tools=declared_tools
    )
    # Skill.__init__ cross-checks the ClassVar declared_tools against
    # registry.list_tools() BEFORE any execute() — unmodified SDK seam.
    skill = skill_cls(tools=registry)
    return await skill.execute(**kwargs)


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required environment variable {name} is missing or empty")
    return value


def _write_result_frame(obj: dict[str, Any]) -> None:
    sys.stdout.buffer.write(encode_frame(obj))
    sys.stdout.buffer.flush()


def _main() -> int:
    """``python -m cognic_agentos.sdk.skill_runner`` — the exec entrypoint.

    Reads the five-env-var contract, runs the skill, and writes the
    outcome as the FINAL length-framed JSON frame on stdout (the
    executor parses it from the session's captured stdout). Unexpected
    exceptions propagate loudly — no silent fallback.
    """
    entry_point_name = _require_env(ENV_ENTRY_POINT)
    sock_path = _require_env(ENV_BROKER_SOCKET)
    session_token = _require_env(ENV_BROKER_SESSION_TOKEN)
    declared_raw = json.loads(_require_env(ENV_DECLARED_TOOLS_JSON))
    if not isinstance(declared_raw, list) or not all(
        isinstance(item, str) for item in declared_raw
    ):
        raise RuntimeError(f"{ENV_DECLARED_TOOLS_JSON} must be a JSON array of strings")
    arguments = json.loads(_require_env(ENV_ARGUMENTS_JSON))
    if not isinstance(arguments, dict):
        raise RuntimeError(f"{ENV_ARGUMENTS_JSON} must be a JSON object")
    try:
        result = asyncio.run(
            run_skill(
                entry_point_name=entry_point_name,
                sock_path=sock_path,
                session_token=session_token,
                declared_tools=declared_raw,
                kwargs=arguments,
            )
        )
    except SkillToolRefused as exc:
        # A governed refusal (e.g. skill_tool_not_declared) is a
        # first-class outcome, not a crash: surface it on the result
        # channel with a non-zero exit so the executor sees both.
        _write_result_frame({"ok": False, "refused": True, "reason": exc.reason})
        return 1
    _write_result_frame({"ok": True, "result": result})
    return 0


if __name__ == "__main__":  # pragma: no cover — exercised via session.exec in Part C
    raise SystemExit(_main())
