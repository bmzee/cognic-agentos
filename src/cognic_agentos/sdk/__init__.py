"""Sprint-7A `agentos_sdk` — public Python API for plugin-pack authors.

Per ADR-008 Phase A: this package is the contract banks build packs
against. Every name re-exported here is part of the **semver-stable
public API surface** — every commit that adds, removes, or changes the
shape of a name in this surface halts before commit per Doctrine
Decision E (broader than the critical-controls gate; SDK shape is a
public contract, not just a security gate).

Wave-1 surface (Sprint-7A T2):

  - ``Tool`` / ``ToolError`` / ``ToolInputSchemaError`` /
    ``ToolOutputSchemaError`` / ``ToolSchemaDeclarationError`` —
    base class + closed-enum exception hierarchy for MCP tool
    implementations.
  - ``Skill`` / ``SkillError`` / ``SkillUnregisteredToolError`` —
    base class + closed-enum exception hierarchy for tool-composition
    implementations (no LLM in skill code per ADR-001 three-pool rule).
  - ``Agent`` — base class for A2A-speaking agents whose ``handle``
    signature matches the shipped Sprint-6 ``A2AEndpoint`` dispatch
    contract.
  - ``ToolRegistry`` — PEP 544 Protocol both runtime + fixture
    registries conform to structurally.

Wave-1 surface (Sprint-7A2 T2):

  - ``Hook`` / ``HookContext`` / ``HookResult`` / ``HookDecision`` —
    base class + value types for governance hook implementations
    registered under the ``cognic.hooks`` entry-point group.
  - ``HookError`` / ``HookContractError`` / ``HookContextError`` /
    ``HookPayloadError`` / ``HookResultShapeError`` — closed-enum
    exception hierarchy for hook contract violations; the runtime
    hook dispatcher catches the top-level ``HookError`` as a single
    refusal-surface catch.

Testing helpers (``agentos_sdk.testing``) and ISO-42001 compliance
helpers (``agentos_sdk.compliance``) ship in T3 of the Sprint-7A
arc.
"""

from __future__ import annotations

from cognic_agentos.sdk.agent import Agent
from cognic_agentos.sdk.hook import (
    Hook,
    HookContext,
    HookContextError,
    HookContractError,
    HookDecision,
    HookError,
    HookPayloadError,
    HookResult,
    HookResultShapeError,
)
from cognic_agentos.sdk.registry import ToolRegistry
from cognic_agentos.sdk.skill import Skill, SkillError, SkillUnregisteredToolError
from cognic_agentos.sdk.tool import (
    Tool,
    ToolError,
    ToolInputSchemaError,
    ToolOutputSchemaError,
    ToolSchemaDeclarationError,
)

__all__ = [
    "Agent",
    "Hook",
    "HookContext",
    "HookContextError",
    "HookContractError",
    "HookDecision",
    "HookError",
    "HookPayloadError",
    "HookResult",
    "HookResultShapeError",
    "Skill",
    "SkillError",
    "SkillUnregisteredToolError",
    "Tool",
    "ToolError",
    "ToolInputSchemaError",
    "ToolOutputSchemaError",
    "ToolRegistry",
    "ToolSchemaDeclarationError",
]
