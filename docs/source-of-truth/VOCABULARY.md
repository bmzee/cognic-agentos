# Cognic AgentOS — Canonical Vocabulary

**Status:** Normative annex to `ARCHITECTURE.md` (revision 1, 2026-07-09)
**Scope:** the nouns AgentOS uses for the artefacts that install on top of it, and the rules for using them in prose, in operator surfaces, and in code.

## 0. Precedence

This document **reflects** decisions made in ADRs; it does not make them. Where this document and an ADR disagree, **the ADR wins** and the drift is a bug in this file — fix it in the same commit that finds it.

The controlling sources are:

| Term | Controlling source |
|---|---|
| Skill, governed action | ADR-025 §"Vocabulary" + §"One `skill` pack kind" |
| Tool, pack discovery + trust | ADR-002 |
| Agent | ADR-027 |
| Hook | ADR-008 + ADR-017 |
| Pack lifecycle | ADR-012 |
| Workflow | **reserved** — ADR-029 / Sprint 15A (not yet written) |

## 1. The nouns

| Noun | Definition | Signed pack? |
|---|---|---|
| **Pack** | The signed, installable, governed artefact: a wheel carrying `cognic-pack-manifest.toml`, cosign signature, SLSA provenance, SBOM, and attestations, admitted through the trust gate and moved through the ADR-012 lifecycle. **This is our word.** | — |
| **Tool** | A governed connector or action surface, normally an MCP server (`cognic-tool-*`): search, database read, case lookup, payment action. | yes |
| **Skill** | A `SKILL.md` package (`cognic-skill-*`) — the full agentskills.io-standard folder: a required `SKILL.md` (YAML frontmatter `name` + `description`, Markdown instructions body — the **entrypoint, not the whole artifact**) plus optional `references/`, `assets/`, `scripts/`, and supporting files, all riding the signed wheel as package data. **A skill may optionally carry one governed action.** Instruction material is hosted and served to the model, **never executed**; bundled `scripts/` are package data with no execution affordance — script execution is explicitly deferred (ADR-025 §"Security model") and lands, if ever, as a governed, sandboxed, declared boundary, never ambient execution. | yes |
| **Governed action** | The runtime primitive **inside** a skill: the deterministic `sdk/skill.py` composer (`Skill.execute()`), no LLM, constrained by a `declared_tools` contract, executed in an ADR-004 sandbox with no network and no ambient credentials, reaching tools only through the broker. It is *not* "the skill" — it is one governed implementation of a skill's runnable behaviour. | no — a component of a skill pack |
| **Agent** | A declarative LLM worker (`cognic-agent-*`): a persona plus a requested capability set. Carries no reasoning code — the kernel owns the loop. | yes |
| **Hook** | A deterministic governance extension (`cognic-hook-*`): DLP pre/post, content safety, policy. Not a tool, skill, or agent. | yes |
| **Workflow** | **Reserved.** The future durable orchestration primitive (declarative DAG / state machine, branching, durable cross-step state, pause/resume, approval gates, compensation). It does not exist today and is **not** what a governed action is. | reserved |

## 1b. Harness — one word, two referents (ruled 2026-07-11)

| Term | Meaning |
|---|---|
| **Cognic Harness** | The external client product (`cognic-harness` repo, retiring the `cognic-portal-ui` name): v1 = the three-screen runtime client (chat, approvals inbox, evidence viewer — ADR-028 spec §0.3), a **browser + same-origin BFF** (tokens BFF-side only; RFC 9700 baseline, full FAPI 2.0 as the bank-deployment target — spec §0.4 profile ladder); v2 = the ADK authoring workbench (ADR-008 Phase B). Zero authoritative domain/governance state (transient session/token state only); **no independent authorization or governance authority — security-sensitive for the OIDC flow, session/token custody, CSRF protection, and request forwarding, but non-authoritative for identity and authorization**. |
| **Runtime harness (internal)** | `src/cognic_agentos/harness/` — the kernel's composition layer / governed execute loop (`harness/base_agent.py`, `harness/runtime.py`, the builders). Kernel code; unrelated to the product above beyond the shared word. |

## 2. Skill and its governed action

ADR-025 (2026-07-02) resolved a collision between this repo's pre-existing `sdk/skill.py` composer and the industry's single meaning of "skill." The resolution:

> **Skill (public noun) = a `SKILL.md` package.** (ADR-025:32)
>
> **Executable action = the governed runtime primitive inside a skill.** ... It is *not* "the skill"; it is *one governed implementation* of a skill's runnable behavior — a **substrate**, not a competing "skill" noun. Public docs stop calling it "executable skill." (ADR-025:33)
>
> The earlier pack-vocabulary split — "instruction skill" + "executable skill service" — **collapses into a single `skill` kind**: a `SKILL.md` package with an optional governed action. (ADR-025:38)

So there is **one** skill. What varies is whether it carries an action:

| Manifest | Meaning | Registry behaviour |
|---|---|---|
| `[skill].mode = "instruction"` | the skill carries **no** governed action | no entry point; discovered by the manifest-walk arm; `load()` refuses with `ManifestOnlyPackNotLoadable` |
| `[skill].mode = "executable"` | the skill carries **one** governed action | a `cognic.skills` entry point; the action runs sandboxed, broker-mediated |

`mode` is an **implementation descriptor**, not a public taxonomy. It says what a skill *has*, not what species it *is*.

## 3. Words we do not use

Retired by ADR-025. Do not reintroduce them, in prose or in identifiers:

- ~~executable skill~~ — ADR-025:33 retires it by name
- ~~executable skill service~~ — the deprecated half of a collapsed split
- ~~skill service~~, ~~skill action~~ — re-create the competing "skill" noun ADR-025 removed

"Instruction skill" and "instruction-only skill" remain acceptable **internally**, as descriptors of `mode="instruction"`. They are not a pack kind, and they must not appear in operator-facing surfaces as if a user were choosing between two species of thing.

## 4. How to say it

| Register | Say |
|---|---|
| Public / operator | **skill** |
| Public, when the distinction matters | **a skill with a governed action** / **a skill with no governed action** |
| Internal / code / manifest | `mode="instruction"` / `mode="executable"` |
| Control surface | neither — see §6 |

## 5. Pack kinds: live vs reserved

The live kinds are exactly four:

```python
PackKind = Literal["tool", "skill", "agent", "hook"]   # packs/lifecycle.py:111
```

matching the four entry-point groups `cognic.tools` / `cognic.skills` / `cognic.agents` / `cognic.hooks` (`protocol/plugin_registry.py:89-92`).

**`workflow` is reserved, not extant.** ADR-025:38 lists it among the pack kinds in the present tense; that is an accuracy defect corrected by the ADR-025 amendment of 2026-07-09. A workflow pack kind lands, if ever, with the Sprint-15A orchestration engine under ADR-029/M14. Until then, **do not describe a governed action as a workflow** — an action is a fixed deterministic composer; a workflow is a generic DAG/state-machine engine with durable state. Conflating them is the exact error inherited from `Cognic_Master_Strategy_v5.0.md:367` ("Layer B — Skill / Workflow Pool"), reconciled in `ARCHITECTURE.md` §8.4.

## 6. Control-surface rule

An operator granting a skill to an agent — in the portal, in the harness, or in an approval screen — **must be shown**:

1. whether the skill carries a governed action, and
2. if it does, the action's `declared_tools` set.

The operator **must not** be asked to choose between "instruction skill" and "executable skill." Those are internal modes, and a species label communicates none of the privilege actually being granted. The privilege is the tool set: the broker refuses any `tool_ref` outside `declared_tools` on every call (`core/skill/broker.py:308`), so `declared_tools` *is* the grant.

## 7. "Plugin"

`protocol/plugin_registry.py`, "plugin trust gate," and ADR-002's title ("MCP plugin protocol") use **plugin** as a historical synonym for **pack**. The names are load-bearing (module paths, an approved ADR title) and are not being changed. Do not introduce "plugin" into new prose: the artefact is a **pack**.

## 8. ADR-029 decision gate

If, and only if, the harness comes to need a **user-facing capability class** that distinguishes action-carrying skills from instruction-only ones, ADR-029 shall evaluate promoting `mode="executable"` to its own `PackKind` value.

That evaluation is **not precommitted**. It carries a real cost — `PackKind` is a signed-manifest field and a database CHECK constraint, and the change would touch `protocol/plugin_registry.py`, `cli/_wheel_integrity.py`, `cli/verify.py`, the `skill.invoke` RBAC scope, and every already-signed skill pack. Today the `mode` discriminator carries the distinction correctly on the wire, and §6 shows the control surface needs `declared_tools` rather than a kind label. **No migration is planned.**

## 9. Where the vocabulary is enforced

| Claim | Enforced at |
|---|---|
| four live pack kinds | `packs/lifecycle.py:111` |
| four entry-point groups | `protocol/plugin_registry.py:89-92` |
| two skill modes | `cli/validators/skills.py:135` |
| an instruction-mode skill is never loaded as code | `protocol/plugin_registry.py:506` (`ManifestOnlyPackNotLoadable`) |
| a governed action reaches no tool outside its declaration | `core/skill/broker.py:308` (refusal emitted at `:317`) |
| a governed action runs no LLM | `sdk/skill.py:110` (`Skill.execute()` — deterministic composer) |
