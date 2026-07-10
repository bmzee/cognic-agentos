# Proof M8.5 SLICE — Conversational Substrate (3-bar kind proof, BARs 1–3)

> **STATUS: PASSED LIVE — 2026-07-10, run 6, exit 0.**
> `PROOF M8.5 SLICE (BARS 1-3) PASS` on `kind`; log 533 lines, SHA-256
> `9c6f17b35efce426ec5194920da327a2257b82116807037cad656717d9f533f9`
> (operator-held), recorded with the run ledger + honesty boundary in
> `docs/VALIDATION-RESULTS.md` §"M8.5-A". The **kernel anchor**
> `main @ 235daede` (the deployed kernel, the proof image label) is
> DISTINCT from the **proof revision** `caab00bd` (the runner +
> structural-suite tree that executed — four C2 commits after the anchor:
> `7981da7c` authored the proof, three review-fix commits followed; zero
> kernel changes).

When run, this proof stands up a `kind` cluster and proves the **ADR-028
conversation substrate** live against a deployed AgentOS kernel: a
kernel-owned conversation record (`/api/v1/conversations`) wraps the
**proven M8 governed agent loop** — every turn re-enters the M8 dispatch
chokepoint (assignment → entitlement → policy per dispatch), prior turns come
exclusively from the kernel store, and the chain carries digest-only evidence
(`conversation.created` / `conversation.turn_completed`) joining each turn to
its `agent.run.%` rows.

Kernel anchor: computed at BUILD time — the runner resolves `git rev-parse
HEAD` from a CLEAN kernel-source tree, passes it as the `KERNEL_GIT_SHA`
build arg (the ARG carries NO default), and verifies the built image's
`io.cognic.proof.kernel-anchor` label equals the computed revision before any
deploy (review finding 2, 2026-07-10 — the earlier hardcoded anchor claimed
`main @ 235daede` while the runner overlaid newer branch source). Run 6 was
anchored at `main @ 235daede6d1b7a99846c6339f2e234c85e6bd0cc` (M8.5 A/B/C1,
PR #126).

**This is the VERTICAL-SLICE GATE, not the M8.5 production proof.** ADR-028
BARs 4–7 (bounds/terminal refusal, erasure, safety hooks, SSE reconnect) are
NOT run here; the harness/SSE surfaces are later M8.5 slices. Do not read a
pass as "conversational agent production-proven."

## What carries forward from proof-m8 (byte-for-byte, m85 names)

The deployment is the proven proof-m8 bring-up VERBATIM: the same **SEVEN
released, signed packs** (oracle tool `v0.3.0` operator-installed via the full
M4 lifecycle; the four instruction skills; the bank-analyst agent pack with
its dual trust root; the M5 hook pack the oracle manifest requires), the same
seven-signer trust-root staging, the same in-cluster Oracle XE + RS256/JWKS AS
+ Redis + litellm + local TLS registry + canonical-image re-home flow, the
same migration-0014 seed matrix (`kernel-seed.sql`, readback `4|4|4|0`), and
the same Step-0 hosted/registered surface asserts. See
`infra/proof-m8/README.md` for the full custody + staging documentation — key
custody, trust-root layout, the sandbox-machinery-kept rationale, and the
model-alias swap all carry unchanged (m85-renamed env/paths).

The conversation substrate adds **no pack, no seed rows, and no new trust
material**: migrations `0015` + `0016` (applied by the same non-hook migrate
Job via `alembic upgrade head`) add the `conversations` +
`conversation_turns` tables and the read-model correlation column + query
indexes, all of which start empty — conversations are runtime records created
through the governed API.

## The M8.5 deltas

1. **Analyst scopes (ruling 2026-07-10).** `analyst.amir` / `analyst.sara`
   carry ONLY the four `conversation.*` scopes — **no `agent.ask`**. The slice
   exercises the conversation surface exclusively; a stray single-shot `/ask`
   from an analyst 403s. (`proof_m85/proof_app.py`.)
2. **`COGNIC_CONVERSATION_CLAIM_TTL_S=600`** (recon finding R1). The
   `ConversationTurnExecutor` construction guard requires
   `claim_ttl_s > agent_run_wall_clock_s`; the proof inherits
   `COGNIC_AGENT_RUN_WALL_CLOCK_S=300` from m8 and the kernel default TTL is
   300.0 — without this env line the lifespan fail-softs the whole
   conversation block and every conversation route 503s.
3. **OTEL is inherited diagnostics only (ruling R6).** The proof-m8 OTLP
   collector + exporter wiring carries forward drift-free, but **no M8.5 bar
   depends on spans** — the collector log is captured only as failure
   diagnostics.
4. **Plan deviation, ruled 2026-07-10 (R4):** the implementation plan's
   `tests/integration/conversation/test_conversation_e2e.py` is deliberately
   NOT authored. One live authority exists — `run-proof-m85.sh` — backed by
   the structural suite `tests/unit/infra/test_proof_m85_structure.py`
   (the proof-m4/m5/m6/m8 convention; a pytest twin of the bash bars would
   be a second source of truth to drift).

## The three bars (ALL MANDATORY; never redefined downward)

* **BAR 1 (governed multi-turn e2e).** As `analyst.amir`: create a
  conversation with `bank-analyst`; turn 1 asks the deterministic
  top-3-depositors question (seeded fixture: Ayesha Khan → Bilal Sheikh →
  Chandni Malik); turn 2 asks *"Of those, what is the second-largest
  customer's total balance?"* — **containing no entity name**, so a correct
  answer requires the replayed turn-1 context. Invariant MECHANICAL pins:
  * the turn-2 `agent.run.started` row carries `prior_context_turns=2` AND a
    `prior_context_sha256` the runner **recomputes independently** from the
    `conversation_turns` plaintext with the loop's exact framing
    `user:<question>\nassistant:<answer>` (`core/agent/loop.py`);
  * **two chain lineages**, all queries tenant-scoped
    (`tenant_id='proof-m85'`) — run-5 ruling, 2026-07-10: the **context
    lineage** `conversation.turn_completed(seq=2)` → `agent_run_id` →
    `agent.run.started`/`agent.run.completed`, with the turn-2 run's
    dispatch count **deliberately unconstrained** (0 = context reuse; ≥1 =
    legitimate re-verification; neither fails); and the **dispatch
    lineage** `conversation.turn_completed(seq=1)` → `agent_run_id` →
    `agent.run.started`/`agent.run.completed` → ≥1 ok retail-scoped
    `run_readonly_query` dispatch row (the three-hop conversation → run →
    dispatch join rides the turn that DID dispatch);
  * digest↔plaintext coupling: `question_sha256`/`answer_sha256` on BOTH
    `turn_completed` rows equal sha256 of the stored plaintext;
  * dual identity: zero `agent.run.%` or `conversation.%` rows for the runs /
    conversation not carrying `actor_id=analyst.amir` (+
    `agent_id=bank-analyst` on run rows).
  The answer-content checks — the turn-1 top-3 names AND the rank-2 name
  (Bilal Sheikh) in the turn-2 answer — are **model-driven functional
  acceptance criteria**: MANDATORY (a miss fails the bar), but distinct from
  the mechanical pins above, which are the invariant evidence.
  `PROOF M8.5 SLICE (BAR 1) PASS`.
* **BAR 2 (record integrity — fully deterministic, no model call).** FIVE
  forged history fields — `messages`, `history`, `prior_context`, `context`,
  `transcript` — each POSTed on a real active conversation must return
  **422**, and each 422 body must carry a Pydantic `extra_forbidden` error
  whose `loc` names the submitted field (status alone is insufficient —
  ruling 2026-07-10). ZERO-LOOP pin: the `agent.run.%` count, the
  conversation's `turn_completed` count, and the wire `turn_count` are
  byte-identical before/after the probe block. The positive half of I-1 is
  BAR 1's `prior_context_sha256` recompute. `PROOF M8.5 SLICE (BAR 2) PASS`.
* **BAR 3 (mid-conversation revocation — the I-2 pin).** Its own conversation
  on the **financials** scope: turn 1 (a GL question) completes with an ok
  `financials` dispatch row; the runner proves **exactly one** amir
  financials entitlement row exists, DELETEs it (readback 0), and turn 2 asks
  a **fresh** financials question (branch P&L — deliberately NOT answerable
  from the replayed turn-1 context, ruling R3: re-asking the same question
  could be answered from the transcript without ever dispatching). Load-
  bearing pins: **≥1** dispatch row `refused` /
  `agent_scope_not_entitled` / `scope_id=financials` for run 2 AND **exactly
  0** ok financials dispatches for run 2. HTTP stays **200** — a dispatch
  refusal is a governed answer; the bar asserts chain rows, never the status
  code. The entitlement is then restored (readback 1) so the seed matrix is
  left exactly as found. `PROOF M8.5 SLICE (BAR 3) PASS`.

Any bar failure → capture to `docs/VALIDATION-RESULTS.md` + exit non-zero;
all pass → `PROOF M8.5 SLICE (BARS 1-3) PASS`.

## M8.5-B (READ APIS) section — NOT YET RUN LIVE

The runner now carries an M8.5-B section AFTER the bars (the BARS 1-3 PASS
marker prints first; the run's last line becomes
`PROOF M8.5-B (READ APIS) PASS`). It is deterministic and READ-ONLY — zero
new model calls, zero record mutation, zero SQL: it drives the governed read
surface (`GET /api/v1/conversations` list + cursor walk + three invalid-cursor
probes, transcript plaintext/watermark pagination, the four-block turn-chain
join with the turn-2 dispatch count deliberately unconstrained per the run-5
ruling) over the SAME record BARs 1 and 3 produced, and proves isolation with
a 7th proof role (`foreign` — `analyst.zara`, tenant `proof-foreign`, the
same four `conversation.*` scopes): six-way byte-identical 404 across
unknown-id / cross-actor / cross-tenant on transcript + chain, empty lists for
sara and zara, and access-log trails carrying identifiers + outcome but never
transcript plaintext. **The 2026-07-10 run-6 PASS above predates this section
— the M8.5-B section has NOT yet executed on a cluster**; its verification so
far is the structural test suite only (`tests/unit/infra/
test_proof_m85_structure.py`). The remediation of review findings 1/2/7
(2026-07-10) also changed the SETUP path since run 6 — the build-time kernel
provenance guard + label readback and the post-migrate 0016 schema readback
have likewise not yet executed live.

## Honesty boundary (read before citing this proof)

* **Model-driven vs deterministic.** BAR 2 is fully deterministic. BARs 1 and
  3 drive a REAL cloud model (`openai/gpt-4o` via litellm) and carry TWO
  kinds of assertion: the mechanical chain pins listed above (the INVARIANT
  evidence — governance held) and the **model-driven functional acceptance
  criteria** (the turn-1 top-3 names, the turn-2 rank-2 name, BAR 3's
  "not available" phrasing). The acceptance criteria are MANDATORY — a miss
  fails the bar — but they are the flake-prone half, and a miss reads as a
  model-behaviour failure, not a governance-integrity failure. The M8 proof
  learned this the hard way (its BAR 4 moved to deterministic drivers).
* **Turn-2 dispatch count is unconstrained (run-5 ruling).** A live run
  proved turn 2 can answer entirely from the replayed context with ZERO
  dispatches (`steps_used=1`) — correct, desirable behaviour. Zero means
  context reuse; one or more means legitimate re-verification; neither is a
  failure. Requiring a turn-2 dispatch was a model-behaviour assumption
  baked into a mechanical pin — the same trap class ruling R3 removed from
  BAR 3. The dispatch join therefore rides turn 1, which must dispatch to
  produce the seeded figures at all.
* **PT-3 posture on BAR 3.** Revoking a scope mid-conversation does NOT
  un-disclose content already in the transcript — turn 1's answer remains in
  the replayed context by design (the transcript is already-disclosed data;
  erasure is the separate M8.5-F pathway). The bar proves no FRESH data
  crosses the revoked scope.
* **BARs 4–7 are not run here.** Bounds + terminal-state refusal, erasure,
  safety hooks, and SSE reconnect are later M8.5 slices per the milestone
  checklist. The unit/CI layer covers the bounds + terminal-refusal contracts
  (including the live-Postgres fencing canary in the CI postgres lane); they
  are simply not part of this deployed gate.
* **Proof-only wiring.** The proof-m8 caveats carry forward unchanged
  (header-driven multi-actor binder; proof-staged trust roots; per-run
  query-context keypair; demo-grain scope→proxy-identity seeding; cloud
  toggles + provider key as operator env).

## Runner environment (operator-supplied at run time; never committed)

| env | required | meaning |
|---|---|---|
| `COGNIC_RUN_PROOF_M85=1` | yes | the proof gate (unset → the runner exits 0 with a skip message; NO default-on CI behavior). |
| `COGNIC_PROOF_M85_TIER1_API_KEY` | yes | the operator's CLOUD provider API key. Fail-loud at the gate; after the zero-spend preflight the runner persists it to a `0600` file under the private per-run dir, **unsets the environment variable**, and creates the `proof-m85-provider-key` k8s Secret `--from-file` — the key never rides a process argument vector (review finding 1, 2026-07-10). **ROTATION REQUIRED for keys used by pre-fix runners** (runs up to and including run 6): those created the Secret via `--from-literal`, exposing the key to local `ps` for the kubectl lifetime — treat them as locally exposed. |
| `COGNIC_PROOF_M85_ALLOWED_PROVIDERS` | no (default `openai`) | the ADR-007 provider allow-list the runner sets on the kernel (`COGNIC_ALLOWED_PROVIDERS`). Lockstep with the values model line for the provider swap. |
| `COGNIC_PROOF_M85_POLICY_MODE` | no (default `cloud_openai`) | the kernel `COGNIC_POLICY_MODE`; lockstep with the values model line for the swap. |
| `COGNIC_PROOF_M85_REGISTRY_PORT` / `COGNIC_PROOF_M85_REGISTRY_TLS_DIR` / `COGNIC_PROOF_M85_REUSE_IMAGES` | no | local TLS-registry knobs (the proof-m6/m8 conventions, m85-named). |

Deploy-time env the runner sets on the kernel Deployment (operator env, never
image-baked): the three cloud-policy toggles, the vault-referenced litellm
master key, `COGNIC_AGENT_RUN_TOKEN_BUDGET=60000` +
`COGNIC_AGENT_RUN_WALL_CLOCK_S=300` (the m8 operational bounds), and the M8.5
delta `COGNIC_CONVERSATION_CLAIM_TTL_S=600` (see "The M8.5 deltas").

## Stage → seed → run

1. **Stage** — `bash infra/proof-m85/stage-packs.sh` (same seven releases,
   same maintainer-locked sha256 pins as proof-m8; fail-closed on mismatch).
2. **Keys** — the runner mints the per-run query-context keypair + the proof
   canonical-image trust material (the m6/m8 re-home flow; no fixture flags).
3. **Seed** — Oracle XE first-boot runs `oracle-seed/seed_schema.sql`;
   `kernel-seed.sql` applies the 0014 rows after the migrate Job (which
   brings the schema to rev 0016; the runner reads back `alembic_version`
   plus the 0016 correlation-column/index shape — the conversation tables
   start empty).
4. **Run** — `COGNIC_RUN_PROOF_M85=1` + the provider key env →
   `./infra/proof-m85/run-proof-m85.sh`: kind + backends + M4 operator
   lifecycle for the tool + Step-0 surface asserts, then BARs 1–3.

## Files

Same layout as `infra/proof-m8/` (see its README's file table) with:
`run-proof-m85.sh` (the three conversation bars + the tenant-scoped evidence
helpers), `proof_m85/` (the conversation-scoped analyst actors),
`proof-m85-values.yaml` / `Dockerfile.agentos-proof` (m85 names + the
build-time `KERNEL_GIT_SHA` anchor label), `migrate-job.yaml` (head =
rev 0016 with a live post-migrate readback), and the structural suite at
`tests/unit/infra/test_proof_m85_structure.py`.
