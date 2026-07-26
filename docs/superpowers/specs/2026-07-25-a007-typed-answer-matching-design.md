# A-007 BAR-I Fixture Remediation Brief
<!-- STATUS: CURRENT -->
<!-- OWNER: cognic-agentos maintainers -->
<!-- LAST-VERIFIED: 2026-07-25 -->

**Decision status:** PROPOSED for maintainer acceptance

**Scope:** proof-fixture corpus clarity and lossless reference-result
construction; the shipped A-007 evaluator remains unchanged

**Evidence anchor:** `feat/m85e-s4-bar-i@468d02381c4dc63c5784684cc8491c1ebc79a988`

## 1. Decisions

HR, SH, and CO in BAR I are proof fixtures over stock Oracle sample schemas.
They are signed and versioned for proof custody, but they are not production
bank packs and do not establish production-schema doctrine.

This brief proposes exactly two remediation tracks:

1. Re-author the affected HR fixture questions and goldens so the requested
   projection, ordering, and cutoff-tie behavior are explicit. Demote the
   observed `hr-006` holdout and add a genuinely unseen same-family holdout.
2. Refuse duplicate or normalized-empty result columns before any producer or
   loader can collapse them into a mapping. Apply this generic correctness fix
   at the Oracle tool pack, the BAR-I live-reference producer, and the AgentOS
   CLI reference-results loader.

The shipped golden-corpus schema, deterministic scorer, judge routing,
calibration, gate math, and audit-C9 authority stay unchanged. In particular:

- no new scoring value or corpus schema is introduced;
- `_routes_to_judge()` remains the one Boolean authority used by runtime
  scoring, run preflight, and calibration selection;
- no deterministic rows case gains a judge fallback;
- no AgentOS matcher learns HR aliases, columns, cases, SQL, ranks, or ties;
  and
- no new evidence field, protocol, service, migration, pack kind, runtime
  loader, or custody mechanism is proposed.

Audit C9 remains byte-for-byte doctrinally intact: `_routes_to_judge()` at
`skill_eval.py:74-84` is the sole shared authority consumed by runtime scoring
at `:891-893`, run preflight at `:1012-1015`, and calibration selection at
`skill_calibration.py:104-109`.

An exact-first judge fallback may have product merit as a separate future
proposal. It requires independent product justification and is not designed,
authorized, or required for BAR I by this brief.

### 1.1 Coordinated footprint

The later implementation footprint is intentionally small and cross-repo:

| Surface | Required change |
|---|---|
| `cognic-skill-hr-data` | Fixture-only question, reference SQL, expected rows, notes, holdout list, and signed fixture-governance corrections |
| `cognic-tool-oracle-schema/readonly_query.py:459-463` | Refuse normalized-empty or colliding cursor columns before row-dict construction |
| `src/cognic_agentos/cli/skill_eval.py::_load_reference_results` | Pair-preserving duplicate-JSON-property refusal before mappings exist |
| `infra/proof-m85c/run-proof-m85c.sh::build_live_reference_results` | Refuse normalized-empty or colliding cursor columns before row-dict construction |
| Tests and proof pins | Pack tests, kernel CLI tests, BAR-I structural mutation pins, and release-digest updates for changed signed fixture/tool artifacts |

No change is proposed to `evaluation/skill_corpus.py`,
`evaluation/skill_eval.py`, `evaluation/skill_calibration.py`, ADR-010, or the
critical-control file set. C9 and shipped schema-version-1 behavior are
non-regression constraints.

## 2. Ownership

| Authority | Responsibility in this remediation |
|---|---|
| Signed HR fixture pack | Case IDs, questions, Oracle reference SQL, expected fixture values, projection wording, order/tie wording, notes, holdouts, and fixture data-governance declaration |
| Signed Oracle tool pack | Oracle cursor/result mechanics and a lossless-or-refused result envelope |
| AgentOS | Generic JSON loading, shipped scoring/judge behavior, repetitions, ablation, and gate reporting |
| BAR-I runner | Fixture installation, independent live-reference construction, structural pins, and proof assertions |

The kernel stays schema-agnostic. Architecture scans must remain red on any
new AgentOS source literal or conditional for:

- `hr-*` case IDs;
- HR/SH/CO table, view, column, scope, server, or tool names;
- case-specific projection, order, or tie handling; or
- runtime alias inference or automatic schema learning.

The fixture questions below are pack-owned recommendations, not AgentOS
constants.

## 3. Frozen Step A Evidence

### 3.1 Retained hashes and custody

No model or cluster is rerun for this design. The leak-safe retained evidence
is:

| Artifact | SHA-256 |
|---|---|
| run map | `71aaf3beae0a0fc4167b78d68a32d100efc9abaffc35bd6302931df6b36ad56e` |
| actual rows | `fd4aaf565701501dd90746d905d9a9bf9b6ded7a41edf4fde9c9fa640204f6fa` |
| JSON-safe live reference | `5f4c9c92a98dac92630e55b2734eb4496966fe030a21fe8901854feed8ae3de5` |
| worker revalidation | `04d8ad71c63bc3206b5a36ae5c738bc6ba77cf4f1c43a22fce55f4f1d9643852` |
| classification | `e14798a382f1ec9faf98387bbbd4c754529041181509d52333228fb61df5be6e` |
| comparison | `bcb810af7598dcb0a2434d857c29e7a74c46ecf5a47e7015d86cd0596cd28121` |
| diagnostic run log | `b5549d62f05c190b9d23f07e765242310cbe4f0859cbd4420059978218aa5da1` |
| worker revalidation script | `9a854ae5c623d4b91eeb6d9579ff3e0affc7a4960cce14aba851a71ae29d86f0` |
| released queries | `e348d8e6c184dea3846620a998b62294e23eb4e4df38f1f54869a0707be2e051` |
| released manifest | `165291567b88e52ed1c6470e0b57b233f6de77f58620d7a45a258381ba8b70e2` |

Raw fictional rows remain untracked under
`scratchpad/a007-rows-diagnostic/output-step-a-8/`. The leak-safe worker
comparison is
`scratchpad/a007-step-a-worker-revalidation-2026-07-25/comparison.json`.
Neither belongs in a commit or durable validation narrative without a separate
retention ruling.

The checked-out skill source was
`5b17538b91699261198407b9afc489d2db7f0e06`. Step A did not retain a verified
wheel digest or an attestation-to-source join, so these hashes prove the
frozen diagnostic capture and checkout, not an independently proven released
wheel. Later BAR-I evidence must record its own signed artifact identities.

### 3.2 Complete chronological classification

The chronology authority is `run-question-map.jsonl`, whose source query
orders by `created_at, agent_run_id`. Decode `question_b64`, join the question
byte-exactly to the released case, assign R1-R3 within each case in that
order, and hash each run ID with SHA-256 over its UTF-8 bytes.

The canonical lines
`case_id<TAB>R<n><TAB>run_id_sha256<LF>` in the table order below hash to
`03903a580238c31b0220940033a67e79b8fb5b86ea3f676508ee622fcb63b49b`.
The retained recompute script compares rows but its log-order repetition
labels are not chronology authority.

These are dispatch `result["rows"]` classifications, not rendered
`output.text` verdicts.

| Case | Rep | Run-ID SHA-256 | Source-row class | Leak-safe basis |
|---|---:|---|---|---|
| `hr-002` | R1 | `438cc780e1ab937bd5bf125797ee16c946daafd645c78406be6daa938cd9b87a` | PROJECTION | Identifier plus requested person/pay fields |
| `hr-002` | R2 | `d676347a63f772104d7bdb2216e1c96b68000cfc28765a16416e00db46e22459` | PROJECTION | Person/pay fields narrower than published reference |
| `hr-002` | R3 | `45f74e6232142b1bad310158e870bde0448d495a6321e7c5f5ccafed7f365070` | PROJECTION | Identifier plus requested person/pay fields |
| `hr-003` | R1 | `c7f585a7fe098a676a8a672c7264670f78d4fdb3210e589954cf501c521424a9` | PROJECTION | Identifier added to name/pay fields |
| `hr-003` | R2 | `fdc8f92f7da8a45dd8c5f50a415f36c4eafaf880f8ae39757a4e375c5e2296ea` | PROJECTION | Identifier added to name/pay fields |
| `hr-003` | R3 | `a3d64468a2758b7e399141ef052ac658aac34cab8541c4c3090eaa8511a6ffdf` | EXACT | Full fetched rows equal live reference |
| `hr-005` | R1 | `9838476ce54d2917f647d957190bfdf4495e5988eafe56cc38aa7aec856e23d6` | PROJECTION | Subject context plus role-qualified manager fields |
| `hr-005` | R2 | `6b898f01c5e1d27307b62ce07b74b2ae88f0e091357030e78b73a288e7b42001` | EXACT | Full fetched rows equal live reference |
| `hr-005` | R3 | `0bb9920f9fdf45fa0473912f2cac768521a0f73e9f8abfc0426ddbfa4d64e578` | EXACT | Full fetched rows equal live reference |
| `hr-006` | R1 | `62a7cbdc06d1b08e8a96f2b61ffbf22952bad3334d6e084e84d5b4c4ad9c3fdd` | PROJECTION | Names only; projected bag matches, sequence differs |
| `hr-006` | R2 | `bfddc2b1ae491795e65a986b93319ea4644a2edbfbb531afc0ea53336ed66ce7` | PROJECTION | Names only; projected bag matches, sequence differs |
| `hr-006` | R3 | `cbf9331e1874233500cabb28d471eee6fe037ae946d8111ce10406465dd15c42` | PROJECTION | Names only; projected sequence matches |
| `hr-008` | R1 | `d6710dd673df87a3b16075c4d579f0d95328e41df51225dcee048e0df9cd3879` | TIE | Alternate member at unstated cutoff tie |
| `hr-008` | R2 | `cfb8b261f720c35986bf9c73d88d38e2a57e50d263e157875e59e3a3c1ad41c3` | TIE | Alternate member at unstated cutoff tie |
| `hr-008` | R3 | `0a5012f70ef0a3515840e9cdf118282605d69c7f879ea1b8e27b8d59a13f3efd` | EXACT | Full fetched rows equal live reference |

Aggregate: **4 EXACT, 9 PROJECTION, 2 TIE, 0 wrong-data**.

This partition describes source-row semantics only. JSON rendering may omit
extra keys, Markdown may rename headers, and prose may not expose fetched
shape. No repetition receives an evaluator PASS/FAIL prediction from this
table.

## 4. HR Fixture Remediation

The later HR fixture change keeps `schema_version = 1` and shipped scorer
semantics. All five affected cases remain `kind="golden"` with
`scoring="deterministic"`; the change is pack data only.

| Case | Required fixture question and golden change |
|---|---|
| `hr-002` | Ask: "Who is the highest-paid employee, and what do they earn? Give only the employee's first name, last name, job title, and salary." Project exactly those four answer fields in the reference and expected rows. |
| `hr-003` | Ask: "List the top five earners in descending salary order. For equal salaries, put the lower employee ID first. Show only first name, last name, and salary." Keep salary descending plus employee-ID ascending as the reference tie-break; the ID orders tied rows but is not an answer field. |
| `hr-005` | Keep the existing fictional subject clause byte-exact and append: "Give only the manager's name in columns named `first_name` and `last_name`." Alias the reference SQL outputs exactly as `first_name` and `last_name`, and keep those exact expected columns. Subject fields and manager-prefixed aliases are not answer fields. |
| `hr-006` | Ask: "List the first and last names of current employees who have held more than one previous role here. The order does not matter; do not include employee IDs or prior-role counts." Qualify and group by employee identity in an inner query, then project names in the outer query. Add the exact `order-insensitive` token to the notes because shipped v1 ordering reads that token. |
| `hr-008` | Ask: "Which three departments have the most staff? Give each department name and staff count, ordered by count descending. If departments tie for the final place, choose the department whose name comes first alphabetically." Keep the alphabetical cutoff explicit in reference SQL and expected rows. |

The `hr-008` choice resolves the natural-language ambiguity by making the
already-published alphabetical cutoff explicit. The captured R1/R2 source-row
sets would be nonconforming if serialized as the complete answer under the
corrected cutoff; prior rendered evaluator verdicts remain unknown. R3
remains source-exact.

The retained worker comparison, SHA-256
`04d8ad71c63bc3206b5a36ae5c738bc6ba77cf4f1c43a22fce55f4f1d9643852`,
shows all three `hr-006` repetitions were inspected and were narrower
projections. Because those observations select the rewrite, `hr-006` is no
longer unseen for later tuning. This is benchmark-methodology contamination,
not model-training or data leakage.

The corrected fixture must:

- set `hr-006` to `holdout=false` and remove it from the manifest holdout list;
- retain it as a tuned regression;
- add a genuinely unseen golden holdout in the same cross-view/history
  failure family;
- make the replacement reference qualify/group by employee identity before
  projecting names, preserving homonyms and duplicates; and
- freeze the replacement case and candidate-corpus digest before any model
  run, with independent human author/reviewer confirmation that it did not
  inform tuning.

Out of scope: `hr-001`, `hr-104`, `hr-105`, `hr-201` through `hr-204`, SH/CO
teaching changes, and the two-model experiment.

The existing judge-routed case text, rubric, judge-case set, and judge
calibration fields remain byte-identical. Any drift in those surfaces stops
the reduced fixture release for separate review.

## 5. Lossless Reference-Result Boundaries

### 5.1 Invariant

A result producer must not create a mapping until it proves every raw column
name has a unique, nonempty comparison key. The comparison key remains the
shipped generic rule:

`re.sub(r"[^a-z0-9]", "", name.casefold())`

For any cursor result:

- column metadata must be strings;
- each normalized key must be nonempty;
- normalized keys must be unique;
- every fetched row width must equal the raw column count; and
- a violation refuses the whole result before any row mapping or partial
  output is produced.

This is not alias learning. Inputs such as punctuation-only names or names
that differ only by case/punctuation are ambiguous and fail closed.

### 5.2 Oracle tool pack

`cognic-tool-oracle-schema/readonly_query.py:459-463` currently collects
cursor names and immediately constructs dictionaries. The later fix validates
the invariant after `cursor.description` is read and before `fetchall()` rows
become dictionaries.

Failure uses the existing `query_execution_failed` envelope, emits no rows,
and logs only the exception class under the existing value-free logging
contract. No new tool refusal reason or result profile is required. Unique
columns retain the current envelope byte shape.

### 5.3 BAR-I live-reference producer

`infra/proof-m85c/run-proof-m85c.sh::build_live_reference_results`
(`:6779-6831`) bypasses the tool pack and independently constructs row
dictionaries from `cursor.description`. Its embedded Python must apply the
same invariant before its row comprehension.

A violation exits the producer nonzero, writes no usable reference-results
artifact, and reaches the existing BAR-I failure path:
`BAR I.6 live reference query failed for <fixture>`. The proof must not
continue with a partial case matrix.

### 5.4 AgentOS CLI loader

`src/cognic_agentos/cli/skill_eval.py::_load_reference_results` currently uses
ordinary `json.loads`, which collapses duplicate JSON object properties
before envelope/matrix checks can observe them.

Use a pair-preserving `object_pairs_hook` that refuses a duplicate raw
property at every object depth before constructing a dictionary. This covers
the outer envelope, `reference`, `results`, per-case table objects, and row
objects. The failure remains the existing
`ValueError("reference-results file is unreadable")`; it must not echo the
duplicate key or any row value. Valid schema-version-1 files retain their
current return shape.

The CLI need not infer Oracle columns or add a matcher. Cursor-column
normalization belongs at the two producers; duplicate serialized properties
belong at the JSON loader.

## 6. Fixture Governance and Product Finding

The released HR fixture's signed declaration currently says:

```toml
data_classes = ["internal"]
purpose = "operational_telemetry"
retention_policy = "none"
egress_allow_list = []
```

That declaration does not authorize judge egress or DecisionHistory retention.
Before any corrected HR fixture is sent through an existing judge-routed case,
a **HUMAN-ONLY** fixture decision must amend the signed declaration to
accurately name the fictional fixture data class, evaluation purpose, selected
judge route/egress, and proof retention. The corrected fixture must then be
reviewed, signed, and re-released. This is a low-stakes fixture-data correction
and does not establish a production policy.

Separately, the kernel has a generic product defect:

- `JudgeRequest`, `/api/v1/eval/judge`, and `LLMGateway` do not receive the
  originating pack's signed data classes, purpose, egress allow-list, or
  retention declaration; and
- route/provider policy therefore cannot enforce those pack-authored fields.

Track that defect independently. This brief does not design its solution,
choose an owner, add a governance subsystem, or make that generic product fix
a BAR-I prerequisite. The fixture amendment makes the signed fixture contract
honest; it does not claim the kernel now enforces that contract for production
packs.

## 7. Gate Honesty

Step A observed tool-result rows. The evaluator scores rendered
`output.text`. Those are different surfaces.

Under shipped behavior:

- deterministic row cases use `result_value_matches()`
  (`skill_eval.py:791-836`);
- Markdown requires the expected normalized header set, while JSON object
  rows select expected keys and ignore extras;
- the exact notes substring `order-insensitive` controls unordered row-bag
  comparison at `skill_eval.py:895-901`;
- current cell normalization is exact and does not implement July-14 float
  tolerance; and
- cases already selected by `_routes_to_judge()` retain their existing
  calibrated judge behavior. No new case is routed.

A BAR-I report with `golden_accuracy == 1.0`,
`golden_all_correct == true`, and an empty `golden_failure_case_ids` means
every with-skill golden observation passed its shipped scorer and none
errored. For deterministic rows, that is current table/JSON extraction and
value comparison. For already-shipped judge cases, it includes the existing
model-dependent calibrated verdict.

It does **not** prove:

- whole-answer truthfulness, because contradictory prose or extra JSON keys
  can coexist with a matching extracted projection;
- July-14's separate `<2%` semantic wrong-answer taxonomy;
- a hard 0% hallucination rate;
- float-tolerant semantic equality;
- that Step A's 4/9/2 source partition predicts rendered-answer verdicts; or
- production data-governance enforcement.

`wrong_answer_rate` remains the shipped aggregate `1 - accuracy`; it is not
silently relabeled as the July-14 semantic metric. `hard_zero_observed`
remains the shipped hard-kind gate, not a hallucination classifier.

## 8. Acceptance and Mutation Matrix

No tests run in this design-only task. A later separately authorized
implementation must provide:

| Area | Required pin |
|---|---|
| Fixture wording | Exact question/notes/reference/expected pins for `hr-002`, `hr-003`, `hr-005`, `hr-006`, and `hr-008` |
| Fixture live sweep | Every changed reference SQL runs against the pinned stock Oracle fixture, returns nonempty deterministic results, and matches expected rows |
| `hr-003` | Salary descending and employee-ID ascending tie-break are both present; deleting either ordering term turns the pin red |
| `hr-006` | Identity-qualified inner grouping, name-only outer projection, newly added exact `order-insensitive` token, tuned-regression status, and replacement unseen holdout are pinned |
| `hr-008` | Alphabetical cutoff is explicit in question, SQL, and expected rows; removing any leg turns the pin red |
| Tool cursor columns | Unique columns pass; empty-normalized and colliding-normalized columns return `query_execution_failed` with no rows |
| BAR-I cursor columns | The same vectors fail before reference JSON is usable; removing either pre-dict check turns the structural/executable pin red |
| Row width | Tool and BAR-I producer refuse a fetched row whose width differs from cursor metadata |
| CLI JSON | Duplicate properties at envelope, reference, results, table, and row levels all raise the existing unreadable-file error without values |
| CLI compatibility | Existing valid schema-version-1 reference files load byte-equivalently |
| C9 non-regression | Existing `_routes_to_judge()` runtime, preflight, and calibration tests remain unchanged and green; no fourth routing authority appears |
| Architecture | Kernel scan remains free of fixture case IDs, Oracle/HR schema literals, case-specific branches, inferred aliases, and schema learning |
| Honesty | Report prose cannot equate shipped golden pass with whole-answer, semantic-rate, hallucination, float-tolerance, or production-governance proof |

Required mutations:

1. remove the tool's pre-dictionary normalized-column check;
2. remove the BAR-I producer's corresponding check;
3. restore ordinary `json.loads` in the CLI;
4. remove the `hr-003` tie-break;
5. remove the `hr-006` ordering token or keep it in holdouts;
6. remove the `hr-008` explicit cutoff; and
7. inject one fixture-specific literal or conditional into generic AgentOS
   evaluation source.

Each mutation must turn its dedicated pin red and be restored byte-exact.

Later gates are scoped to the changed repositories: skill-pack suite and
wheel-content checks; tool-pack full suite plus lint/type checks; kernel
focused CLI/infra suites plus the repository's ordinary commit gate for that
code change; `bash -n` for the proof runner; freshness for any tracked docs;
and the BAR-I structural gate before a live run.

## 9. Sequence and Residual Blockers

Required sequence:

1. Author and independently review an unsigned HR fixture candidate containing
   only the question/golden/holdout and fixture-governance corrections above.
2. Under separate code authorization, implement and mutation-prove the three
   lossless reference-result boundaries without changing shipped scorer or
   C9 behavior.
3. Live-sweep the changed HR reference SQL against the pinned stock Oracle
   fixture and freeze the candidate corpus/manifest digests before any model
   run.
4. Obtain the HUMAN-ONLY fixture-governance approval, then sign and release
   the corrected HR fixture. Separately release the corrected Oracle tool pack
   under its normal custody lane.
5. Update only the affected proof release pins, run structural gates, and run
   BAR I with the shipped evaluator.
6. Record the actual rendered evaluator report with the honesty boundaries in
   section 7. Release/proof evidence must cite the exact signed fixture and
   tool artifacts used.

Residual BAR-I blockers after this design:

- maintainer approval of the fixture-governance declaration;
- HR fixture corpus/holdout review and signed re-release;
- implementation and review of the three no-collapse boundaries;
- signed Oracle tool-pack release and proof re-pin;
- a fresh BAR-I run establishing actual rendered outcomes; and
- any genuine model-quality miss surfaced by that run.

The independent generic signed-governance enforcement defect remains open but
is not a BAR-I prerequisite under this fixture-only ruling.

Non-goals: evaluator routing or matching changes, corpus schema changes,
calibration redesign, ADR amendments, production-schema policy, new evidence
or attestation formats, model comparison, implementation in this task,
staging, commit, release, or any remote action.
