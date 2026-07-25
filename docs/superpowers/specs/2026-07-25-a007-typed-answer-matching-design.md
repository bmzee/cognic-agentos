# A-007 BAR-I Rows-Mode Remediation Brief
<!-- STATUS: CURRENT -->
<!-- OWNER: cognic-agentos maintainers -->
<!-- LAST-VERIFIED: 2026-07-25 -->

**Decision status:** PROPOSED for maintainer acceptance

**Scope:** signed HR corpus clarification plus an explicitly opted-in,
exact-first fallback to the existing ADR-010 judge

**Baseline:** `feat/m85e-s4-bar-i@468d02381c4dc63c5784684cc8491c1ebc79a988`

## 1. Decisions

This brief proposes three bounded changes:

1. A future `cognic-skill-hr-data` candidate makes four answer projections
   explicit, resolves the `hr-008` cutoff tie, and replaces the contaminated
   `hr-006` holdout.
2. `scoring="exact_then_judge"` explicitly opts a signed case into
   deterministic equality followed, only on non-match, by the existing judge.
3. A-007 remains an acceptance-bar name for generic AgentOS evaluation
   machinery; no module relocation or symbol rename is proposed.

This is nine projection remediations plus two tie-policy resolutions in
skill-pack data. It is not eleven observations made to pass. Captured
post-remediation evaluator outcomes remain unknown until a fresh BAR-I run.

No schema-specific matcher, row digest, evidence schema, service, migration,
pack kind, runtime loader, or business-schema logic is introduced. The only
generic evaluation changes are the versioned fallback route and strict
projection for that profile.

## 2. Ownership and architecture

The four modules `evaluation/skill_corpus.py`, `evaluation/skill_eval.py`,
`evaluation/skill_calibration.py`, and `cli/skill_eval.py` are generic
AgentOS machinery under ADR-010. `load_skill_corpus()` parses a path
(`skill_corpus.py:335-340`); its proof/install caller establishes signed-wheel
custody first.

| Authority | Responsibility |
|---|---|
| Signed skill pack | Cases, questions, reference SQL, expected values, projection, order/tie wording, notes, and presentation requirements |
| Signed tool pack | Governed query execution, database-specific behavior, and result-envelope semantics |
| AgentOS | Generic corpus validation, deterministic comparison, governed judge routing/calibration, repetitions, ablation, and gate math |

ADR-010 originally described agent-pack YAML; commit `0342cffa` added the
signed skill-pack convention followed here. Nothing is relocated, deleted,
deprecated, or orphaned.

Fallback inherits the correlation already implemented by `skill_eval.py`:
`SkillCaseVerdict` records repetition and variant (`:103-104`), the matrix
keys every result by `(case_id, repetition, variant)` (`:185-193`), the report
projects `judge_model_alias` (`:141`, `:303`, `:1101`), and `_judge()` refuses
a requested-alias mismatch (`:945-946`). The judge route separately
hash-chains the actual upstream model and tier, while ADR-007 ledgers resolved
provider/route provenance under its request ID. That request ID, actual route,
and judge rationale are not joined into `SkillCaseVerdict` or the stable
skill report, so current evidence proves the hybrid matrix aggregate but not a
per-repetition judge-event/ADR-007 join. This brief adds no correlation
mechanism and makes no stronger claim.

AgentOS remains schema-agnostic. Architecture tests scan evaluation sources
and `src/cognic_agentos/cli/skill_eval.py` and fail on:

- `hr-*` case IDs, HR/Oracle table, view, field, scope, server, or tool
  literals;
- a case-ID comparison against any literal string or literal collection;
- a case-specific conditional; or
- runtime/value-inferred aliases or schema learning.

One mutation per class must make its pin red. Generic header normalization
remains allowed; the HR examples below never become AgentOS constants.

## 3. Frozen Step A evidence

### 3.1 Retained hashes and provenance gaps

No model or cluster was rerun. Retained SHA-256 values:

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

Raw fictional rows remain untracked in
`scratchpad/a007-rows-diagnostic/output-step-a-8/`; worker revalidation is
`scratchpad/a007-step-a-worker-revalidation-2026-07-25/comparison.json`.
Both stay unstaged and uncommitted pending maintainer disposition.
Any durable validation record stores only these hashes, case/rep labels,
counts, and provenance gaps. Raw rows remain guard-path-only until an explicit
retention or deletion ruling.

The checked-out skill source is revision
`5b17538b91699261198407b9afc489d2db7f0e06`, but Step A did not retain a
verified wheel digest or attestation-to-source join. These hashes therefore
bind the frozen capture and checkout, not an independently proven released
wheel. The diagnostic producer/instrumentation is also guard-only rather than
a signed release artifact. A later proof must record verified wheel, installed
corpus, producer revision, and source-attestation identities before making
release-provenance claims.

### 3.2 Complete chronological classification

The canonical chronology method is: preserve
`run-question-map.jsonl` line order (its source query orders by
`created_at, agent_run_id`), decode `question_b64`, join it byte-exactly to the
released question, assign R1-R3 within each case in that order, and compute
`sha256(run_id.encode("utf-8"))`. The canonical UTF-8 lines
`case_id<TAB>R<n><TAB>run_id_sha256<LF>` in the table order below hash to
`03903a580238c31b0220940033a67e79b8fb5b86ea3f676508ee622fcb63b49b`.
`recompute.py` is retained for row comparison but its log-order repetition
labels are not chronology authority.

These labels classify dispatch `result["rows"]`, not rendered `output.text`.
JSON ignores extra object keys while Markdown requires exact headers
(`skill_eval.py:766-836`); the evidence therefore assigns no evaluator route
or verdict.

| Case | Rep | Run-ID SHA-256 | Source-row class | Evidential basis |
|---|---:|---|---|---|
| `hr-002` | R1 | `438cc780e1ab937bd5bf125797ee16c946daafd645c78406be6daa938cd9b87a` | PROJECTION | Identifier plus the requested person/pay fields |
| `hr-002` | R2 | `d676347a63f772104d7bdb2216e1c96b68000cfc28765a16416e00db46e22459` | PROJECTION | Person/pay fields, narrower than the published reference |
| `hr-002` | R3 | `45f74e6232142b1bad310158e870bde0448d495a6321e7c5f5ccafed7f365070` | PROJECTION | Identifier plus the requested person/pay fields |
| `hr-003` | R1 | `c7f585a7fe098a676a8a672c7264670f78d4fdb3210e589954cf501c521424a9` | PROJECTION | Identifier added to name/pay fields |
| `hr-003` | R2 | `fdc8f92f7da8a45dd8c5f50a415f36c4eafaf880f8ae39757a4e375c5e2296ea` | PROJECTION | Identifier added to name/pay fields |
| `hr-003` | R3 | `a3d64468a2758b7e399141ef052ac658aac34cab8541c4c3090eaa8511a6ffdf` | EXACT | Full fetched rows equal the live reference |
| `hr-005` | R1 | `9838476ce54d2917f647d957190bfdf4495e5988eafe56cc38aa7aec856e23d6` | PROJECTION | Subject context plus role-qualified manager fields |
| `hr-005` | R2 | `6b898f01c5e1d27307b62ce07b74b2ae88f0e091357030e78b73a288e7b42001` | EXACT | Full fetched rows equal the live reference |
| `hr-005` | R3 | `0bb9920f9fdf45fa0473912f2cac768521a0f73e9f8abfc0426ddbfa4d64e578` | EXACT | Full fetched rows equal the live reference |
| `hr-006` | R1 | `62a7cbdc06d1b08e8a96f2b61ffbf22952bad3334d6e084e84d5b4c4ad9c3fdd` | PROJECTION | Names only; projected bag matches, sequence differs |
| `hr-006` | R2 | `bfddc2b1ae491795e65a986b93319ea4644a2edbfbb531afc0ea53336ed66ce7` | PROJECTION | Names only; projected bag matches, sequence differs |
| `hr-006` | R3 | `cbf9331e1874233500cabb28d471eee6fe037ae946d8111ce10406465dd15c42` | PROJECTION | Names only; projected sequence matches |
| `hr-008` | R1 | `d6710dd673df87a3b16075c4d579f0d95328e41df51225dcee048e0df9cd3879` | TIE | Alternate member at the unstated cutoff tie |
| `hr-008` | R2 | `cfb8b261f720c35986bf9c73d88d38e2a57e50d263e157875e59e3a3c1ad41c3` | TIE | Alternate member at the unstated cutoff tie |
| `hr-008` | R3 | `0a5012f70ef0a3515840e9cdf118282605d69c7f879ea1b8e27b8d59a13f3efd` | EXACT | Full fetched rows equal the live reference |

Aggregate: **4 EXACT, 9 PROJECTION, 2 TIE, 0 wrong-data**. Under the current
v1 comparator added identifiers are unscored, not proven accurate. There is
no frozen answer text, so all fifteen evaluator outcomes require a fresh run.

## 4. Signed HR corpus candidate

These are data recommendations for a later unsigned candidate review in
`cognic-skill-hr-data`. This task edits no pack.

| Case | Recommended question and contract change |
|---|---|
| `hr-002` | "Who is the highest-paid employee, and what do they earn? Give only the employee's first name, last name, job title, and salary." Keep those four projected fields; under the new strict fast path an added identifier is NONEXACT. |
| `hr-003` | "List the top five earners in descending salary order. For equal salaries, put the lower employee ID first. Show only first name, last name, and salary." Keep the existing reference tie-break but make it explicit; the identifier orders tied rows and is not an answer field. |
| `hr-005` | Keep the existing fictional subject clause byte-exact and append: "Give only the manager's first and last name." Keep the manager-only reference projection; subject context is not an answer field. |
| `hr-006` | "List the first and last names of current employees who have held more than one previous role here. The order does not matter; do not include employee IDs or prior-role counts." Qualify and group by employee identity in an inner query, project only names in an outer query, and add the exact signed notes token `order-insensitive`; this preserves homonyms and duplicate names. |
| `hr-008` | "Which three departments have the most staff? Give each department name and staff count, ordered by count descending. If departments tie for the final place, choose the department whose name comes first alphabetically." Keep the existing alphabetical cutoff and expected rows. |

The released `hr-008` question did not disclose its notes-only alphabetical
cutoff, so its natural-language contract was ambiguous. The candidate chooses
one deterministic question instead of multiple accepted tie sets. Captured
R1/R2 become nonconforming if replayed; R3 stays source-exact.

Editing published holdout `hr-006` after seeing R1-R3 contaminates it. Mark it
as a tuned regression, set `holdout=false`, remove it from the holdout list,
and add a genuinely unseen golden holdout in the same cross-view/history
failure family. Its reference must qualify and group by employee identity in
an inner query, then project only names in an outer query; this preserves
homonyms and duplicate names instead of grouping them together. Before any
model run, freeze the replacement case and candidate corpus digests and obtain
independent human author/reviewer confirmation that holdout content did not
inform tuning. That confirmation is review evidence, not a machine-verifiable
attestation.

All five case IDs become fallback-eligible after opt-in. The source-only
4/9/2 partition predicts no fresh evaluator path. Out of scope: `hr-001`,
`hr-104/105`, `hr-201..204`, wider teaching, and the two-model experiment.

## 5. Minimal generic kernel design

### 5.1 Current authority

`result_value_matches()` compares rendered JSON/Markdown rows
(`skill_eval.py:766-836`). `score()` sends routed cases to `_judge()` and
converts every other non-match to deterministic non-pass
(`skill_eval.py:882-901`).

Released Orders `co-101` and Warehouse `sh-103` already use
`mode="rows", scoring="judge", expected.value=null, verify_live=true`.
They are direct-judge cases today; `co-101` relies on that judge to detect
followed embedded instructions. Their semantics must not change.

### 5.2 Versioned opt-in and strict projection

Golden-corpus schema v1 remains byte-compatible and accepts only
`deterministic|judge`. Schema v2 adds
`scoring="exact_then_judge"`. The loader supports both versions, rejects the
new value under v1, and rejects unknown versions. Existing v1 wheels,
including `co-101`/`sh-103`, retain direct-judge live-null behavior. An old
AgentOS reader rejects a v2 candidate before execution; new/old reader
compatibility is pinned. Parsing is schema-discriminated: widening the shared
`SkillScoring` alias must not make a v1 case accept the new value. Notes never
opt a case into judging.

A v2 fallback case is valid only when:

- kind is exactly `golden`, mode is `rows`, `verify_live=true`, and
  `reference_sql.strip()` is nonempty;
- authored value has exact outer keys `columns|rows`, non-null lists,
  nonempty string columns, and rows of exactly that width;
- normalized expected headers are nonempty and collision-free;
- resolved live rows satisfy the same contract; and
- it is neither a trigger nor a performance-conformance case.

Author-known violations are `skill_corpus_case_invalid`; live-resolved
violations are `SkillEvalContractError`. The performance exclusion prevents
an exact PASS from adding `shape_passed=None` to that side metric. The
golden-only restriction prevents exact structured data from bypassing the
whole-answer judge on a hard adversarial case; all five HR targets are golden.

One lower-level pure module, `evaluation/skill_answer_contract.py`, owns
`normalize_header()`, v2 expected-shape validation, strict JSON/Markdown row
extraction/matching, fallback criterion construction, and its 2,000-character
bound. It imports none of `skill_corpus`, `skill_eval`, or
`skill_calibration`; those three depend on it, preventing import cycles and
grammar drift. Moving `_header_key` into it preserves the v1 normalization
algorithm byte-for-byte.

For fallback exact matching:

- candidate JSON uses a pair-preserving decoder that rejects duplicate raw
  properties recursively at outer, table, and row objects before dict
  construction; such a document is NONEXACT;
- each JSON object row must have exactly the expected normalized key set;
  extra/missing keys, normalized-empty keys, or collisions are NONEXACT;
- a JSON table object has exactly `rows` or `columns|rows`; extra outer keys
  are NONEXACT, and supplied columns must exactly match normalized expected;
- positional JSON rows have exact width;
- Markdown has the same exact normalized header set, collision rules, and row
  width; and
- authored/live contract defects error before comparison, while candidate
  projection defects are NONEXACT and may reach the judge.

The one `normalize_header()` function applies to expected columns, JSON keys,
JSON `columns`, and Markdown headers. This parity makes every signed
"only"/"do not include" projection enforceable without HR-specific logic.
Reference acquisition must use the same duplicate-property refusal before it
creates Python mappings. For live mapping rows, strict validation compares the
raw normalized key set with expected columns before `_normalised_reference()`
may project or reorder values; extra, missing, normalized-empty, or colliding
live keys are `SkillEvalContractError`, never silently discarded.

That promise requires changes at three existing boundaries; the lower matcher
cannot recover information already collapsed:

1. `cognic-tool-oracle-schema/readonly_query.py:459-463` must normalize all
   cursor column names and refuse an empty or duplicate normalized name before
   its `dict(zip(columns, row))`-equivalent row construction. A lossless
   columns-plus-positional-rows envelope would also satisfy this boundary, but
   this brief selects fail-closed uniqueness for the existing envelope.
2. `src/cognic_agentos/cli/skill_eval.py:_load_reference_results` must replace
   ordinary `json.loads` with a pair-preserving duplicate-property refusal at
   the envelope, results, table, and row levels before Python dictionaries
   exist.
3. BAR-I's actual producer,
   `infra/proof-m85c/run-proof-m85c.sh::build_live_reference_results`
   (`:6779-6831`), bypasses the tool pack and constructs dictionaries directly
   from `cursor.description`. It must apply the same normalized
   empty/duplicate-column refusal before its row comprehension.

The tool-pack, proof structural test, and CLI tests share
normalization/collision vectors. None of these changes teaches AgentOS an
Oracle schema or permits inferred aliases.

### 5.3 One C9 routing authority

Audit C9 and commit `0342cffa` made `_routes_to_judge()` the sole authority.
Preserve its name and return a closed enum:

```python
class JudgeRoute(Enum):
    ALWAYS = "always"
    EXACT_THEN_JUDGE = "exact_then_judge"
    NEVER = "never"

    def __bool__(self) -> bool:
        raise TypeError("JudgeRoute requires explicit comparison")

    @property
    def may_invoke_judge(self) -> bool:
        return self is not JudgeRoute.NEVER

def _routes_to_judge(case: SkillCorpusCase) -> JudgeRoute:
    if case.kind in _TRIGGER_KINDS:
        return JudgeRoute.NEVER
    if case.scoring == "exact_then_judge":
        return JudgeRoute.EXACT_THEN_JUDGE
    if case.scoring == "judge" or case.expected.mode in {
        "refusal", "assumption", "clarify"
    }:
        return JudgeRoute.ALWAYS
    return JudgeRoute.NEVER
```

The three consumers use explicit semantics: runtime compares enum members,
run preflight checks `may_invoke_judge`, and
`skill_calibration._effective_judge_case_ids()` uses the same property.

Trigger precedence lives in the helper and calibration removes its duplicate
filter. No second judge/mode predicate is allowed. This closes the truthiness
trap where nonempty `"never"` selects every case.

### 5.4 Runtime and result states

Runtime order is:

```text
route = _routes_to_judge(source), exactly once
-> trigger kind: existing trigger scorer returns immediately
-> non-trigger: expected = _expected_value(source, reference_values)
-> ALWAYS: existing direct judge
-> EXACT_THEN_JUDGE: strict v2 validate/match; exact PASS else existing judge
-> NEVER: existing deterministic scorer
```

Within `SkillCorpusScorer.score()`, trigger return performs zero
`_expected_value`, reference-map lookup, strict-row work, or judge calls.
Run-level reference collection remains unchanged:
`required_reference_case_ids()` and the CLI reference-results set still
include any trigger authored with `verify_live=true`. The scorer-local pin
must not be described as zero reference I/O for the whole run. Only
`EXACT_THEN_JUDGE` enters strict v2 row validation and exact-first fallback.
Authored/live shape, drift, reference, calibration, authorization, or
criterion failure stays fail-closed before the judge.

| Condition | Existing result vocabulary |
|---|---|
| applicable calibration absent | run refusal `skill_eval_judge_calibration_missing` before network |
| authored corpus contract invalid | `SkillCorpusLoadError` |
| live reference/criterion contract invalid | per-case `outcome="errored"` via `SkillEvalContractError` |
| exact rows match | `outcome="succeeded"`, PASS, no judge |
| fallback judge `pass` with value criterion true | `outcome="succeeded"`, PASS |
| fallback judge `fail` or `inconclusive` | `outcome="succeeded"`, non-pass |
| judge transport, response, model, or criterion mismatch | per-case `outcome="errored"` |

Fallback cannot be a shape case, so `inconclusive` is always non-pass.
Legacy shape cases retain current behavior: a true value criterion may pass
despite aggregate `inconclusive`, while shape remains separately non-gating.

Normative precedence is signed-wheel/governance preflight, corpus-v2 load,
run calibration preflight, one route decision, immediate trigger return,
live expected resolution, strict exact comparison, then judge. Candidate
projection defects are NONEXACT; authored/live contract defects error at
their earlier boundary.

### 5.5 Criterion bounds and exact calibration

The current criterion truncates at 2,000 characters
(`skill_eval.py:969-984`). For fallback only, construct it in full and
require DTO fit:

- authored-value overflow is `skill_corpus_case_invalid` at load;
- live-resolved overflow is per-case `SkillEvalContractError`/`errored`; and
- calibration rejects the item with `SkillCalibrationContractError`.

Legacy `ALWAYS`, including `co-101`/`sh-103`, retains current truncation.
Changing that compatibility behavior is separate work.

Calibration permits repeated `case_id` values but requires unique `item_id`
values. The set of case IDs still equals `_effective_judge_case_ids()`.
This lets even one fallback case carry both a human PASS and FAIL example.
Calibration-sheet schema v2 carries that repeated-case contract; schema v1
retains its current unique-case behavior.

The staged API is:

```python
prepare_calibration(
    corpus, sheet, *, reference_values, verified_corpus_identity
) -> PreparedSkillCalibration
render_labeling_sheet(prepared) -> str
run_calibration_judge(prepared, *, target_url, token, http_client=None)
compute_calibration_report(prepared, labelled_sheet, judge_results)
```

`verified_corpus_identity` is an immutable value produced by the existing
signed-wheel verifier before corpus loading. It has exact fields
`wheel_sha256`, `queries_member_sha256`, `manifest_member_sha256`,
`queries_semantic_sha256`, and `manifest_semantic_sha256`. Member digests are
SHA-256 over the exact signed UTF-8 member bytes and are owned by that
verifier; preparation does not receive or claim to rehash raw bytes. The
verifier-approved load operation returns the parsed `SkillCorpus` and this
identity together. Semantic digests are, respectively, SHA-256 over
`canonical_bytes()` of the parsed case list in source order and the parsed
manifest model dump. Preparation recomputes only those two semantic digests,
compares them with the identity, and carries the complete identity unchanged
into the prepared artifact. A bare parsed corpus, a changed semantic digest,
or an identity not produced by the verified-load caller refuses.

`PreparedSkillCalibration` v2 is a closed canonical JSON object. Its body has
exactly `schema_version`, `skill_id`, `calibration_set_id`,
`requested_model_alias`, `verified_corpus_identity`, and `items`; its wrapper
has exactly `body` and `prepared_sha256`, where
`prepared_sha256 = sha256(canonical_bytes(body))`.
`core/canonical.py` stays byte-identical.

Every item has common exact fields `item_id`, `case_id`, `route`, `question`,
`candidate_output`, `resolved_expected`, `criterion`,
`question_utf8_sha256`, `candidate_output_utf8_sha256`,
`resolved_expected_canonical_sha256`, and `criterion_utf8_sha256`.
String digests use the exact UTF-8 bytes; structured expected values use
`canonical_bytes()`. When `verify_live=true`, the item additionally requires
`normalized_reference_canonical_sha256`, computed from
`canonical_bytes(_normalised_reference(...))`; the field is forbidden
otherwise.

Items form a closed route-discriminated union:

- `route="always"` represents legacy `ALWAYS` cases and forbids
  `deterministic_nonexact`; and
- `route="exact_then_judge"` represents fallback items and requires
  `deterministic_nonexact=true`.

The discriminator must equal `_routes_to_judge(case)`. Cross-arm fields,
missing hashes, unknown keys, and an `ALWAYS` item claiming a deterministic
result refuse. A mixed-v2 corpus containing legacy `ALWAYS` cases plus
fallback cases is a mandatory fixture; current HR contributes six `ALWAYS`
cases, including null and non-row expectations, alongside the five fallback
cases. `ALWAYS` preparation resolves its existing expected/live contract but
never invokes the strict deterministic matcher.

`prepare_calibration()` runs before labeling or judge calls. It resolves the
governed live values, validates v2 rows, proves every fallback candidate
NONEXACT with the shared strict matcher, builds the full criterion, and emits
the immutable prepared artifact. `render_labeling_sheet()` and
`run_calibration_judge()` consume it directly; the human sheet renders the
exact frozen question, candidate, and criterion bytes sent to the judge.
Labelled-sheet v2, judge-results v2, and report v2 each carry
`prepared_sha256`; every item joins by the exact `(item_id, case_id)` pair.
`compute_calibration_report()` verifies all joins and requires every fallback
case to have at least one human PASS and one human FAIL. Exact fallback items
or incomplete class coverage are contract errors.

Bounds are deterministic: 1-64 total items, 1-16 items per case (at least two
for each fallback case), at most 1,000 reference rows, 64 columns, 64,000
cells, 1 MiB canonical reference bytes, and 3 MiB canonical prepared-artifact
bytes. Static item and byte bounds are checked before reference work; live
row/cell/byte bounds are checked immediately after reference resolution and
before any judge call. AgentOS issues at most one judge request per item,
hence at most 64 requests. An isolated proof tenant must pass the existing
ADR-018 gateway quota check before each request; an exhausted quota refuses,
and BAR-I records configured limits plus observed actuals.

That is a request-count and already-consumed-actuals admission bound, not a
token reservation or hard spend proof. The existing gateway can overshoot a
limit by one completion, provider/proxy retries can occur behind one AgentOS
request, and usage settlement is best-effort when providers omit usage.
This brief neither changes ADR-018 nor claims those gaps closed.

BAR-I must reproduce the prepared normalized-reference SHA before claiming
criterion parity. Changed questions/effective set require a new sheet,
labels, calibration ID, and kappa; old values do not carry over.

Validation retains full SHA-256 values for the human sheet, judge results,
calibration report, normalized live reference, exact raw manifest and corpus
members, their parsed semantic forms, requested model alias UTF-8 bytes,
verified wheel, and prepared artifact. The measured kappa remains inside the
hashed calibration report and final manifest; no standalone canonical-decimal
kappa digest is claimed. Runtime keeps the existing requested-alias check and
trusts the signed `calibration_set_id` plus `measured_kappa`; actual
model/tier and ADR-007 route provenance remain separate as section 2 states.

Pre-calibration/final-wheel parity is a release-validation check over two
independently signature-verified wheels. Safe extraction rejects absolute or
parent-traversing paths, duplicate normalized POSIX paths, symlinks, and
non-regular payload members. The comparison includes every regular installed
payload member, including `SKILL.md`, the golden corpus, and package data.
ZIP metadata and directory entries are not payload. Before excluding the
generated `.dist-info/RECORD`, validation parses it as CSV and requires
exactly one matching SHA-256 and byte-size entry for every other regular
member, no duplicate/unlisted payload, and the expected single RECORD entry.
External signature/bundle records remain separately verified release
artifacts.

For `golden/manifest.toml` only, validation first parses the TOML and requires
the pre-calibration member to omit `[judge].measured_kappa` and the final
member to contain exactly one valid assignment for it. Normalized manifest
bytes are the exact original UTF-8 bytes with only that complete final
assignment line removed, preserving every other byte and line ending. The
normalized member size and digest use those bytes. Every other member is
hashed byte-exactly. A canonical tree is the path-sorted list of exact
`{"path": <POSIX path>, "size": <byte length>, "sha256": <lowercase hex>}`
objects; its root is SHA-256 over `canonical_bytes(tree)`.
Pre-calibration and final wheels must have identical path sets, member
digests after the stated manifest normalization, normalized manifest bytes,
and normalized tree roots. Thus the exact kappa assignment plus each wheel's
independently validated RECORD are the only permitted wheel differences; a
changed `SKILL.md`, question, note, reference, governance declaration, or
other installed byte refuses parity. This is validation evidence on existing
signed-wheel surfaces, not a new runtime evidence protocol.

Authored row headers use shared `normalize_header()`. Judge request criteria
and response results require an exact raw count and name set; duplicate names
refuse before dict conversion. A deletion/duplication mutation must fail.

### 5.6 Governance blocker and evidence honesty

Fallback sends candidate text, question, expected/live rows, reference SQL,
and notes (`skill_eval.py:903-984`); the judge route retains full criteria and
notes in DecisionHistory (`portal/api/evaluation/routes.py:95-139`).

The released HR outer manifest currently declares:

```toml
data_classes = ["internal"]
purpose = "operational_telemetry"
retention_policy = "none"
egress_allow_list = []
```

An empty allow-list permits no egress, and `retention_policy="none"` does not
authorize the judge's DecisionHistory retention. `JudgeRequest`, the judge
route, and `LLMGateway` carry no pack/data-class/purpose/retention context;
cloud policy checks route/provider, not this signed contract.

No existing enforceable preflight owner bridges that gap:
`infra/proof-m85c/run-proof-m85c.sh` verifies wheel custody but does not
authorize governance, while `run_skill_evaluation()` and `/api/v1/eval/judge`
lack the manifest context. Therefore the present HR pack cannot enable
fallback, and BAR I remains blocked on it.

A separately reviewed candidate must change its signed outer
data-governance declaration to authorize the actual local/external judge
route, evaluation purpose, and DecisionHistory retention, or use a separately
authorized compatible judge/evidence path. The same decision must authorize
the governed live-reference query, value-bearing prepared/labelled/judge-result
artifacts, human-labeler access, their private storage and retention deadline,
and cleanup. Existing operator-owned proof-temporary custody may hold those
artifacts for BAR-I only after that authorization; it is not durable or
general-purpose custody.

A separate implementation/design authorization must assign and test a
fail-closed preflight owner that receives the verified manifest context before
live-reference preparation, human-sheet release, or any judge call. This brief
does not invent one. `eval.judge.run` and gateway route/provider policy remain
necessary controls, but they are not sufficient data-governance
authorization.

`SkillCaseVerdict`/stable reports omit scorer basis and judge events lack
case/repetition/variant correlation. Current evidence exposes only the
hybrid aggregate, not its exact/judge mix; no report field is added here.

## 6. Gate and governance claims

A judge PASS may satisfy commit `0342cffa`'s 100% golden sub-gate only after
calibration over the exact effective route set meets the signed
`minimum_judge_kappa` (currently 0.70). Judge FAIL, `inconclusive`, or error
breaks the sub-gate. The only currently auditable claim is aggregate and
model-dependent:

> `golden_all_correct=true` and `golden_accuracy=1.0` for the observed
> with-skill golden rows under the configured hybrid scorer.

It does not identify any repetition's scorer path or claim model-free source
equality/whole-answer correctness.

The exact fast path remains a structured-table check, not a whole-answer
fidelity proof: a matching table or JSON document surrounded by contradictory
prose or another unsupported assertion can still pass. Strict v2 projection
closes extra table and row keys, but broader contradiction/multiple-document
handling is a named residual risk and separate matcher work.

July-14's separate semantic wrong-answer target remains unresolved. Current
`wrong_answer_rate` is simply one minus pass rate over golden+adversarial
rows; it does not distinguish wrong answers from safe refusals/misses, is not
in the `passed` conjunction, and the signed minimum is 100 observations while
the proposed HR run has fewer than 100 with-skill answer observations. BAR I
must not claim the `<2%` semantic gate. Defining that outcome taxonomy and
minimum-observation gate is separate work outside this remediation; neither
the report field nor a redundant conjunction is mutation evidence for it.
BAR I also cannot claim July-14's separate hard 0% hallucination rate:
`hard_zero_observed` applies the current signed hard-failure kinds and does
not implement the answerable/refusal/hallucination taxonomy at July-14
lines 89-99.

July-14 governs semantic intent: unordered unless implied, labels are not the
answer, and judge use is secondary
(`2026-07-14-skill-engineering-and-accuracy-design.md:73-81,148-166`).
Schema v1 instead uses notes token `order-insensitive`
(`skill_eval.py:891-901`), which remains BAR-I's wire encoding. `hr-006` adds
it; `hr-003` and `hr-008` author order/tie-breaks. A typed field is future.

For schema v2, strict authored header/key equality deliberately amends
July-14's column-name-insensitive rule: a friendly alias or extra projected
field is NONEXACT and reaches the calibrated judge rather than passing the
fast path. Schema v1 remains unchanged. Numeric fast-path comparison also
keeps current exact normalized-Decimal equality for floats, counts, and
money; it does not implement July-14's float tolerance. A non-exact float may
reach the judge, but that is not a numeric-tolerance implementation, so BAR I
must not claim that July-14 requirement either.

## 7. Required tests and mutations

| Pin | Required behavior |
|---|---|
| legacy rows+judge | `co-101`/`sh-103` remain `ALWAYS`; live-only null expected remains valid |
| schema readers | v1 rejects fallback but preserves old cases; v2 accepts valid fallback; unknown versions refuse |
| exact fast path | exact fallback case passes with zero judge calls |
| non-exact path | eligible non-match reaches judge and preserves PASS/FAIL/inconclusive |
| JSON/Markdown parity | exact key sets pass; extra/missing/colliding/empty headers are NONEXACT and invoke judge |
| raw JSON boundaries | duplicate properties at candidate outer/table/row levels are NONEXACT; duplicate live properties error before projection |
| table boundaries | extra expected keys/blank SQL/bad live width or raw extra/colliding live keys error before projection; extra candidate table keys/bad positional width are NONEXACT |
| `test_reference_producers_refuse_normalized_duplicate_columns` | tool-pack and BAR-I producer refuse collisions before row dict construction; CLI refuses duplicate JSON before mapping construction |
| error precedence | governance/load/preflight/trigger/live/exact/judge ordering is fail-closed and mutation-pinned |
| performance class | fallback case in `non_gating_case_ids` refuses at load |
| safe fallback scope | only golden cases may opt in; adversarial fallback refuses at load |
| `test_routes_to_judge_is_sole_routing_authority` | no second routing predicate exists |
| `test_judge_route_consumer_matrix_is_explicit` | runtime, preflight, and `_effective_judge_case_ids` use the helper explicitly |
| `test_judge_route_refuses_boolean_coercion` | bool conversion raises for every enum member |
| `test_effective_judge_case_ids_includes_every_reachable_case` | calibration covers `ALWAYS` and fallback, never triggers/`NEVER` |
| `test_trigger_scorer_is_expected_and_judge_free` | route computed once; scorer performs zero expected/reference-map/strict/judge calls while run-level live-reference collection stays compatible |
| rows shape | null/malformed fallback rows refuse; legacy live-only judge rows still load |
| header/criterion identity | shared normalization rejects empty/colliding headers; judge criteria reject duplicate/missing names |
| criterion fit | fallback static overflow load-refuses; live overflow errors before judge; legacy direct-judge compatibility is pinned |
| mixed calibration staging | `ALWAYS` forbids deterministic fields; fallback requires `deterministic_nonexact=true`; cross-arm fields refuse; every fallback case has labelled PASS+FAIL |
| `test_prepare_calibration_binds_verified_identity_semantically` | verifier owns raw-member hashes; preparation recomputes parsed-semantic hashes, preserves the exact immutable identity, and joins normalized-reference/UTF-8/canonical digests through labels/judge/report |
| calibration bounds | item/per-case/reference/cell/byte/call caps refuse before the corresponding reference or judge work |
| existing model evidence | requested-alias drift refuses; actual model/tier and ADR-007 route stay separately recorded and unjoined |
| wheel parity | RECORD mismatch refuses before exclusion; any added/removed member or changed non-kappa byte changes the normalized tree root |
| golden gate | judge PASS may meet the 100% golden aggregate; FAIL/inconclusive/error breaks it |
| semantic-rate honesty | current `wrong_answer_rate` is never presented as the unresolved July-14 `<2%` gate |
| doctrine honesty | strict v2 headers and exact floats are pinned as July-14 amendments/nonconformance; BAR I cannot claim its hallucination taxonomy |
| ordering | v1 notes token controls unordered comparison; removing it from `hr-006` turns the pack pin red |
| exact-scope honesty | contradiction, multiple-document, and unsupported-assertion fixtures pin the documented fast-path limitation; reports never call it whole-answer correctness |
| architecture | each HR/Oracle literal, case-ID branch, and alias-learning mutation turns its fence red |

Mandatory mutations map `EXACT_THEN_JUDGE` to `NEVER` or `ALWAYS`, use route
truthiness, omit a C9 consumer, resolve expected before trigger return, ignore
an extra JSON key/Markdown header, collapse duplicate JSON properties, project
away an extra/colliding live key, collapse duplicate cursor names in either
the tool pack or BAR-I producer, accept duplicate reference-file properties,
accept a blank SQL/empty or colliding header/extra expected key/bad width,
allow fallback into the adversarial or shape set, delete criterion fit or a
calibration bound, mis-tag an `ALWAYS` item as deterministic, substitute a
parsed corpus whose semantic digest differs from the verifier identity, alter
the identity instead of carrying it byte-exact, drop a normalized-reference
digest join, calibrate an exact fallback candidate, reject duplicate case
IDs, skip per-case PASS+FAIL enforcement, accept duplicate criterion names,
accept requested-alias drift, skip RECORD validation, ignore an
installed-payload change, send an exact match to judge, or hide judge
non-pass/error from the golden aggregate. Each must turn its named regression
red.

Fresh evaluation tests, Ruff, format, strict mypy, and the repository full
suite are implementation gates because `evaluation/` is shared machinery.
Because this changes acceptance authority, a later separately authorized
implementation must amend ADR-010 before its code commit and place the new
`skill_answer_contract.py` authority plus the affected schema, routing, and
calibration modules on the durable critical-control review/coverage packet
at the 95% line/90% branch floors with negative-path and mutation evidence.
The implementation review determines the complete file list and count; this
brief freezes neither. This task edits no ADR and authorizes no
implementation.

## 8. Naming, future work, and release sequence

`A-007` is an acceptance-bar ID and the four modules are generic. A future
naming cleanup may revise ambiguous docstrings or report labels to "signed
skill-pack golden evaluation." It does not imply relocation or a code rename.

**Governed External Scorer Protocol** is legitimate future ADR-010 work on
signed binding, isolation, and calibration attestation. It is not designed,
authorized, or required here. The established vocabulary already has five
pack kinds; this brief adds none and prescribes no PluginRegistry/runtime
loader.

Holdout non-exposure currently rests on a pre-run frozen candidate digest and
independent human author/reviewer confirmation; it is review evidence, not
machine-verifiable proof, and undisclosed holdout-informed tuning remains a
residual risk. A signed non-exposure attestation bound to a wheel content root
would be a new ADR-016 mechanism. It is deferred future work, is not a BAR-I
prerequisite, and is not authorized or designed by this brief.

Required sequence:

1. author and independently review the unsigned HR candidate, including the
   replacement holdout and its human non-exposure confirmation;
2. obtain separate authorization for schema-v2 implementation and for a
   governance-compatible preflight/path;
3. independently review and sign a pre-calibration candidate wheel whose
   governance decision authorizes the actual judge route/retention and whose
   measured kappa is absent; address it only by its digest, mark it
   non-releasable, and never register, tag, or publish it under the release
   version;
4. verify that wheel before loading it, record the human holdout review, then
   prepare, label, judge, and compute calibration;
5. write only the final measured kappa under the already frozen calibration
   ID, build/sign the final candidate, and require the full installed-payload
   parity check above against the calibrated wheel; only this final wheel
   digest enters registry/ADR-016 release records;
6. run BAR I against those final bytes, retaining leak-safe hashes and the
   explicit Step-A provenance gap; and
7. release only after every applicable gate is honestly green and explicit
   release authorization is granted.

Until steps 2-4 exist, fallback is blocked and this brief cannot unblock
BAR I.

Non-goals: code, corpus, ADR, manifest, evaluator, model/cluster, staging,
commit, remote action, the two-model experiment, and any new protocol,
service, migration, evidence profile, custody system, or pack kind.
