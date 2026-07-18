# Proof M8.5-C — Cognic Harness v1 (basic bank harness) live proof

> **STATUS: PASSED LIVE.** Run 20 completed on `kind` on 2026-07-14 with exit
> 0 and printed `PROOF M8.5-C (BARS A-F) PASS`. AgentOS anchor = proof
> revision `926b11884647ac3ea4045c5c3988020a99874c35`; the separately built,
> signed, and verified Cognic Harness revision was
> `4dc64cccb5c3a591f1a4e40885e2f58ad37f075c`. The operator-held 926-line log
> has SHA-256
> `233787cf37263ae1fdc2c513298106bc4bad006f8514bb31d08d91d6b9ecf593` and is
> deliberately not committed. Full bar evidence, the 20-attempt live-run
> ledger, and the honesty boundary are in `docs/VALIDATION-RESULTS.md` under
> "M8.5-C — Basic bank harness (ADR-028) — PASS".

> **D2 A-minus extension (2026-07-18): PASSED LIVE.** Attempt 6 completed on
> `kind` with exit 0 and printed `PROOF M8.5-C (BARS A-G) PASS`. The clean
> AgentOS anchor/proof revision was
> `c2f418a79b62fc3ee9e381494ede7d6dc3fba615`; the separately built, signed,
> and verified Cognic Harness revision remained
> `4dc64cccb5c3a591f1a4e40885e2f58ad37f075c`. The operator-held 939-line log
> has SHA-256
> `5ae3f83ea578614271ada9255a9a6d90f6873a11054c10598509a8c1bc7dc114`
> and is deliberately not committed. Bars A-F re-passed, and Bar G proved
> bank-owned 3-of-3 assignment, direct-MCP consume-once, and maker-checker
> exclusion. The historical run-20 record above remains unchanged.

## What the passing run proved

M8.5-C stands up the **Cognic Harness v1** — a same-origin BFF (`cognic-harness`
repo) with three governed screens (chat, approvals inbox, evidence) — in front
of a deployed AgentOS kernel, and proves the **harness boundary** and the
**approvals surface**:

- **Real OIDC identity, no fallback.** Every one of the ten proof identities
  arrives as a real Keycloak access token verified locally by the reference
  `ActorBinder` (`overlay_reference/`). The `X-Proof-Role` header binder that
  M8.5-A/B used is **deleted, not gated** (ADR-028 §4) — there is no actor
  header, no shared-secret impersonation, and no "trust unverified claims in
  proof mode" anywhere in the tree.
- **Session/token custody.** The BFF holds every OAuth token server-side in a
  dedicated TLS Redis; the browser gets only an opaque `__Host-` cookie. Two
  replicas share one session; logout revokes it on both; a Redis outage fails
  closed (re-authenticate/503), never a memory fallback.
- **The paginated four-eyes approvals surface (HP-4).** A separately-released
  high-risk MCP probe (`cognic-tool-approval-probe`, `risk_tier =
  high_risk_custom`) drives the ADR-014 four-eyes flow through the approvals
  screen; an independent proof-local ledger proves *zero execution* until the
  second distinct grant, and the actor-bound grant replay refuses a same-tenant
  different-subject replay (`tool_approval_originator_mismatch`).

## The bars (spec §5.2)

- **Bar A — session/BFF custody.** Session rotation (S1); OIDC state/nonce
  single-use — a replayed callback does not authenticate (S5); cookie-content
  inspection with no OAuth material (S8); **cross-replica** — the same session
  authenticates against **each named replica** individually via per-pod
  port-forward (S2), survives a pod kill (S9), and is dead on **both** replicas
  after logout (S3); a fail-closed Redis outage that does not abort the proof
  (S7); CSRF refused with the exact `403 csrf_invalid`; hostile-output XSS proven
  inert **and actually present** as escaped text.

  **Per-step replica attribution** (the ratified contract: *"Value-free proof logs
  record which pod served each step"*). The BFF exposes no per-pod response header,
  so the driver's own `served_by` key is `[]` — attribution is not *observed*, it is
  **established**: every host port-forward targets a **named pod**
  (`kubectl port-forward pod/<name>` bypasses the Service and connects to exactly
  that pod), so the runner **chooses** the serving replica and records it as
  `step=<name> served_by=<pod>`. That is a fact the runner created, not an inference
  about which replica **kube-proxy** happened to pick — and it alternates the two
  replicas across the steps, so both genuinely serve real traffic. A pod name is
  value-free: it carries no session, token or claim material.

  **All ten S-cases run LIVE** — including the three
  a first draft had ducked into the conformance suite: **S4** (idle and absolute
  TTLs are independent — proven by shrinking the BFF's own TTL env, showing an
  *idle* session dies while the absolute window is still open and a *continuously
  active* one still dies at the absolute window, then restoring); **S6**
  (concurrent refresh has exactly one winner **across replicas** — 8 simultaneous
  requests split across two per-pod port-forwards, with **Keycloak's own event
  log** as the independent observer: exactly 1 `REFRESH_TOKEN`, 0
  `REFRESH_TOKEN_ERROR`); **S10** (an unknown session-schema version refuses — a
  single-variable experiment that reads the live Redis record, changes **only**
  its `v` field, and proves the same cookie stops authenticating).
- **Bar B — identity.** A real browser login; the approvers bind as
  `actor_type="human"` — proven by a **human-gated action** (a deny), not a
  scope-only queue read; the locked grant profile's negative space
  (client-credentials + direct-access-grant attempts against `cognic-harness`
  both fail); four token-shape refusals at AgentOS, **each pinned to its exact
  binder gate** via the value-free `reference_binder.refused reason=…` log marker
  — real-ID-token substitution (`typ_not_at_jwt`), malformed bearer
  (`token_malformed`), unknown signing key (`kid_unknown`), and wrong audience
  (`audience_not_exact`, an otherwise-perfect token); a manipulated under-scoped
  grant against a **real** request refused with the kernel's governed **403**.
  The **expired-token** refusal is also live (`token_expired`): Keycloak's
  per-client `access.token.lifespan` override mints a 10-second token from the
  **same** client, so `azp` stays `cognic-harness` and the binder walks its gates
  in the usual order to reach the `exp` check with a genuinely expired, genuinely
  signed token — no 15-minute wait, no unit-suite delegation.
- **Bar C — chat.** A governed multi-turn conversation through the UI plus one
  entitlement-revoked turn (revoked by the binder's **issuer-qualified subject**,
  not the login name) whose refusal renders in the UI **and** correlates to the
  refused chain-dispatch row (the DB side is the runner's PSQL).
- **Bar D — approvals.** The eight-step four-eyes sequence against the probe,
  every recall an **actual replay** (the same `approval_request_id` + its bound
  nonce, so the kernel matches the SAME request — the milestone's whole point):
  pending→ledger 0; deny→exact-shape replay returns `tool_approval_denied`, ledger
  0; single grant→replay still `tool_approval_pending`, ledger 0; self-grant-second
  refused, distinct approver completes; re-call executes→ledger **exactly 1**;
  originator isolation (sara's exact-shape replay→`tool_approval_originator_mismatch`,
  ledger stays 1); `Link` pagination over 51 minted requests asserted as an
  **exact id-set** (no dupes/omissions) with a `Link` on page one and none on the
  last; a non-observer gets a rendered 403 (never hidden-empty); the
  foreign-tenant observer sees an empty own-queue.
- **Bar E — evidence.** The transcript + per-turn chain screens render; the
  driver extracts the rendered ids/digests; the runner's PSQL reconciles the
  rendered `agent_run_id` **and** the `question_sha256` / `answer_sha256` digests
  to the kernel chain row. The BFF image retains **zero DB driver**.
- **Bar F — structural.** Against the running BFF image: zero DB modules;
  **exactly the three screen route modules** (+ auth) and no operator/pack/builder
  surface; **no actor-header path**; no `|safe`; htmx absent (no un-pinned
  vendored asset); CSP + `no-store` present.
- **Bar G — assigned approval and consume-once.** Omar assigns Dana, Erin, and
  Fiona to the probe tool; a real service token is refused before mutation and
  exactly one `approval.assignment_changed` row is appended. A direct Postgres
  witness reads `flow=require_assigned`, `required_count=3`,
  `decisions_recorded=0`. The deployed detail wire then advances exactly
  **1/3 -> 2/3 -> 3/3**, with exact chain order and no probe execution. The first
  exact recall executes once (ledger **1 -> 2**); the second refuses
  `tool_approval_consumed` and the ledger stays 2. Finally, the same
  scope-holding originator is refused at decision index 0 with
  `originator_cannot_approve` and at index 1 with the byte-stable
  `four_eyes_approver_not_distinct`, after which the normal scope set is
  restored.

## Topology (spec §5.1)

The proven M8/M8.5 conversational stack (kernel proof app, oracle pack + XE + AS,
LiteLLM→cloud, Postgres) **plus**: Keycloak (pinned `26.2` digest, per-run realm
import, ten generated identities — nothing committed), a dedicated TLS session
Redis (BFF-only ACL, persistence off), **two** harness BFF replicas behind one
Service, and the approval-probe MCP Service. AgentOS terminates TLS itself; the
whole human-identity path runs HTTPS under one per-run proof CA with no
`verify=False`/`-k` anywhere.

## The TLS matrix — and the one disclosed exception

Every human/session-token leg is HTTPS under the per-run proof CA:
browser→BFF, BFF→AgentOS, BFF→Keycloak, BFF→Redis, and driver→Keycloak,
driver→AgentOS, binder-JWKS→Keycloak. **Disclosed exception (service-token
boundary):** the kernel→MCP-pack transport inside the cluster remains plaintext
HTTP, as in every prior M-series proof, and it carries the per-tenant MCP OAuth
**service** token — this is disclosed here and never folded into the
human-identity claim. Securing in-cluster MCP transport is a future slice.

## Prerequisites for the live run

1. **Bash 4.0 or newer.** The runner uses associative arrays for its
   identity/token matrix. macOS `/bin/bash` 3.2 is unsupported; invoke the
   runner with a current Bash. The runner checks this before provider or
   cluster work and fails with the installed version.
2. `COGNIC_RUN_PROOF_M85C=1` + the operator's cloud provider key
   (`COGNIC_PROOF_M85C_TIER1_API_KEY`).
3. **The D-S1 pack releases and rotated trust roots are COMMITTED pins.**
   `cognic-tool-oracle-schema@v0.4.0` and
   `cognic-tool-approval-probe@v0.2.0` carry the per-tool capability
   declarations required by the fail-closed dispatcher. Their wheel and
   `cosign.pub` digests are MAINTAINER-committed literals in `stage-packs.sh`;
   both public-key pins changed with these releases.

   This is deliberately **not** an operator-exported environment variable. *A pin
   the person running the proof supplies at run time is not a pin*: they could swap
   the release and export a digest that matches the swap. It only means something
   when it is committed in the tree that the proof-input cleanliness guard checks
   **before** the run. The runner reads the committed literals at preflight and
   fails loud in the first seconds — not 25 minutes in at Bar D — if a probe pin
   is ever reverted to its sentinel.
4. Two one-time operator `/etc/hosts` loopback entries (`cognic-proof-keycloak`
   + `cognic-proof-harness`) + the registry trust setup — the runner prints
   copy-paste instructions.

## Honesty boundaries (mandatory — spec §8)

1. **Direct-MCP grants are now consume-once.** BAR G claims a granted request
   atomically, executes the first exact recall, and requires a second identical
   recall to refuse `tool_approval_consumed` without moving the independent
   ledger. The historical Bar-D run predates this D2 change and remains a record
   of the then-current replayable contract.
2. The harness-PR-CI **kernel fake never counts as milestone evidence** — the
   real-kernel `kind` proof is the authority.
3. **HP-2 remains open per bank** (issuer, claim mapping, assurance level,
   accepted FAPI profile). The reference binder is a worked example, not a
   shipped bank overlay.
4. **Conversation-correlated auto-execution is not live-proven here.** D2's
   executor/system-turn path is unit/e2e-proven, but BAR G uses the direct-MCP
   probe. The live write + system-turn bar needs D5's external action agent and
   released write pack.
5. Any plaintext proof-internal MCP transport is disclosed explicitly (above).
6. The M8.5-C baseline is **RFC 9700**; full **FAPI 2.0** is the bank-deployment
   target — nothing here is called FAPI conformant. The realm pins the RFC 9068
   `at+jwt` **header type** only, not the full RFC 9068 claim profile.
7. **NOT PILOT-READY.** M8.5-C proves the harness boundary and the approvals
   surface only. Still outstanding before any pilot: HP-5, erasure,
   content-safety/escalation hooks, data-access brokerage (M8.5-D/E), full FAPI
   2.0 or a formally accepted equivalent, and D5's live write proof.

### M8.5-C-specific proof-staging disclosures

- **The shared approve trust root (governance-sensitive).** The approve 5-gate
  signature root is resolved per-tenant, but M8.5-C installs **two** tools-kind
  packs through the approve flow (oracle + probe) and a tenant-keyed root cannot
  carry two release keys. So the runner mints one per-run approve-signing key,
  stages its public half as `trust-roots/_default/cosign.pub`, and **re-signs
  both tools-kind wheels' `cosign.sig` under it** (analogous to the
  canonical-image re-home). Before overwriting either signature, it verifies the
  original signature offline against that release's digest-pinned public key and
  wheel; ADR-016 releases deliberately use `--tlog-upload=false`, so this check
  has no Rekor dependency. This is the one M8.5-C change to a proven (M8)
  trust-staging path; it is safe and localized (only the two tools-kind packs use
  `_default`; hook/skill/agent packs keep their own per-pack roots) but is
  **exercised only in the operator's live run** — it is not verified by the
  inline structural gates.
- **The BFF/probe images are built locally from clean-tree pinned commits.** The
  harness image is built from the `cognic-harness` repo at a clean tree,
  registry-signed under the proof key, and its signature is verified before
  `kind load` (the sign→verify→load discipline). Production verifies a
  CI-published cosign signature instead; the proof re-signs a locally-built image
  from the pinned commit.
- **Deployment mutations the proof performs (disclosed).** Three of the live
  session/identity cases are time- or state-dependent, and the runner reaches them
  by driving the system's *own* configuration surfaces rather than by waiting for
  hours or faking a result. Each is reverted immediately, and a failed revert is a
  hard bar failure, never a silent carry-over:
  * **S4** temporarily repoints the BFF's session TTLs
    (`COGNIC_HARNESS_SESSION_{IDLE,ABSOLUTE}_TTL_S` — the same env vars a bank
    operator sets) to 60s/150s and rolls out, then restores 900s/28800s. Leg 2
    (absolute expiry) **arithmetically excludes idle expiry** as the cause of death:
    every keep-alive touch must return **200**, the last one lands *inside* the
    absolute window, and the gap from that last touch to the final probe is
    *strictly less than the idle TTL* — so at the moment of the probe the session had
    been idle for less than the idle TTL, and the only clock that can have killed it
    is the absolute one. The runner asserts this both from the constants (before the
    leg) and from the realized wall-clock instants (after it).
  * **S6** and the Bar B **expired-token** leg temporarily set Keycloak's
    per-client `access.token.lifespan` (70s and 10s respectively) via the admin
    API, then restore it to 900s. `azp` stays `cognic-harness` throughout — the
    locked grant profile Bar B pins is untouched.
  * **S10** writes one mutated record into the session Redis (only the `v` schema
    field changes) using a TLS-verified `redis-cli` inside the store's own pod.
  These are *proof mechanics on a throwaway cluster*, and they are named here
  because they are the difference between "we proved it" and "we asserted it".

### Review-round hardening (2026-07-12, round 1)

An adversarial review of this tree before the live run found eleven defects, all
fixed in-tree (and each pinned by `tests/unit/infra/test_proof_m85c_remediation.py`
so a regression fails a gate, not the live run). The load-bearing ones: the
browser driver no longer self-authorizes TLS (it pins the SPKI of the on-disk
runner-minted leaf certs and **fails closed** if no pin can be computed — no
served-leaf fetch, no blanket `ignore_https_errors` fallback); **Bar D now
actually replays** each approval (the same `approval_request_id` + bound nonce),
without which the HP-4 actor-binding claim went entirely unexercised; the BFF pod
can read its own TLS key (pod `fsGroup: 10001`); every new secret rides a
`--from-file` 0600 file, never the `kubectl` argument vector; the four-eyes TTL
is raised above the browser-workflow duration; and the reference binder binds the
**stable issuer-qualified `sub`** (not the mutable `preferred_username`) as
`Actor.subject`, with the kernel seed rendered from the same value.

### Review-round hardening (2026-07-12, round 2)

The reviewer rejected that packet and found nine more. The theme: **several bars
could pass without their claimed evidence.**

- **The delegation was reversed.** Bar A had ducked **S4 / S6 / S10** into the
  store conformance suite, and Bar B the **expired token** into a unit suite — but
  the ratified spec (§5.2) requires all ten session cases *and* the expired-token
  refusal **live on kind**, and a README disclosure cannot lower a ratified
  contract. All four turned out to be perfectly liveable (see the disclosed
  deployment mutations above): the delegation had been convenience, not
  infeasibility. They now run live.
- **S5 was vacuous.** It replayed the consumed OIDC callback in a *cookieless*
  context — but the BFF reads the session cookie **before** it consumes the
  one-time state, so the replay died at the wrong gate, and a BFF that never
  consumed state/nonce at all would still have passed. The replay now carries the
  **pre-auth cookie**, and the BFF's new value-free `auth.callback.refused
  reason=…` log is what proves the refusal came from `login_state_already_consumed`
  rather than from `no_login_session`.
- **S9 / S7 / S3 could pass without their event.** S9 swallowed a failed pod delete
  with `|| true`, so *no restart at all* still passed (it now proves the victim's
  UID is gone); S7 accepted *any* browser-driver failure (it now demands the exact
  governed **503** against a live session, after a 200 control); S3 `continue`d past
  a missing replica while reporting "BOTH".
- **Bar C never proved a *visible* refusal** (a nonempty answer + a DB row sufficed,
  so a hallucinated figure would have passed) and **Bar E never validated the
  rendered transcript** (it compared the kernel's digests against the kernel's
  digests, and only checked the transcript was non-empty). Bar C now requires the
  refusal to **render**, with its **scope**; Bar E now re-hashes the **words on the
  page** against the chain rows.
- **A harness gap fell out of that.** `scope_id` was carried by the kernel chain
  row, the read API, the client and the view-model — then **dropped by the evidence
  template**. Because one turn dispatches the same capability against two scopes
  (retail allowed, financials refused), the two rows rendered indistinguishably and
  an examiner could not see *which* scope was refused. The template now renders it
  (`cognic-harness`, `evidence_chain.html`).
- Plus: the direct-AgentOS token cache is now **expiry-aware** (the realm mints
  900s tokens while the proof spends minutes between minting and use — it would
  have sent an expired bearer mid-run and failed looking like a governance bug);
  Bar D.7 asserts the **keyset order**, not merely set membership; and the probe's
  trust digests are **maintainer-committed literals**, not environment variables —
  a pin the operator supplies at run time is not a pin.

### Review-round hardening (2026-07-12, round 3)

Eight more. The theme: **credential custody, and gates that do not exist.**

- **Live credentials rode process argv.** Access JWTs, session cookies, callback
  URLs (whose `?code=` is exchangeable for tokens) and the whole session *record*
  (the OAuth access + refresh + id tokens) were passed as command arguments. An
  argument vector is world-readable — any local `ps` captures it for the life of
  the process. All of them now ride **stdin** or the child's environment; the
  driver's credential *flags* were deleted outright, with a negative selftest that
  refuses to let them return.
- **S4 could "prove" absolute expiry using idle expiry.** Its keep-alive touches
  discarded both transport failures and HTTP status, so a silently-dead touch loop
  would have let the session die of *idle* expiry at ~45s and credited the death to
  the *absolute* TTL. Every touch now must return 200, and idle expiry is
  **arithmetically excluded**: the last touch lands inside the absolute window, the
  runner then stops touching, crosses the absolute boundary, and probes — with the
  gap from last touch to probe strictly under the idle TTL.
- **The required production-bundle gate did not exist.** The spec requires a
  structural scan of the shipped image; CI had none. It exists now — and it
  immediately caught a latent **Bar F failure already in the tree** (the literal
  `|safe` in a shipped docstring, which Bar F greps the installed package for). The
  gate earned its keep before it was merged.
- Plus: Bar E now requires the **complete, ordered** turn set (it had proved
  correctness only for whichever turns happened to render); the per-step replica
  attribution the spec asks for is **implemented**, not amended away; and the
  harness image's base + `uv` are **digest-pinned** (a clean git SHA does not
  establish source-to-image provenance).
- **Found while remediating:** the refusal assertions were stale-tolerant *existence*
  greps — "a line carrying this reason appears somewhere in a multi-minute window" —
  which any earlier step's marker satisfies. They became **count deltas**.

### Review-round hardening (2026-07-12, round 4)

Five more, and two the review did not find. The theme: **a failed read is not an
observation.**

- **A failed `kubectl logs` read was indistinguishable from a legitimate zero.** The
  count-delta above swallowed the read error and reported `0` — so a failed
  *pre*-read, followed by a **stale** marker left by an earlier step, produced a
  clean `0 → 1` delta and the assertion passed although the step's own request never
  refused, or never even reached the server. Reads now capture their exit status and
  **refuse to report a count they did not observe**.
- **The same shape sat on the proof's most load-bearing negative claim.** The probe
  ledger — the independent oracle for *"the denied tool did **not** execute"* — read
  `wc -l < ledger 2>/dev/null || echo 0`. An unreadable ledger reported **zero
  executions**, which is precisely the value four assertions treat as proof of the
  negative. It now distinguishes *absent* (an affirmative zero) from *unreadable*
  (a loud failure).
- **S4's clocks were bounded on the wrong side.** The keep-alive touch was stamped
  *after* its response, making the measured idle interval a **lower** bound — which
  constrains nothing — and leg 1 never checked its absolute-window claim against the
  wall clock at all. Both are now conservative bounds (touch stamped at *send*, probe
  at *completion*), so a slow run makes the leg fail **loud** rather than pass falsely.
- **S10 was a two-variable experiment.** It re-read the record's TTL, mutated the
  record client-side, then wrote it back with `PSETEX <that TTL>` — pushing the
  deadline out by the elapsed interval. Measured on real Redis: a 5s key came back
  with **4.8s** to run where a preserved deadline would show ~3.8s. The rewrite is now
  one atomic server-side `SET … KEEPTTL`, so the schema version really is the only
  thing that changes.
- **"Every upstream input is digest-pinned" was false.** The BuildKit *frontend* — the
  program that executes the Dockerfile — rode a mutable tag, `apk add` resolved
  whatever the Alpine repo served, and CI actions rode mutable tags. Rather than
  narrow the claim, the claim was **made true**: the frontend is digest-pinned, the
  `apk` layer is gone (the pinned base already ships `ca-certificates`; `binutils`
  only powered an optional strip, whose removal costs a disclosed 15.3MB), and every
  CI action is pinned to a commit SHA.
- **Found while remediating — and live-run-fatal.** The JSON reader printed Python's
  `True`/`False` while eighteen call sites compare the lowercase JSON spelling.
  Seventeen would have failed loudly on a healthy BFF. The eighteenth is worse: S7's
  outage check reads `[ "$A_OUTAGE_OK" != "true" ]`, and `"True" != "true"` is **true** —
  so the assertion that the BFF must **not** fall back to memory with its session store
  destroyed could never have fired, *even if it did*. It had never fired because the
  proof had not yet been run end to end at that review checkpoint.
- **Found while verifying.** That same assertion was the runner's only **fail-open**
  boolean: `!= "true"` passes on anything that is not that exact string, including an
  unreadable outcome and a `"false"` *manufactured* out of a read failure by an
  `|| echo`. It now demands an **observed** `false`; every other outcome fails loud.

### Review-round hardening (2026-07-12, round 5)

Four more, and one found while remediating. Round 4 closed *"a failed read is not an
observation"* **inside the readers**. Round 5 found the same shape one level **up**, in the
things that *feed* them — and in every case the fabricated value was the **safe-looking**
one, so the bug was invisible on a green run and would have surfaced only as a false PASS.

- **S7 awarded "the BFF refused a fresh login" for *any* driver failure.** The capture
  helper synthesised `{"ok": false, "login_failed": true}` for **every** non-zero driver
  exit and every empty result file. So a Chromium crash, a selector typo, a `uv`
  dependency-resolution failure, an OOM, or a password missing from the credentials file
  each **manufactured the exact evidence** that the BFF failed closed. Round 4's fix
  (demand an *observed* `false`) closed the fabrication inside the JSON reader and left
  this one untouched — `ok: false` still conflated *"the BFF refused"* with *"the proof
  harness broke"*. Both halves are now fixed. A **direct, driver-free** cookie-less
  `GET /login` must return **exactly 503** while the store is destroyed, with curl's own
  exit status checked so that `000` — *"the request never happened"* — can never read as a
  refusal. And the browser leg carries a **discriminated outcome** (`authenticated` /
  `refused`, with the HTTP status the driver actually observed on the `/login` navigation /
  `driver_error`), where `driver_error` **fails the bar loudly**. A broken harness is a
  broken proof, never a passing one.
- **The disabled-grant proof passed without ever reaching Keycloak.** The two legs were the
  runner's only **unguarded negative** assertions: `[ "$CODE" != "200" ]`. That is true for
  `404` (a typo'd endpoint), for `500` (Keycloak itself broke), and — worst — for curl's
  `000`, which is what `%{http_code}` prints when the connection *never happened*. **A
  total failure to contact Keycloak "proved" the grants were disabled.** The response body
  was discarded (`-o /dev/null`), so the OAuth error contract could not even be inspected.
  And even a *legitimate* `400` did not carry the claim: a password grant that is
  **enabled** but handed a **wrong password** returns `400` too. Both legs now demand an
  **observed** OAuth refusal that **names the grant type as the reason** — RFC 6749 §5.2's
  `unauthorized_client`, *"the authenticated client is not authorized to use this
  authorization grant type"* — sent with a **valid** client secret, with curl's exit status
  checked.
- **S10's "same bytes" claim was false.** The leg is billed as a controlled single-variable
  experiment: same key, same bytes, same deadline, only the schema version changes. But the
  record was round-tripped through Python's JSON encoder with **compact** separators while
  the harness stores it with the **default** ones — so *every separator byte in the record
  changed*. The conclusion still held; **the claim did not**. A hidden second variable sat
  in it, too: the day the record grows a field whose JSON round trip is not byte-faithful,
  "only the version changed" silently becomes false in a way that *does* matter. The record
  is no longer re-serialised at all. The version value's byte span is located, required to
  be **unique** (an ambiguous record is refused, never guessed at), replaced, and then
  **verified** — it parses, the version is 999, every other key and value is identical *in
  order*, and the bytes outside the span are byte-for-byte unchanged. The copy being mutated
  is itself proven byte-identical to what Redis holds, by comparing Redis's own digest of
  its stored bytes.
- **Bar F's `|safe` gate was textual, and swallowed its own failure.** The strongest claim
  in Bar F — no XSS escape hatch in the shipped templates — rested on
  `grep -rl '|safe' … || true`. Every one of `{{ x| safe }}`, `{{ x | safe }}`,
  `{% filter safe %}` and `{% autoescape false %}` evades that grep, and the `|| true` meant
  a grep that **could not run at all** yielded the empty string and **passed**. It is now a
  **semantic** gate: every shipped template is parsed with the running image's own Jinja2
  and its AST walked, so it reasons about *nodes* rather than spelling — the `safe` filter
  in any position or spacing, the filter-block form, and any `{% autoescape %}` node (banned
  outright, even `true`, because permitting the node lets a later edit flip it to `false`).
  An **unparseable** template is an offender, not a skip; and **finding zero templates is a
  hard failure**, because a scan that observed nothing is not a clean bundle. The two sibling
  Bar F scans carried the identical `|| true` swallow and were fixed with it.
- **Found while remediating — and live-run-fatal.** `local role="$1"
  user="${IDENTITY_USER[$role]:-}"` **does not work**. Bash word-expands *every* argument of
  the `local` builtin *before* it assigns any of them, so the `$role` inside the second
  argument is the outer, **unset** one. Under this script's `set -u` that is a hard
  `role: unbound variable` abort — reproduced on bash 3.2.57, 4.4 **and** 5.2. Bar A's very
  first action is `drive_login amir`, so **the entire proof died on its first login, on every
  bash version.** It had never fired because the proof had not yet been run end to end at that review checkpoint; it
  surfaced only because the round-5 regressions execute the runner's *real* function text
  rather than a re-typed copy of it.

Every fix is pinned by a regression that **executes the runner's own production text**, and
every pin was verified by **reverting its fix and confirming the test fails** — 15 of 15.
Two of the new pins were themselves caught vacuous that way and rewritten: one matched the
*text* of a guard that an `if False:` would have left sitting in place (it is now an AST
walk), and two were being satisfied by a neighbouring assertion rather than the one they
claimed to pin (they are now isolated).

**Pre-live boundary at that review checkpoint.** These were structural and
behavioural pins over the proof *scripts*, not the live run. That distinction
remains important historically: the subsequent attempt sequence found live-only
defects that reading and unit gates could not expose. Run 20 later executed the
whole stack and Bars A–F end to end; its PASS evidence and the complete attempt
ledger are recorded in `docs/VALIDATION-RESULTS.md`.

## Reproduce

Once the prerequisites are met:

```
COGNIC_RUN_PROOF_M85C=1 \
COGNIC_PROOF_M85C_TIER1_API_KEY=<operator key> \
  ./infra/proof-m85c/run-proof-m85c.sh
```

(The probe's two trust digests are **not** environment variables — they are
maintainer-committed literals in `stage-packs.sh`; see prerequisite 2.)

On all-pass it prints `PROOF M8.5-C (BARS A-G) PASS` and exits 0; on any bar
failure it captures diagnostics to `docs/VALIDATION-RESULTS.md` and exits
non-zero — the proof is never redefined downward.

## What carries forward from proof-m8/m85 (byte-for-byte)

The kernel + agent bring-up is the proven M8/M8.5 deployment verbatim: the same
seven released, signed packs (oracle tool operator-installed via the M4
lifecycle; the four instruction skills; the bank-analyst agent pack with its dual
trust root; the M5 hook pack the oracle manifest requires), the same
seven-signer trust-root staging, the same in-cluster Oracle XE + RS256/JWKS AS +
LiteLLM cloud tier, the same seed matrix, and the conversation substrate the
chat screen drives. M8.5-C adds only the identity/TLS/approvals surface above —
`protocol/mcp_authz.py` stays byte-identical to `main`.
