# M8.5-C live-proof Playwright driver

`driver.py` is the **browser driver** for the M8.5-C live proof (design spec
§5.2, Bars A–F). The proof runner (`../run-proof-m85c.sh` — **not** owned by this
directory) invokes it as subprocesses to DRIVE and OBSERVE the **Cognic Harness
v1 BFF** (`../../../../cognic-harness`) with a real Chromium browser.

## The one rule

**The driver DRIVES and OBSERVES; it never asserts a bar outcome.** Each
subcommand prints one JSON object to **stdout** and:

- exits **0** when the browser interaction *completed* — **including when the
  observed outcome is a governed refusal** (a rendered 403 / a governed-refusal
  answer is a *successful observation*, not a driver error);
- exits **non-zero** (3 = interaction failure, 4 = unexpected exception) with a
  JSON **diagnostic on stderr** when the interaction itself failed (page never
  loaded, an expected control was absent, TLS/browser launch failed, …). The
  diagnostic carries the URL, the missing selector, and a DOM excerpt so a
  minute-40 live-run failure is diagnosable without a re-run.

The **runner** reads the JSON keys and makes every pass/fail judgement. A driver
that decided bar outcomes would hide failures.

## Install / invoke

Python **3.12**. Requirements are pinned in `requirements.txt`:

```
playwright==1.49.1        # bundles Chromium build 1148
cryptography>=42,<45      # in-process SPKI pin computation
```

One-time (in the driver's environment): download the browser binary.

```bash
# the driver's env — via uv (the repo toolchain):
uv run --with-requirements requirements.txt playwright install chromium

# manual subcommand invocation:
uv run --with-requirements requirements.txt python driver.py <subcommand> \
    --base-url https://127.0.0.1:8444 \
    --ca        /run/proof/ca.pem \
    --state-file /run/proof/amir.state.json \
    --out       /run/proof/amir.login.json \
    [subcommand flags]
```

The live runner does **not** resolve that environment on every interaction. At
its `[1/11]` preflight, before any cluster work, it creates a private temporary
Python 3.12 venv, installs `requirements.txt` and its resolved dependencies into
that otherwise-empty environment, installs the matching Chromium, and then
invokes that venv's Python directly for every Bar A-F interaction. This keeps
package-index/DNS availability out of the live-bar path; a dependency or
browser-install failure refuses before the expensive kind bring-up. Cleanup
removes the venv unconditionally. The `selftest` subcommand and `import driver`
need **no** Playwright installed (the import is lazy, inside browser functions).

**Versions targeted:** Playwright **1.49.1** (matches the harness's own
`playwright>=1.49` pin), Chromium **build 1148** (the build Playwright 1.49.1
installs), cryptography **42–44**. Gates were run on macOS + CPython 3.12.8.

### Global flags (every subcommand)

| Flag | Meaning |
|---|---|
| `--base-url` | the BFF origin, e.g. `https://127.0.0.1:8444` |
| `--ca` | path to the per-run proof CA PEM (BFF + Keycloak are served under it) |
| `--state-file` | Playwright `storage_state` JSON; a session persists **across** invocations |
| `--out` | also write the JSON result here (in addition to stdout) |
| `--leaf` | path to an on-disk leaf cert whose SPKI to pin (repeatable; the runner passes the harness + Keycloak leaves it minted) |
| `--no-sandbox` | pass Chromium `--no-sandbox` (auto-on when running as root) |
| `--headed` | run the browser headed (debug) |
| `--timeout-ms` | default Playwright timeout (ms); default 30000, chat uses 180000 |

### Credentials ride the environment, never argv

A process's **argument vector is world-readable** (`ps`); its environment is not.
So every credential-bearing input is read from the environment:

| Env var | Used by | Why it is a credential |
|---|---|---|
| `HARNESS_USER_PASSWORD` | `login` | the Keycloak user password |
| `COGNIC_PROOF_COOKIE_VALUE` | `replay-cookie` (required), `replay-callback` (optional) | **possession of the `__Host-` cookie value IS the session** — a bearer credential exactly like a token |
| `COGNIC_PROOF_CALLBACK_URL` | `replay-callback` (required) | the URL carries a one-time authorization **`code`**, exchangeable for tokens |

The corresponding `--cookie-value` and `--callback-url` flags are **deleted** (not
merely optional): a flag that still accepts a credential invites a call site that
passes one. Passing either is now an argparse error, and the `selftest` pins that
**no** subcommand declares them.

Fail-closed semantics for `COGNIC_PROOF_COOKIE_VALUE`: **unset** = no cookie (legal
only for `replay-callback`, whose `cookie_injected:false` tells the runner it hit
the session gate); **set but empty** = always a hard failure (a shell variable that
expanded to nothing would inject a valueless cookie and make the replay probe report
`authenticated:false` for the wrong reason — a vacuous pass).

## TLS — SPKI pinning (the decision)

The proof CA is self-signed, so the naive move is `ignore_https_errors=True` —
which accepts **any** certificate. Instead the driver computes the base64
SHA-256 of the **SubjectPublicKeyInfo (SPKI)** of every cert in `--ca` and of
every **on-disk leaf** passed with `--leaf`, and passes them to Chromium as
`--ignore-certificate-errors-spki-list=<pin,pin,…>`. That pins **exactly** our
CA/leaf public keys and still rejects every other bad cert — strictly stronger
than the blanket bypass.

**The pins come only from material the runner already minted.** An earlier draft
also fetched the leaf actually *served* by the target origin and pinned that,
which is circular — it would have trusted whatever certificate an attacker
presented. That fetch and the `--tls-insecure` bypass are both **deleted**, and a
pin set that cannot be computed now fails closed (`spki_pins_unavailable`) rather
than degrading to "accept anything".

**Verified working.** Against a self-signed HTTPS server serving the exact
harness markup:
- bare Chromium (no flag) → `net::ERR_CERT_AUTHORITY_INVALID` (the cert is
  genuinely untrusted);
- the driver (SPKI pin on) → page loads and parses. So the pin is *load-bearing*.

The SPKI computation is proven **byte-identical** to the canonical
`openssl x509 -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256
-binary | openssl enc -base64` recipe (the driver falls back to that `openssl`
pipeline if `cryptography` is absent). If **neither** can compute a pin, the
driver **fails closed** with `spki_pins_unavailable` — there is no "accept
anything" path left to fall back to.

**Two caveats a live run must know:**

1. **The Node request stack is separate.** Playwright's `context.request` (used
   by `manipulated-post` and `csrf-probe`) is a Node HTTP client that does **not**
   honour the Chromium launch flag. The driver therefore also sets
   `NODE_EXTRA_CA_CERTS=<--ca>` so those POSTs trust **exactly** our CA — again,
   not a blanket bypass. (Verified end-to-end.)
2. **Other origins are pinned from their on-disk leaf.** Chromium navigation to a
   *different* same-CA host (Keycloak) is accepted if that host presents the
   shared CA in its chain (its CA-SPKI pin matches) **or** if its leaf was pinned
   with `--leaf`. Because the proof's servers present only their leaf (the CA is
   not in the presented chain), the runner passes **both** leaves it minted:
   `--leaf $PKI_TMP/harness.crt --leaf $PKI_TMP/keycloak.crt`. If a live run shows
   a Keycloak cert rejection during `login`, the fix is to pass that host's
   **minted leaf file** — never to weaken the pinning.

## Subcommands (JSON keys = the runner's contract)

Extra diagnostic keys beyond the contract are emitted and are non-breaking.

| Subcommand | Required flags | Contract JSON keys |
|---|---|---|
| `login` | `--username` (pw from `HARNESS_USER_PASSWORD`), optional `--landing-path /\|/approvals` | `ok, final_url, pre_auth_session_id, post_auth_session_id, cookie_names, served_by, callback_url` |
| `cookie-dump` | — | `cookies[] {name,value,secure,httpOnly,sameSite,path,domain}` |
| `replay-cookie` | *(no flags)* — cookie from `COGNIC_PROOF_COOKIE_VALUE` | `status, authenticated` |
| `replay-callback` | *(no flags)* — URL from `COGNIC_PROOF_CALLBACK_URL`, optional **pre-auth** cookie from `COGNIC_PROOF_COOKIE_VALUE` | `status, authenticated, cookie_injected` |
| `chat-turn` | `--message` (`--conversation-id`, `--agent-id`, `--create`) | `conversation_id, answer_text, turn_count, served_by` |
| `approvals-list` | — | `status, rows[]` (or `status:403, refusal_rendered:true, rows:[]`) |
| `approvals-paginate` | — | `pages, request_ids[]` |
| `approvals-act` | `--request-id`, `--action grant\|grant-second\|deny` (`--reason`) | `status, resulting_state, refusal_reason` |
| `evidence` | `--conversation-id`, `--seq` | `transcript_turns[] {sequence, agent_run_id, question_text, answer_text}`, `chain{turn_completed, started, terminal, dispatches[], dispatch_columns[], heading_seq}` |
| `manipulated-post` | `--path` (`--field k=v` …) | `status, body_reason` |
| `csrf-probe` | `--path` (`--csrf-mode garbage\|missing`) | `status` (+ `body_reason`) |
| `xss-probe` | `--conversation-id` (`--surface chat\|evidence\|both`) | `script_executed, rendered_text_contains_markup` |
| `logout` | — | `status, cookie_cleared` |
| `selftest` | — | validates the CLI surface + JSON shapes + pure helpers, **no browser** |

Notes on the observation semantics:

- **`login`** drives the real OIDC flow: `GET /login` → Keycloak login form
  (`#username` / `#password` / `#kc-login`) → `/auth/callback` → the
  authenticated BFF. The default landing screen is chat (`/`); approval-only
  identities use `--landing-path /approvals`, carried through the BFF's guarded
  `next` parameter, so authentication does not require `conversation.read`.
  `pre_auth_session_id` / `post_auth_session_id` are the
  `__Host-cognic_session` **cookie values** before and after login — the runner
  compares them for **S1** (login must rotate the session; the old cookie must be
  unusable via `replay-cookie`).
- **`replay-cookie`** starts a **fresh** context (does not load `--state-file`),
  injects the cookie value from `COGNIC_PROOF_COOKIE_VALUE`, and requests `/`.
  `authenticated` is false when the BFF redirects to `/signin`. Used for S1 (stale
  pre-auth cookie) and S3 (post-logout cookie).
- **`approvals-list`** renders the 403 **refusal view** (a non-observer) as a
  successful observation: `{status:403, refusal_rendered:true, rows:[]}`.
- **`approvals-act`** captures the *governed* status of the POST itself
  (303 success / 403 scope / 409 conflict / 400 validation), not the followed
  GET — so a four-eyes self-grant refusal surfaces as `status:403` +
  `refusal_reason:"…"`.
- **`chat-turn`** ensures an active conversation (targets `--conversation-id`, or
  creates one with `--agent-id`, default `bank-analyst`), submits a turn, and
  reads the rendered answer. A governed refusal is returned **as the answer
  text**, never treated as an error.
- **`manipulated-post`** proves an under-scoped user is refused by **AgentOS
  RBAC**, not merely hidden in the UI: it uses a **valid session + a real
  harvested CSRF token**, then POSTs directly (bypassing the UI button).
- **`xss-probe`** installs `window.__XSS_FIRED=false` at document start and a
  dialog listener; `script_executed` is true only if injected script actually
  ran (proven to correctly report `true` on a control page with a real
  `<script>`, and `false` on the harness's escaped output).

## `served_by` — a documented finding, and how the proof meets the contract anyway

**The Cognic Harness BFF exposes no replica/pod-identifying response header.**
It ships only the security headers in `web/security.py` (CSP, `no-store`, HSTS,
etc.) — no `X-Pod-Name`, no `X-Served-By`, nothing instance-specific. So:

- the **driver's** `served_by` JSON key is an **empty list `[]`** against the real
  harness — it observes response headers, and there is no per-pod header to observe;
- the generic `Server:` header (`uvicorn`) is **deliberately excluded** from the
  candidate set — it identifies the server *software*, identical on every
  replica, so surfacing it would fabricate a per-pod marker;
- if the deployment ever *does* inject a real per-pod header (downward-API
  `POD_NAME` → a small middleware), the driver captures it automatically (candidate
  set in `REPLICA_HEADER_CANDIDATES`) with no code change.

**Bar A's "value-free proof logs record which pod served each step" is met at the
RUNNER layer, not here.** The runner never *infers* the replica from a header or
from which pod kube-proxy happened to pick: every host port-forward targets a
**named pod** (`kubectl port-forward pod/<name>` bypasses the Service and goes to
exactly that pod), so the runner **chooses** the serving replica and then records it
— `step=<name> served_by=<pod>` — as a **fact it established**, not an inference. It
alternates the two replicas across the Bar A steps so both genuinely serve traffic.
See `bff_served_by()` / `bff_pf_pod()` in `../run-proof-m85c.sh`.

## Selector provenance

Every selector is derived from the harness source, not invented:

| Selector const | Source |
|---|---|
| `#username` / `#password` / `#kc-login` | Keycloak default theme; **confirmed** by the harness e2e `tests/e2e/test_authenticated_screens_e2e.py:37-39` |
| `__Host-cognic_session` | `auth/cookies.py:15` |
| `csrf_token` field / `X-CSRF-Token` | `auth/csrf.py:16-17`; enforced `web/dependencies.py:63-73` |
| `header.topbar .actor`, `form.logout-form` | `web/templates/base.html:18,21` |
| `form.new-convo`, `form.composer`, `ol.turns li.turn`, `.msg.agent pre`, `.refusal code` | `web/templates/chat.html:6,48,33-42,29` |
| `table.queue tbody tr`, `.refusal code`, `a.next-page` | `web/templates/approvals.html:8,11-16,34` |
| `form[action$="/grant"]` …, `dl.detail` State dt/dd | `web/templates/approval_detail.html:10-13,28-45` |
| evidence `h2` + `dl.detail`, dispatch `table.queue` | `web/templates/evidence_chain.html:9-53`, `evidence_transcript.html:9-17` |

## What was verified — and what was NOT

**Verified** (real Chromium + real self-signed TLS against a fixture serving the
exact harness markup):
`approvals-list`, `approvals-paginate`, `evidence`, `cookie-dump`,
`replay-cookie` (live + dead), `manipulated-post`, `csrf-probe` (garbage +
missing), `xss-probe` (inert + a positive control), `approvals-act` (grant +
four-eyes refusal), `logout`, `chat-turn`. Plus: SPKI pinning is load-bearing;
`import driver` and `driver.py selftest` (81/81 — incl. the credential-env channel
and the pins that **no** subcommand declares a credential flag) run with no
playwright; ruff + ruff format + mypy `--strict` all clean.

**NOT verified without a live cluster** (there is none available):
- the **full OIDC login redirect chain** through the real Keycloak (the login
  form selectors and the pre/post cookie capture are proven; the Keycloak
  round-trip itself is not) — the selectors match the harness's own e2e lane;
- **SPKI pinning against the real BFF + Keycloak** certificates (pinning is
  proven against a self-signed fixture). The live servers present only their
  **leaf** (the CA is not in the presented chain), which is why the runner pins
  both minted leaves via `--leaf` rather than relying on a CA-chain match — see
  the TLS caveats;
- true **cross-replica** behavior (there is one origin in the fixture) — the
  driver observes; pod attribution is runner-side;
- exact **timing** of a real LLM-backed `chat-turn` (the 180s budget is a
  generous default).
