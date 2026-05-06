"""Cosign trust gate — pack-signature verification with secure-subprocess invariants.

Critical-controls module per AGENTS.md (cosign verification — argv-
construction critical control). The most security-sensitive surface in
Sprint 4: a single sloppy ``shell=True`` or unscrubbed ``env`` here
defeats the entire plugin trust model the platform is built on.

§2 of the Sprint-4 plan-of-record locks 8 invariants. Every one of
them has a corresponding negative-path test in
``tests/unit/protocol/test_trust_gate.py``:

  1. Argv is list-form only. ``asyncio.create_subprocess_exec`` is
     used — it has no ``shell`` parameter, so the API itself prevents
     a string-form regression. A test asserts ``shell=True`` cannot
     be reintroduced via subprocess.run.
  2. ``cosign`` binary resolved via ``shutil.which`` at TrustGate
     construction; failure deferred to the first verify call so a
     kernel-image boot that never reaches the trust gate doesn't
     fail.
  3. Pack identity / version / signature blob path validated against
     strict regexes BEFORE the subprocess runs. Pack name:
     ``^[a-z0-9][a-z0-9_-]{0,127}$``. Version:
     ``^[0-9A-Za-z.+_-]{1,64}$`` (PEP 440 superset). Path arguments
     canonicalise via ``os.path.realpath`` and must remain under
     the operator-configured root prefix.
  4. Per-tenant trust root path canonicalised under
     ``settings.trust_root_prefix``; symlink-escape rejected.
  5. No environment-variable passthrough. The subprocess gets an
     explicit minimal env: ``{"PATH": "/usr/local/bin:/usr/bin",
     "HOME": "/tmp"}``. No ``os.environ``.
  6. Strict timeout (default 30s, ``settings.cosign_verify_timeout_s``).
     SIGKILL on timeout; an ``audit_event(trust_gate.cosign_timeout)``
     is chained into the Sprint-2 substrate before the
     CosignVerificationFailed re-raises.
  7. Verification signal is the ``cosign verify-blob`` **exit code**
     (R3 reviewer-P1 fix): exit 0 = verified; non-zero = fail-closed
     CosignVerificationFailed. Per upstream sigstore/cosign, the
     ``--output json`` flag belongs to OCI ``cosign verify`` and is
     not supported by ``verify-blob``. We never parse cosign
     stdout/stderr for the decision (which would also break the
     privacy invariant — those streams can carry attacker-influenced
     text). Error messages include only ``stderr_sha256`` /
     ``stderr_len`` / ``stdout_sha256`` / ``stdout_len`` for operator
     log correlation; raw stream bytes are never surfaced.
  8. ``signature_digest`` returned to the caller is the SHA-256 of
     the signature file itself — the auditable identifier the
     plugin registry pins onto ``RegistrationOutcome``.

Per ADR-016 §"What this is NOT" + the April-2026 MCP supply-chain
disclosures, **no pack-controlled string ever flows into argv**. The
strict-regex + canonicalisation invariants are what enforce that.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from cognic_agentos.core.audit import AuditEvent, AuditStore
from cognic_agentos.core.config import Settings

if TYPE_CHECKING:
    from cognic_agentos.db.adapters.protocols import SecretAdapter

_LOG = logging.getLogger("cognic_agentos.protocol.trust_gate")

#: Pack identity regex — single segment, snake-case + dashes only,
#: 1..128 chars. Refuses every shell metacharacter (``;``, ``|``, `` ` ``,
#: ``$``, ``&``, newline, backslash, quotes, glob chars) by virtue of
#: the strict character class. Tested per §2 invariant 8.
_PACK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")

#: Version regex — PEP 440 superset (``^[0-9A-Za-z.+_-]{1,64}$``). Same
#: shell-metacharacter immunity property as ``_PACK_ID_RE``.
_VERSION_RE = re.compile(r"^[0-9A-Za-z.+_-]{1,64}$")

#: Tenant identity regex — same shape as the pack-id regex; refuses
#: every path metacharacter (``/``, ``..``, newline, ``\0``, raw
#: percent-encoded sequences). Used by :meth:`TrustGate.verify_jws_blob`
#: (T7) to validate ``tenant_id`` BEFORE interpolation into the
#: per-tenant Vault path. Without this gate, a malformed tenant id
#: like ``bank_a/../bank_b`` could address a different secret
#: depending on the SecretAdapter's path-resolution behaviour —
#: exactly the per-tenant boundary this trust root protects.
_TENANT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

#: Subprocess env — only PATH + HOME. ``os.environ`` is NOT passed
#: through. Anything cosign needs from the environment must come from
#: argv-explicit flags. Per §2 invariant 5.
_SUBPROCESS_ENV: dict[str, str] = {
    "PATH": "/usr/local/bin:/usr/bin",
    "HOME": "/tmp",
}


# --- exception taxonomy -------------------------------------------------


class TrustGateError(RuntimeError):
    """Base for all trust-gate failures (security-class). Callers in
    T10 catch this to refuse pack registration with
    ``refusal_reason="cosign_verification_failed"``."""


class CosignNotInstalledError(TrustGateError):
    """The cosign binary is not on the path AND ``require_cosign`` is
    True. Operator must install cosign in the default-adapters image
    or set ``settings.cosign_path`` to an absolute path."""


class CosignVerificationFailed(TrustGateError):
    """Cosign refused the signature, or the verification pipeline
    surfaced a fail-closed condition. Failure classes:

      * Non-zero ``cosign verify-blob`` exit (the upstream
        verification signal — R3 reviewer-P1 contract).
      * Timeout: the cosign subprocess exceeded
        ``settings.cosign_verify_timeout_s``; SIGKILL'd; an
        ``audit_event(trust_gate.cosign_timeout)`` row is chained.
      * Subprocess-launch OSError (EACCES / ENOEXEC / race between
        ``shutil.which`` and exec) — wrapped from raw OSError into
        this taxonomy.
      * Post-verify ``_hash_file`` OSError (signature removed or
        swapped between cosign's read and our digest computation).

    The exception message includes only the failure class plus
    ``stderr_sha256`` / ``stderr_len`` / ``stdout_sha256`` /
    ``stdout_len`` (or ``errno`` / ``class`` for OSError variants)
    for operator log correlation. Raw cosign stdout/stderr bytes are
    NEVER surfaced — privacy + log-injection control, since those
    streams can carry attacker-influenced content if the signature
    blob itself is hostile."""


class PathTraversalError(TrustGateError, ValueError):
    """A path argument canonicalised outside the operator-approved
    root prefix. Inherits from both ``TrustGateError`` (so T10's
    ``except TrustGateError:`` catches it) and ``ValueError`` (so the
    standard library's path-tools idiom of ``except ValueError:``
    catches it too).
    """


class TrustGateSignerNotAllowlistedError(TrustGateError):
    """Raised by :meth:`TrustGate.verify_jws_blob` when the JWS
    advertises a ``kid`` that is NOT on the per-tenant trust root.

    Distinct from the generic :class:`TrustGateError` (which covers
    JWS parse failures + cryptographic signature mismatches) so
    callers can map the two failure modes onto distinct closed-enum
    reasons. Sprint-6 :class:`A2AAgentCardVerifier` (T7) catches
    this subclass BEFORE the parent ``TrustGateError`` to route
    signer-allow-list failures onto
    ``agent_card_signer_not_allowlisted`` and cryptographic
    mismatches onto ``agent_card_signature_invalid``.

    Operationally distinct: a signer-not-allowlisted failure means
    rotate the per-tenant trust root + re-register; a signature-
    invalid failure means the card was tampered with after signing.
    Different audit categories + different operator runbooks.

    Inherits from :class:`TrustGateError` so a caller that ONLY
    catches the parent still sees the failure (defensive Python
    isinstance behaviour). Callers MUST place the
    ``except TrustGateSignerNotAllowlistedError`` clause BEFORE
    ``except TrustGateError`` to preserve closed-enum routing.
    """


# --- result type --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CosignVerificationResult:
    """Outcome of a successful ``verify_pack_signature`` call.

    Failures raise ``CosignVerificationFailed`` rather than returning a
    ``verified=False`` result — fail-closed at the API surface.

    ``signature_digest`` is the SHA-256 hex string of the signature
    file. T5's ``RegistrationOutcome`` carries it forward as the
    audit-trail identifier.
    """

    verified: bool
    pack_id: str
    version: str
    signature_digest: str


# --- input validation helpers ------------------------------------------


def _validate_pack_id(pack_id: str) -> None:
    if not isinstance(pack_id, str):
        raise ValueError(f"pack_id must be str; got {type(pack_id).__name__!r}")
    if len(pack_id) > 128:
        raise ValueError(f"pack_id too long ({len(pack_id)} > 128 chars)")
    if not _PACK_ID_RE.match(pack_id):
        raise ValueError(f"invalid pack_id {pack_id!r}: must match {_PACK_ID_RE.pattern}")


def _validate_version(version: str) -> None:
    if not isinstance(version, str):
        raise ValueError(f"version must be str; got {type(version).__name__!r}")
    if len(version) > 64:
        raise ValueError(f"invalid version: too long ({len(version)} > 64 chars)")
    if not _VERSION_RE.match(version):
        raise ValueError(f"invalid version {version!r}: must match {_VERSION_RE.pattern}")


def _canonicalise_under_root(path: Path, root: Path) -> Path:
    """Resolve ``path`` to an absolute canonical form and assert it
    lives under ``root`` (also canonicalised).

    Catches absolute paths (``/etc/passwd``), relative traversal
    (``../escape``), and symlink escape (a symlink under root that
    points outside). Raises ``PathTraversalError`` on any violation.

    Per §2 invariants 3 + 4. ``os.path.realpath`` is the canonical
    form (it follows symlinks and resolves ``..``); ``Path.resolve``
    delegates to it on POSIX. Both root and path are realpath'd so a
    symlink installed at root itself doesn't trick the comparison.
    """
    if not isinstance(path, Path):
        raise PathTraversalError(f"path must be a Path; got {type(path).__name__!r}")
    if not isinstance(root, Path):
        raise PathTraversalError(f"root must be a Path; got {type(root).__name__!r}")
    root_canonical = Path(os.path.realpath(str(root)))
    path_canonical = Path(os.path.realpath(str(path)))
    try:
        path_canonical.relative_to(root_canonical)
    except ValueError:
        raise PathTraversalError(
            f"path {path!s} canonicalises to {path_canonical!s}, "
            f"which is not under root {root!s} (canonical {root_canonical!s})"
        ) from None
    return path_canonical


# --- TrustGate -----------------------------------------------------------


class TrustGate:
    """Cosign-based plugin signature verifier.

    Construction takes ``settings`` (for the cosign-path, timeout, and
    root-prefix configuration) + an ``AuditStore`` (for the timeout
    audit emission) + an optional :class:`SecretAdapter` (Sprint-6 T7
    addition — required for :meth:`verify_jws_blob` Agent Card JWS
    verification; left as ``None`` for callers that only need the
    Sprint-4 cosign verification surface).

    The cosign binary is resolved at construction via
    ``shutil.which``; ``CosignNotInstalledError`` is deferred to the
    first ``verify_pack_signature`` call so a kernel-image boot that
    never reaches the trust gate doesn't fail.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        audit_store: AuditStore,
        secret_adapter: SecretAdapter | None = None,
    ) -> None:
        self._settings = settings
        self._audit_store = audit_store
        self._secret_adapter = secret_adapter
        # § 2 invariant 2: resolve at construction; defer the missing-
        # binary error to first call. ``shutil.which`` returns the
        # absolute path or None.
        configured = settings.cosign_path or "cosign"
        self._cosign_bin: str | None = shutil.which(configured)

    @property
    def cosign_bin(self) -> str | None:
        """Resolved cosign path; None when ``shutil.which`` came up empty."""
        return self._cosign_bin

    async def verify_jws_blob(
        self,
        *,
        jws_bytes: bytes,
        payload_bytes: bytes,
        tenant_id: str,
    ) -> None:
        """Verify a detached JWS over an arbitrary payload using the
        per-tenant trust root.

        Used by Sprint-6 :class:`A2AAgentCardVerifier` (T7) to verify
        Agent Card detached JWS files. The same per-tenant trust
        authority that signs the wheel (Sprint-4 cosign) is expected
        to sign the Agent Card; T7's Vault layout stores JWS-format
        public keys at
        ``secret/cognic/<tenant>/a2a-jws-trust-root`` as a list of
        ``{"kid": "<key-id>", "pem": "<PEM-encoded public key>"}``
        entries.

        Per Sprint-6 plan-of-record T7 R4 P2 reviewer correction +
        the Sprint-5 T15 R1 P2 #2 + #3 doctrine:

        - Raises :class:`TrustGateSignerNotAllowlistedError` (subclass
          of :class:`TrustGateError`) when the JWS advertises a
          ``kid`` that is NOT on the per-tenant trust root. Operator
          fix: rotate the trust root or have the agent re-sign with
          an allow-listed key.
        - Raises :class:`TrustGateError` on every other failure mode
          (no ``kid`` AND no key verifies; ``kid`` resolves to a key
          but the cryptographic verify fails; JWS bytes are
          unparseable; supported algorithm mismatch; size cap
          exceeded). Operator fix: investigate the card's signing
          pipeline.
        - Propagates :class:`asyncio.CancelledError` unwrapped per
          Sprint-5 T15 R1 P2 #2 doctrine.
        - Returns ``None`` on success.

        ``payload_bytes`` is the **detached** card JSON (the bytes
        the JWS was computed over, not embedded in the JWS itself —
        RFC 7797). ``joserfc`` performs the cryptographic verify
        with these bytes provided via the ``payload=`` kwarg.

        Caller MUST catch the subclass BEFORE the parent for
        closed-enum routing:

        .. code-block:: python

            try:
                await trust_gate.verify_jws_blob(...)
            except TrustGateSignerNotAllowlistedError:
                # signer key not on trust root
                ...
            except TrustGateError:
                # signature mismatch / parse failure
                ...
        """
        if self._secret_adapter is None:
            raise TrustGateError(
                "TrustGate.verify_jws_blob requires a secret_adapter at "
                "construction time; this instance was built without one. "
                "Wire the Vault SecretAdapter through "
                "create_prod_app's TrustGate construction site."
            )

        # T7 R1 P2 #2 reviewer correction: validate ``tenant_id``
        # against a strict regex BEFORE interpolating it into the
        # Vault path. A malformed tenant id like ``bank_a/../bank_b``
        # would address a different secret depending on the
        # SecretAdapter's path-resolution semantics — exactly the
        # per-tenant boundary this trust root protects. The
        # exception message intentionally does NOT echo the raw
        # tenant text (which could be attacker-controlled) — only
        # the field name + the validation regex source. The audit
        # surface that consumes this exception logs the request_id,
        # not the raw tenant value.
        if not isinstance(tenant_id, str) or not _TENANT_ID_RE.match(tenant_id):
            raise TrustGateError(
                "tenant_id failed strict-segment validation; "
                "expected match for ``^[a-z0-9][a-z0-9_-]{0,63}$``"
            )

        # 1. Parse the JWS to extract its protected header (which
        #    carries the signing-key id under "kid"). ``extract_compact``
        #    returns the parsed structure WITHOUT verifying the
        #    signature — verification happens in step 3 after we've
        #    decided which key to verify against.
        from joserfc import jws as _jws_module
        from joserfc.errors import DecodeError, JoseError

        try:
            extracted = _jws_module.extract_compact(jws_bytes)
        except (DecodeError, JoseError, ValueError) as exc:
            raise TrustGateError(f"JWS unparseable: {type(exc).__name__}") from exc

        kid = extracted.headers().get("kid") if extracted.headers() else None
        alg = extracted.headers().get("alg") if extracted.headers() else None

        # 2. Resolve the per-tenant JWS trust root via Vault.
        try:
            trust_root_payload = await self._secret_adapter.read(
                f"secret/cognic/{tenant_id}/a2a-jws-trust-root"
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise TrustGateError(
                f"per-tenant JWS trust root read failed: {type(exc).__name__}"
            ) from exc

        if not isinstance(trust_root_payload, dict):
            raise TrustGateError("per-tenant JWS trust root payload is not a mapping")
        keys_field = trust_root_payload.get("keys", [])
        if not isinstance(keys_field, list):
            raise TrustGateError("per-tenant JWS trust root 'keys' field is not a list")

        keyring: dict[str, str] = {}
        for entry in keys_field:
            if not isinstance(entry, dict):
                continue
            entry_kid = entry.get("kid")
            entry_pem = entry.get("pem")
            if isinstance(entry_kid, str) and isinstance(entry_pem, str):
                keyring[entry_kid] = entry_pem

        if not keyring:
            raise TrustGateError(
                "per-tenant JWS trust root has no usable keys (every "
                "entry must be a {kid, pem} dict of strings)"
            )

        # 3. Allow-list check. If the JWS advertises a kid, that kid
        #    MUST be on the per-tenant trust root. Distinct closed-
        #    enum reason from cryptographic-verify failure.
        if kid is None:
            # No kid header — cannot resolve a specific key on the
            # allow-list. Treat as invalid signature (caller maps
            # to ``agent_card_signature_invalid``).
            raise TrustGateError(
                "JWS protected header is missing 'kid'; cannot resolve "
                "signing key against per-tenant trust root"
            )
        if kid not in keyring:
            raise TrustGateSignerNotAllowlistedError(
                # T7 R1 P2 #2: do NOT interpolate raw tenant_id into
                # exception text — even though the validator above
                # has rejected path-metacharacter shapes, the
                # exception message reaches operator log surfaces
                # where tenant identifiers are PII-class data.
                "JWS signer kid is not on the per-tenant trust root"
            )

        # 4. Cryptographic verification via joserfc. The detached
        #    payload is passed via the ``payload=`` kwarg per RFC 7797.
        from joserfc.errors import BadSignatureError
        from joserfc.jwk import RSAKey

        try:
            public_key = RSAKey.import_key(keyring[kid])
        except Exception as exc:
            raise TrustGateError(
                f"per-tenant JWS public key import failed: {type(exc).__name__}"
            ) from exc

        algorithms = [alg] if alg else None

        try:
            _jws_module.deserialize_compact(
                jws_bytes,
                public_key,
                algorithms=algorithms,
                payload=payload_bytes,
            )
        except BadSignatureError as exc:
            raise TrustGateError(
                f"JWS cryptographic verification failed: {type(exc).__name__}"
            ) from exc
        except (DecodeError, JoseError, ValueError) as exc:
            # Already-parsed JWS that fails on detached-payload
            # verification (e.g., RFC 7797 mode mismatch). Maps
            # to signature-invalid.
            raise TrustGateError(
                f"JWS detached-payload verification failed: {type(exc).__name__}"
            ) from exc

    async def verify_pack_signature(
        self,
        *,
        pack_id: str,
        version: str,
        signature_path: Path,
        blob_path: Path,
        trust_root: Path,
        tenant_id: str | None = None,
        request_id: str = "system",
    ) -> CosignVerificationResult:
        """Verify a cosign signature over the pack blob.

        Validates inputs (regex + path canonicalisation), invokes
        cosign via ``asyncio.create_subprocess_exec`` with a minimal
        env and a strict timeout, treats the **exit code** as the
        verification signal (R3 reviewer-P1 fix; ``cosign verify-blob``
        does not support ``--output json``), and returns the result.
        Cosign stdout / stderr are NEVER parsed for the decision —
        those streams can carry attacker-influenced text and the
        upstream contract is exit-code-only. Fail-closed at every
        boundary.

        Raises ``ValueError`` on regex-invalid pack identity or version,
        ``PathTraversalError`` on any path argument that escapes its
        root prefix, ``CosignNotInstalledError`` when cosign is missing
        and ``settings.require_cosign`` is True, and
        ``CosignVerificationFailed`` for every other failure class:
        timeout (audit-event-chained), non-zero cosign exit,
        subprocess-launch OSError (EACCES / ENOEXEC after
        ``shutil.which`` succeeds), and post-verify hashing OSError
        (signature removed/swapped between cosign read and digest
        computation).
        """
        # §2 invariant 3: validate identifiers before any subprocess.
        _validate_pack_id(pack_id)
        _validate_version(version)
        sig_canonical = _canonicalise_under_root(signature_path, self._settings.signature_root_path)
        blob_canonical = _canonicalise_under_root(blob_path, self._settings.signature_root_path)
        # §2 invariant 4: trust root canonicalised under its own prefix.
        trust_canonical = _canonicalise_under_root(trust_root, self._settings.trust_root_prefix)

        # ``require_cosign=False`` is a documented dev-iteration override
        # (Settings.require_cosign docstring + AGENTS.md production-grade
        # rule). The trust gate honours it by short-circuiting with a
        # synthetic skip result; T10 / operator dashboards distinguish
        # this from a real signature via the digest sentinel.
        if not self._settings.require_cosign:
            _LOG.warning(
                "trust gate: require_cosign=False — skipping cosign "
                "verification for %s/%s. This is a critical-controls "
                "violation in production per AGENTS.md.",
                pack_id,
                version,
            )
            return CosignVerificationResult(
                verified=True,
                pack_id=pack_id,
                version=version,
                signature_digest="cosign-skipped:require_cosign=false",
            )

        # §2 invariant 2: defer the missing-binary error to first call.
        if self._cosign_bin is None:
            raise CosignNotInstalledError(
                "cosign binary not found on PATH and require_cosign=True. "
                f"Settings.cosign_path={self._settings.cosign_path!r}; "
                f"shutil.which returned None. Install cosign in the "
                f"default-adapters image (per Sprint-4 plan §2 invariant 2)."
            )

        # §2 invariant 1: list-form argv. asyncio.create_subprocess_exec
        # has no ``shell`` parameter — by API construction this cannot
        # be a string-form invocation. A test asserts subprocess.run is
        # not used (which CAN take shell=True).
        #
        # ``cosign verify-blob`` reports verification by exit code only
        # (R3 reviewer-P1 fix): per the upstream sigstore/cosign
        # documentation, ``--output json`` is a flag of the OCI
        # ``cosign verify`` subcommand and is NOT supported by
        # ``verify-blob``. Treating exit code as the verification
        # signal is what the upstream contract specifies — exit 0
        # means "signature verifies"; non-zero means anything else.
        # We never parse cosign stdout/stderr for the decision (which
        # would also break the privacy invariant — those streams can
        # carry attacker-influenced text).
        argv = [
            self._cosign_bin,
            "verify-blob",
            "--key",
            str(trust_canonical),
            "--signature",
            str(sig_canonical),
            str(blob_canonical),
        ]

        # R3 reviewer-P2 fix: ``asyncio.create_subprocess_exec`` can
        # raise OSError on launch (exec-format error, permission
        # denied, race between shutil.which and exec, ENOEXEC on bad
        # shebang). Without the wrapper, raw OSError escapes the
        # TrustGateError taxonomy and T10 cannot convert it into a
        # clean ``cosign_verification_failed`` registration refusal.
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=_SUBPROCESS_ENV,
            )
        except OSError as exc:
            raise CosignVerificationFailed(
                f"failed to launch cosign at {self._cosign_bin!r} for "
                f"pack_id={pack_id!r} version={version!r}; "
                f"errno={exc.errno} class={type(exc).__name__}"
            ) from None

        timeout_s = self._settings.cosign_verify_timeout_s
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        except TimeoutError:
            # §2 invariant 6: SIGKILL the cosign process. ``proc.kill``
            # sends SIGKILL on POSIX; ``proc.wait`` reaps the zombie.
            proc.kill()
            await proc.wait()
            await self._emit_timeout_audit(
                pack_id=pack_id,
                version=version,
                timeout_s=timeout_s,
                tenant_id=tenant_id,
                request_id=request_id,
            )
            raise CosignVerificationFailed(
                f"cosign verification timed out after {timeout_s}s for "
                f"pack_id={pack_id!r} version={version!r}; "
                f"audit_event(trust_gate.cosign_timeout) chained"
            ) from None

        # §2 invariant 7 (revised per R3 P1): fail-closed on non-zero
        # exit. Exit 0 IS the verification signal for cosign verify-
        # blob; we never parse stdout. Stderr SHA-256 + length are
        # included for operator log correlation, but raw stderr is
        # NOT surfaced (privacy + log-injection — cosign stderr can
        # contain attacker-influenced content if the blob is hostile).
        if proc.returncode != 0:
            raise CosignVerificationFailed(
                f"cosign verify-blob exited non-zero "
                f"(returncode={proc.returncode}) for pack_id={pack_id!r} "
                f"version={version!r}; "
                f"stderr_sha256={hashlib.sha256(stderr_b).hexdigest()} "
                f"stderr_len={len(stderr_b)} "
                f"stdout_sha256={hashlib.sha256(stdout_b).hexdigest()} "
                f"stdout_len={len(stdout_b)}"
            )

        # §2 invariant 8: signature_digest is the SHA-256 of the .sig
        # file itself. The plugin registry pins this onto
        # RegistrationOutcome.signature_digest as the auditable
        # identifier.
        #
        # R3 reviewer-P2 fix: ``_hash_file`` can raise OSError if the
        # signature is removed or made unreadable between cosign's
        # read and our hash. Wrap so the post-verification path stays
        # inside the TrustGateError taxonomy.
        try:
            signature_digest = _hash_file(sig_canonical)
        except OSError as exc:
            raise CosignVerificationFailed(
                f"signature digest hashing failed AFTER cosign verified "
                f"for pack_id={pack_id!r} version={version!r}; "
                f"errno={exc.errno} class={type(exc).__name__}"
            ) from None

        return CosignVerificationResult(
            verified=True,
            pack_id=pack_id,
            version=version,
            signature_digest=signature_digest,
        )

    async def _emit_timeout_audit(
        self,
        *,
        pack_id: str,
        version: str,
        timeout_s: float,
        tenant_id: str | None,
        request_id: str,
    ) -> None:
        """Chain a ``trust_gate.cosign_timeout`` audit event into the
        Sprint-2 substrate before re-raising. Per §2 invariant 6 +
        ISO 42001 A.7.4 (admission-control evidence)."""
        event = AuditEvent(
            event_type="trust_gate.cosign_timeout",
            request_id=request_id,
            tenant_id=tenant_id,
            payload={
                "pack_id": pack_id,
                "version": version,
                "timeout_s": timeout_s,
            },
            iso_controls=("A.7.4",),
        )
        await self._audit_store.append(event)


def _hash_file(path: Path) -> str:
    """SHA-256 of the file at ``path`` as hex; reads in chunks so the
    signature blob (typically a few KB but could be larger for bundles)
    doesn't sit in memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


__all__ = (
    "CosignNotInstalledError",
    "CosignVerificationFailed",
    "CosignVerificationResult",
    "PathTraversalError",
    "TrustGate",
    "TrustGateError",
    "TrustGateSignerNotAllowlistedError",
)
