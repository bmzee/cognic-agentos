#!/usr/bin/env python3
"""Preflight: assert the EXACT claim contract the pinned Keycloak realm emits.

Design spec §4 requires the authorized-party (and every other) claim to be
"validated against the exact claim contract the pinned Keycloak configuration
emits (established at implementation time from the pinned realm export, then
pinned in tests — **not assumed from folklore**)."

``gen_realm.py`` CONFIGURES that contract. This script PROVES it, against a
REAL token minted by the REAL realm, BEFORE any bar spends a cent or a minute.
It exists because the three properties the whole identity story rests on are
each one vendor-default away from silently breaking:

  * ``typ: at+jwt`` — Keycloak 26.2's ``access.token.header.type.rfc9068`` is
    OFF by default. If the attribute were dropped, every token would carry
    ``typ: JWT`` and the binder would refuse 100% of requests.
  * ``aud == {cognic-agentos}`` EXACTLY — a stock Keycloak token also carries
    ``account`` (via the audience-resolve mapper in the built-in ``roles``
    scope). If any of the realm's audience levers regressed, the binder would
    refuse with ``audience_not_exact`` and every bar would fail identically,
    with no signal pointing at the realm.
  * ``cognic_scopes`` as a JSON **array** — a non-multivalued mapper emits a
    bare string, which the binder refuses as ``scopes_claim_malformed``.

Without this preflight all three failure modes look the same from the outside:
"everything 403s". With it, the runner stops in the first minute and prints the
OBSERVED header and claims next to the expected ones.

This does NOT verify the signature — that is the binder's job, exercised live by
every subsequent bar. This asserts the SHAPE and the VALUES of what the realm
actually mints. Tokens themselves are never printed; claims are (they are the
diagnosis, and they carry no secret).

Usage:
    assert_claim_contract.py <tokens-json> <issuer> <username> <tenant> <scope,scope,...>
"""

from __future__ import annotations

import base64
import binascii
import json
import sys
from typing import Any

EXPECTED_ALG = "RS256"
EXPECTED_TYP = "at+jwt"
EXPECTED_AUDIENCE = {"cognic-agentos"}
EXPECTED_AZP = "cognic-harness"


def _decode_segment(segment: str) -> dict[str, Any]:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode())
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"segment is not base64url: {exc}") from exc
    doc = json.loads(raw)
    if not isinstance(doc, dict):
        raise ValueError("segment did not decode to a JSON object")
    return doc


def _split(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"token has {len(parts)} segments (expected 3)")
    return _decode_segment(parts[0]), _decode_segment(parts[1])


def check(
    *, tokens: dict[str, Any], issuer: str, username: str, tenant: str, scopes: set[str]
) -> list[str]:
    failures: list[str] = []
    header, claims = _split(tokens["access_token"])

    # --- the access token: header ------------------------------------------------
    if header.get("alg") != EXPECTED_ALG:
        failures.append(f"header.alg={header.get('alg')!r} (expected {EXPECTED_ALG!r})")
    if header.get("typ") != EXPECTED_TYP:
        failures.append(
            f"header.typ={header.get('typ')!r} (expected {EXPECTED_TYP!r}) — the realm's "
            "access.token.header.type.rfc9068 client attribute is OFF or was dropped; "
            "Keycloak 26.2 defaults it to OFF"
        )
    if not isinstance(header.get("kid"), str) or not header.get("kid"):
        failures.append("header.kid is absent or not a string")

    # --- the access token: claims ------------------------------------------------
    if claims.get("iss") != issuer:
        failures.append(f"iss={claims.get('iss')!r} (expected {issuer!r})")

    aud = claims.get("aud")
    audiences = {aud} if isinstance(aud, str) else set(aud) if isinstance(aud, list) else None
    if audiences is None:
        failures.append(f"aud={aud!r} is neither a string nor an array")
    elif audiences != EXPECTED_AUDIENCE:
        extra = sorted(audiences - EXPECTED_AUDIENCE)
        failures.append(
            f"aud={sorted(audiences)!r} (expected EXACTLY {sorted(EXPECTED_AUDIENCE)!r})"
            + (
                f" — the extra audience {extra!r} means an audience-resolve mapper ran: the "
                "'roles' client scope is back on the client, or a user regained client roles"
                if extra
                else ""
            )
        )

    if claims.get("azp") != EXPECTED_AZP:
        failures.append(f"azp={claims.get('azp')!r} (expected {EXPECTED_AZP!r})")
    if not isinstance(claims.get("sub"), str) or not claims.get("sub"):
        failures.append("sub is absent or empty (the 'basic' client scope supplies it)")
    if claims.get("preferred_username") != username:
        failures.append(
            f"preferred_username={claims.get('preferred_username')!r} (expected {username!r}) — "
            "a login-identity sanity check that the token belongs to the expected user; the "
            "reference binder keys Actor.subject on the STABLE issuer-qualified sub, NOT on this "
            "mutable claim (the kernel seed is rendered from the same sub)"
        )
    if claims.get("tenant_id") != tenant:
        failures.append(f"tenant_id={claims.get('tenant_id')!r} (expected {tenant!r})")

    raw_scopes = claims.get("cognic_scopes")
    if not isinstance(raw_scopes, list) or not all(isinstance(s, str) for s in raw_scopes):
        failures.append(
            f"cognic_scopes={raw_scopes!r} is not a JSON array of strings — the mapper's "
            "multivalued flag is off, so Keycloak emitted a bare string"
        )
    elif set(raw_scopes) != scopes:
        failures.append(f"cognic_scopes={sorted(raw_scopes)!r} (expected {sorted(scopes)!r})")

    for time_claim in ("exp", "iat"):
        value = claims.get(time_claim)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            failures.append(f"{time_claim}={value!r} is not a number")

    # --- the ID token must be STRUCTURALLY distinct -------------------------------
    # Bar B substitutes the REAL id_token from this same login for the access token
    # and requires a refusal. That test is only meaningful if the two tokens really
    # do differ on the two checks the binder rejects with — assert it here.
    id_header, id_claims = _split(tokens["id_token"])
    if id_header.get("typ") == EXPECTED_TYP:
        failures.append(
            "the ID token's header typ is also at+jwt — the access/ID structural "
            "distinction the binder relies on does not hold in this realm"
        )
    id_aud = id_claims.get("aud")
    id_audiences = (
        {id_aud} if isinstance(id_aud, str) else set(id_aud) if isinstance(id_aud, list) else set()
    )
    if id_audiences == EXPECTED_AUDIENCE:
        failures.append(
            f"the ID token's aud is also {sorted(EXPECTED_AUDIENCE)!r} — an ID token must be "
            "audienced to the harness client, not to AgentOS"
        )

    if not failures:
        print(
            f"  claim contract OK for {username}: typ=at+jwt alg=RS256 "
            f"aud={sorted(audiences or [])} azp={EXPECTED_AZP} tenant={tenant} "
            f"scopes={len(scopes)} | id_token structurally distinct "
            f"(typ={id_header.get('typ')!r}, aud={sorted(id_audiences)})"
        )
    return failures


def main(argv: list[str]) -> int:
    if len(argv) != 6:
        print(
            "usage: assert_claim_contract.py <tokens-json> <issuer> <username> "
            "<tenant> <csv-scopes>",
            file=sys.stderr,
        )
        return 2
    tokens_path, issuer, username, tenant, csv_scopes = argv[1:6]
    with open(tokens_path, encoding="utf-8") as fh:
        tokens = json.load(fh)
    scopes = {s for s in csv_scopes.split(",") if s}

    try:
        failures = check(
            tokens=tokens, issuer=issuer, username=username, tenant=tenant, scopes=scopes
        )
    except (ValueError, KeyError) as exc:
        print(f"FAIL: the minted token is not a well-formed JWS: {exc}", file=sys.stderr)
        return 1

    if failures:
        header, claims = _split(tokens["access_token"])
        print(
            f"FAIL: the realm's emitted claim contract does not match the pinned one "
            f"for {username!r}:",
            file=sys.stderr,
        )
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        # The observed header + claims ARE the diagnosis and carry no secret. The
        # token itself is never printed.
        print(f"  observed header: {json.dumps(header, sort_keys=True)}", file=sys.stderr)
        print(f"  observed claims: {json.dumps(claims, sort_keys=True)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
