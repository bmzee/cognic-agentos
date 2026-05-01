"""Sprint 4 T13 — Dockerfile binary-pin regression test.

Pins the cosign + OPA versions + SHA-256 sums baked into the
``default-adapters-builder`` stage at ``infra/agentos/Dockerfile``.
A drift here is a supply-chain event (the trust gate's verifier
binary or the policy engine's enforcement binary changed without
review), so it gets caught at unit-test time rather than at
CI image-build time.

Why pin in unit tests rather than just trust the SHA-256 check in
the Dockerfile? The Dockerfile's ``sha256sum -c`` only fires during
``docker build``. CI runs unit tests on every push but only builds
the docker image on selected lanes; this test makes the pin visible
to every push.

If the version OR sha256 needs to change (security CVE bump, OPA
feature dependency), update both this test AND the Dockerfile in
the same commit.
"""

from __future__ import annotations

import re
from pathlib import Path

_DOCKERFILE = Path(__file__).resolve().parents[3] / "infra" / "agentos" / "Dockerfile"

#: Pinned at T13 commit time; sources documented in the T13 commit
#: message + the Sprint-4 plan §T13. Both are statically-linked Go
#: binaries published to GitHub releases (cosign) / openpolicyagent.org
#: (OPA).
EXPECTED_COSIGN_VERSION = "3.0.6"
EXPECTED_COSIGN_SHA256 = "c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74"
EXPECTED_OPA_VERSION = "1.16.1"
EXPECTED_OPA_SHA256 = "dc00b1c32c52f1557f7f127940bc3f1de6c507fdfbe0446f19d3b19ca5786494"


def _arg_value(dockerfile_text: str, name: str) -> str:
    """Pull an `ARG NAME=value` out of the Dockerfile.

    Pinning expressed as a regex against the Dockerfile bytes — the
    test fails loudly if the ARG is missing OR if its default-value
    drifts. Returns the value verbatim (no quotes stripped); the
    Dockerfile uses bare values, not quoted ones, so this is fine.
    """
    pattern = re.compile(rf"^ARG\s+{re.escape(name)}=(\S+)\s*$", re.MULTILINE)
    match = pattern.search(dockerfile_text)
    assert match is not None, f"Dockerfile missing required ARG {name}"
    return match.group(1)


class TestDockerfileBinaryPins:
    def test_dockerfile_present(self) -> None:
        assert _DOCKERFILE.is_file(), f"Dockerfile missing at {_DOCKERFILE}"

    def test_cosign_version_pinned(self) -> None:
        text = _DOCKERFILE.read_text(encoding="utf-8")
        assert _arg_value(text, "COSIGN_VERSION") == EXPECTED_COSIGN_VERSION

    def test_cosign_sha256_pinned(self) -> None:
        text = _DOCKERFILE.read_text(encoding="utf-8")
        assert _arg_value(text, "COSIGN_SHA256") == EXPECTED_COSIGN_SHA256

    def test_opa_version_pinned(self) -> None:
        text = _DOCKERFILE.read_text(encoding="utf-8")
        assert _arg_value(text, "OPA_VERSION") == EXPECTED_OPA_VERSION

    def test_opa_sha256_pinned(self) -> None:
        text = _DOCKERFILE.read_text(encoding="utf-8")
        assert _arg_value(text, "OPA_SHA256") == EXPECTED_OPA_SHA256

    def test_binaries_copied_into_runtime(self) -> None:
        """The default-adapters runtime stage MUST COPY both binaries
        from the builder. Without these COPYs the binaries exist only
        in the builder layer and the runtime image's ``cosign`` /
        ``opa`` invocations would ENOENT at registration time."""
        text = _DOCKERFILE.read_text(encoding="utf-8")
        assert (
            "COPY --from=default-adapters-builder /usr/local/bin/cosign /usr/local/bin/cosign"
            in text
        )
        assert "COPY --from=default-adapters-builder /usr/local/bin/opa /usr/local/bin/opa" in text

    def test_kernel_runtime_does_not_carry_cosign_or_opa(self) -> None:
        """Trust gate + policy engine run in the default-adapters
        profile only. The kernel runtime stage MUST NOT carry the
        cosign / opa binaries — that protects the ≤120 MiB kernel
        budget AND signals that ``create_app`` (kernel factory) does
        NOT call into either subsystem."""
        text = _DOCKERFILE.read_text(encoding="utf-8")
        # Find the kernel runtime stage block; bounded by its
        # ``FROM ... AS runtime`` and the next ``# ----------`` divider.
        kernel_match = re.search(
            r"FROM python:\$\{PYTHON_VERSION\}-alpine AS runtime\n(.*?)\n# -+",
            text,
            re.DOTALL,
        )
        assert kernel_match is not None, "kernel runtime stage block not found"
        kernel_block = kernel_match.group(1)
        assert "cosign" not in kernel_block.lower()
        assert "/usr/local/bin/opa" not in kernel_block
