# infra/proof-m4/Dockerfile.as — PROOF-ONLY emulated-external OAuth AS (M4, RS256 mode)
FROM python:3.12-slim
RUN pip install --no-cache-dir "uvicorn[standard]>=0.35" "starlette>=0.40" "python-multipart>=0.0.9" "PyJWT[crypto]>=2.10,<3"
# PyJWT[crypto]: in rs256 mode (COGNIC_PROOF_AS_SIGNING_MODE=rs256) _local_as.py mints RS256-signed JWTs +
# serves JWKS so the released oracle pack's real PyJWKClient verifier can verify the token (M4). The
# python-multipart note from Proof 1b-2 still applies: the AS /token endpoint reads `await request.form()`
# (without it Bar 2 fails at the token POST). Vendor exactly the one AS fixture file. Build context =
# infra/proof-m4/ (NOT repo root): the runner copies _local_as.py into this context before `docker build`,
# because .dockerignore excludes tests/ from every repo-root context. Same vendor-into-context pattern as
# Dockerfile.agentos-proof. So the COPY source is context-relative, NOT repo-root-relative.
COPY _local_as.py /app/_local_as.py
WORKDIR /app
EXPOSE 9000
CMD ["python", "_local_as.py"]
