"""PROOF-ONLY package for the M6 governed-agent-skill deployed proof.

Vendored into the proof kernel image by ``Dockerfile.agentos-proof``
(``COPY proof_m6/ /app/proof_m6/``); the image CMD boots
``proof_m6.proof_app:create_proof_app``. NOT kernel product code. Unlike the
M4/M5 proof apps (which live under ``tests/integration/proof_m*``), this
package lives INSIDE ``infra/proof-m6/`` — it is already in the docker build
context, so the runner needs no copy step for it.
"""
