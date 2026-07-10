"""PROOF-ONLY package: the multi-actor AgentOS app factory for the Proof M8.5
SLICE (the deployed three-bar conversational-substrate proof, ADR-028).

Vendored into the proof kernel image by ``Dockerfile.agentos-proof``
(``COPY proof_m85/ /app/proof_m85/`` + ``PYTHONPATH=/app``) so uvicorn can boot
``proof_m85.proof_app:create_proof_app``. NOT kernel product code — see
:mod:`proof_m85.proof_app`'s header for why this factory is unacceptable in
production.
"""
