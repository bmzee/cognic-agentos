"""PROOF-ONLY package: the multi-actor AgentOS app factory for Proof M8
(the deployed six-bar governed-agent-loop proof, ADR-027).

Vendored into the proof kernel image by ``Dockerfile.agentos-proof``
(``COPY proof_m8/ /app/proof_m8/`` + ``PYTHONPATH=/app``) so uvicorn can boot
``proof_m8.proof_app:create_proof_app``. NOT kernel product code — see
:mod:`proof_m8.proof_app`'s header for why this factory is unacceptable in
production.
"""
