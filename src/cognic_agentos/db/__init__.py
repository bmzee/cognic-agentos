"""Persistence + adapter sub-package.

Per ADR-009, AgentOS reaches every external system through a typed
``Protocol`` interface declared in ``cognic_agentos.db.adapters.protocols``.
Bundled adapters live alongside the protocols; alternative adapters
install as plugin packs (per ADR-002).
"""
