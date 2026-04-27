"""Cognic AgentOS — bank-grade governance kernel + runtime + protocol layer.

Layer classification: **package root**.

This package is the OS-only platform per ADR-001. Tools, skills, agents, UI,
and bank overlays are external plugin packs / artefacts and never imported here.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cognic-agentos")
except PackageNotFoundError:  # editable install before metadata is built
    __version__ = "0.0.0+local"

__all__ = ["__version__"]
