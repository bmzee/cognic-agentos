"""M8 (ADR-027) — data-scope entitlement package.

``EntitlementStore`` (CRITICAL CONTROLS) is the tenant-scoped pure-read
substrate for the M8 dispatch entitlement gate; ``DataScope`` is the resolved
governed-view allow-set + proxy DB identity the dispatcher stamps into the
signed query-context token.
"""

from cognic_agentos.core.entitlements.store import DataScope, EntitlementStore

__all__ = [
    "DataScope",
    "EntitlementStore",
]
