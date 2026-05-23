"""Cognic AgentOS Model Registry primitive — ADR-013 (Sprint 9.5).

Public-API surface: every name in :data:`__all__` is re-exported from
its source module (``registry`` / ``storage`` / ``trust``) and stays
identity-equal to the source definition. The re-export contract is
pinned by ``tests/unit/models/test_models_package.py``.
"""

from cognic_agentos.models.registry import (
    MODEL_LIFECYCLE_ISO_CONTROLS,
    ModelKind,
    ModelLifecycleRefusalReason,
    ModelLifecycleRefused,
    ModelLifecycleState,
    ModelTransition,
    validate_transition,
)
from cognic_agentos.models.storage import (
    ModelNotFound,
    ModelRecord,
    ModelRecordStore,
)
from cognic_agentos.models.trust import (
    ModelSignatureVerificationError,
    ModelTrustGate,
    sigstore_bundle_digest,
)

__all__ = [
    "MODEL_LIFECYCLE_ISO_CONTROLS",
    "ModelKind",
    "ModelLifecycleRefusalReason",
    "ModelLifecycleRefused",
    "ModelLifecycleState",
    "ModelNotFound",
    "ModelRecord",
    "ModelRecordStore",
    "ModelSignatureVerificationError",
    "ModelTransition",
    "ModelTrustGate",
    "sigstore_bundle_digest",
    "validate_transition",
]
