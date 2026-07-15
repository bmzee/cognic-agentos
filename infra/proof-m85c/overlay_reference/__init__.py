"""Reference OIDC ``ActorBinder`` overlay for the M8.5-C proof (design §4).

PROOF/REFERENCE code — a worked example of a bank overlay, injected via
``create_app(actor_binder=...)`` by ``proof_m85c/proof_app.py``. It is NOT a
shipped bank overlay and HP-2 (per-bank issuer/claim/assurance adaptation)
remains open; see the design spec's honesty boundaries.
"""

from overlay_reference.binder import (  # noqa: F401
    ReferenceBinderConfig,
    ReferenceOidcBinder,
    build_reference_binder,
    kernel_scope_allow_list,
)
