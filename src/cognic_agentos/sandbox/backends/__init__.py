"""Sprint 8A backend implementations.

Wave-1: ``DockerSiblingSandboxBackend`` (Sprint 8A T10) +
``KubernetesPodSandboxBackend`` (Sprint 8B). Both conform to the
``SandboxBackend`` Protocol declared at
:mod:`cognic_agentos.sandbox.protocol`.

The DockerSibling backend's actual class lives in
:mod:`cognic_agentos.sandbox.backends.docker_sibling` and depends on
``aiodocker`` from the optional ``sandbox-docker`` extra. The
sandbox package's top-level re-export wraps the import in a
try/except ImportError so a deployment that does not need the Docker
backend (e.g. Kubernetes-only production) does not require the
extra.
"""
