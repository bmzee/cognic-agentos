import sys
from pathlib import Path

# The egress-proxy shim is image content under infra/sandbox/egress-proxy/
# (hyphenated dir, not an importable package), so put it on sys.path to import
# the module file directly.
_SHIM_DIR = Path(__file__).resolve().parents[4] / "infra" / "sandbox" / "egress-proxy"
sys.path.insert(0, str(_SHIM_DIR))
