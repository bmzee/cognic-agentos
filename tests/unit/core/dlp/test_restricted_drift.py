# TEST-ONLY pin to the cli canonical (no runtime core->cli import).
from cognic_agentos.cli._governance_vocab import RESTRICTED_DATA_CLASSES as CliRestricted
from cognic_agentos.core.dlp.scanner import DLP_RESTRICTED_CLASSES


def test_dlp_restricted_set_lockstep_with_cli():
    assert CliRestricted == DLP_RESTRICTED_CLASSES
