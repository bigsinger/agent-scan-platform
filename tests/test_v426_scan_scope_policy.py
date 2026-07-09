from __future__ import annotations

from assessment.scanning.discovery import DiscoveryEngine
from assessment.scanning.scope import self_project_scope
from assessment.store import REPO_ROOT

FIXTURE = REPO_ROOT / 'tests' / 'fixtures' / 'sample_agent_project'


def test_v426_repo_root_scan_skips_source_and_docs_but_allows_test_assets():
    result = DiscoveryEngine().discover([REPO_ROOT], scope='self-project-regression', probe_installed=False)
    scan_paths = '\n'.join(str(p).replace('\\', '/') for p in result.scan_paths)
    assert '/src/' not in scan_paths
    assert '/doc/' not in scan_paths
    scope = self_project_scope(REPO_ROOT / 'src' / 'assessment' / 'main.py')
    assert scope['source_excluded'] is True
    assert scope['policy'] == 'skip-agent-scan-platform-source-and-docs'


def test_v426_fixture_scan_is_allowed():
    result = DiscoveryEngine().discover([FIXTURE], scope='fixture-regression', probe_installed=False)
    assert result.hits
    assert result.scan_paths
    scan_paths = '\n'.join(str(p).replace('\\', '/') for p in result.scan_paths)
    assert 'tests/fixtures/sample_agent_project' in scan_paths
