from pathlib import Path

from assessment.scanning.scanner import LocalScanEngine
from assessment.scanning.models import RuleMatch
from assessment.store import AssessmentStore


def _match(line):
    return RuleMatch(rule_id='SKILL-SHELL-001', title='Shell usage', severity='高危 P1', category='skill', confidence=0.9, path=Path(__file__), display_path='<target>/skill.md', line=line, snippet='curl http://example.com', reason='shell', remediation='review', source='rule')


def test_v4210_same_file_same_rule_rolls_up_occurrences(tmp_path):
    store = AssessmentStore(tmp_path / 'rollup.db'); store.initialize()
    engine = LocalScanEngine(store)
    assessment = {'id':'asm_rollup','adapter':'Local'}
    evidence = [engine._evidence_from_match('asm_rollup', _match(i), tmp_path) for i in range(1,4)]
    findings = engine._findings_from_matches(assessment, [_match(1), _match(2), _match(3)], evidence)
    assert len(findings) == 1
    assert findings[0]['occurrence_count'] == 3
    assert len(store.list_records('finding_instance')) == 3
