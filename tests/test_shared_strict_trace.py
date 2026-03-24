from __future__ import annotations

import json

import pytest

from tests.helpers import REPO_ROOT, load_module_from_path


def _load_module():
    return load_module_from_path(
        'test_shared_strict_trace_module',
        REPO_ROOT / 'tools/shared/strict_trace.py',
    )


def test_load_strict_records_supports_include_raw(tmp_path):
    module = _load_module()
    trace_jsonl = tmp_path / 'trace_flow_match_strict.jsonl'
    trace_jsonl.write_text(
        json.dumps(
            {
                'testcase_key': 'CASE001',
                'trace_file': str(tmp_path / 'CASE001' / '1.json'),
                'best_flow_type': 'b2b',
                'bug_trace_length': 3,
                'procedure': 'bad',
            }
        )
        + '\n',
        encoding='utf-8',
    )

    without_raw = module.load_strict_records(trace_jsonl)
    with_raw = module.load_strict_records(trace_jsonl, include_raw=True)

    assert len(without_raw) == 1
    assert without_raw[0].raw is None
    assert with_raw[0].raw is not None
    assert with_raw[0].raw['testcase_key'] == 'CASE001'


def test_load_strict_records_requires_required_keys(tmp_path):
    module = _load_module()
    trace_jsonl = tmp_path / 'trace_flow_match_strict.jsonl'
    trace_jsonl.write_text(
        json.dumps(
            {
                'testcase_key': 'CASE001',
                'trace_file': str(tmp_path / 'CASE001' / '1.json'),
                'bug_trace_length': 3,
            }
        )
        + '\n',
        encoding='utf-8',
    )

    with pytest.raises(ValueError, match='Missing required keys'):
        module.load_strict_records(trace_jsonl)


def test_strict_trace_record_raw_defaults_to_none():
    module = _load_module()
    record = module.StrictTraceRecord(
        testcase_key='CASE001',
        trace_file=REPO_ROOT / 'dummy.json',
        best_flow_type='b2b',
        bug_trace_length=1,
        procedure='bad',
    )

    assert record.raw is None
