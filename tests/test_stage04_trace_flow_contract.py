from __future__ import annotations

import json

import pytest

from tests.golden.helpers import (
    REPO_ROOT,
    load_module_from_path,
    prepare_workspace,
    run_module_main,
)


def test_stage04_trace_flow_contract(tmp_path):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_stage04_trace_flow_contract',
        REPO_ROOT / 'experiments/epic001d_trace_flow_filter/scripts/filter_traces_by_flow.py',
    )

    output_dir = work_root / 'expected/04_trace_flow'
    assert (
        run_module_main(
            module,
            [
                '--flow-xml',
                str(baseline_root / 'expected/02c_flow/manifest_with_testcase_flows.xml'),
                '--signatures-dir',
                str(baseline_root / 'expected/03_signatures_non_empty'),
                '--output-dir',
                str(output_dir),
            ],
        )
        == 0
    )

    strict_path = output_dir / 'trace_flow_match_strict.jsonl'
    summary_path = output_dir / 'summary.json'
    for path in [strict_path, summary_path]:
        assert path.exists()

    strict_rows = [
        json.loads(line) for line in strict_path.read_text(encoding='utf-8').splitlines() if line
    ]
    assert strict_rows
    for row in strict_rows:
        assert {
            'trace_file',
            'testcase_key',
            'status',
            'best_flow_type',
            'best_flow_meta',
            'flow_match',
        } <= set(row)
        assert row['status'] == 'strict_match'
        assert row['best_flow_meta']['strict_match'] is True
        for flow_meta in row['flow_match'].values():
            assert set(flow_meta['hit_tag_counts']) <= {'flaw', 'fix'}

    summary = json.loads(summary_path.read_text(encoding='utf-8'))
    assert set(summary) == {'artifacts', 'stats'}
    assert summary['artifacts']['trace_flow_match_strict_jsonl'] == str(strict_path)
    assert {'traces_total', 'traces_strict_match', 'matched_best_flow_counts'} <= set(
        summary['stats']
    )


def test_stage04_cli_rejects_removed_convenience_options():
    module = load_module_from_path(
        'test_stage04_trace_flow_cli',
        REPO_ROOT / 'experiments/epic001d_trace_flow_filter/scripts/filter_traces_by_flow.py',
    )

    with pytest.raises(SystemExit) as excinfo:
        run_module_main(
            module,
            [
                '--flow-xml',
                'flow.xml',
                '--signatures-dir',
                'signatures',
                '--output-dir',
                'out',
                '--infer-name',
                'infer-2026.03.09-14:42:44',
            ],
        )

    assert excinfo.value.code == 2
