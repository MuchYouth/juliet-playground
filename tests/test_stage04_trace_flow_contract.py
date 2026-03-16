from __future__ import annotations

import json

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

    all_path = output_dir / 'trace_flow_match_all.jsonl'
    strict_path = output_dir / 'trace_flow_match_strict.jsonl'
    partial_path = output_dir / 'trace_flow_match_partial_or_strict.jsonl'
    summary_path = output_dir / 'summary.json'
    for path in [all_path, strict_path, partial_path, summary_path]:
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
        assert row['best_flow_type']
        assert row['trace_file']
        assert row['best_flow_meta']['strict_match'] is True

    summary = json.loads(summary_path.read_text(encoding='utf-8'))
    assert {'flow_index', 'trace_stats', 'matched_best_flow_counts', 'output_files'} <= set(summary)
