from __future__ import annotations

import json

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main


def test_stage05_cli_selects_longest_counterpart_and_records_leftover(tmp_path):
    module = load_module_from_path(
        'test_stage05_cli_module',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    signatures_dir = tmp_path / 'signatures'
    signatures_dir.mkdir()

    b2b_path = signatures_dir / 'b2b.json'
    selected_counterpart_path = signatures_dir / 'g2b.json'
    leftover_counterpart_path = signatures_dir / 'b2g.json'

    for path, payload in (
        (b2b_path, {'key': 'b2b', 'hash': 'hash-b2b', 'bug_trace': []}),
        (selected_counterpart_path, {'key': 'g2b', 'hash': 'hash-g2b', 'bug_trace': []}),
        (leftover_counterpart_path, {'key': 'b2g', 'hash': 'hash-b2g', 'bug_trace': []}),
    ):
        path.write_text(json.dumps(payload), encoding='utf-8')

    trace_jsonl = tmp_path / 'trace_flow_match_strict.jsonl'
    records = [
        {
            'testcase_key': 'CASE001',
            'trace_file': str(b2b_path),
            'best_flow_type': 'b2b',
            'bug_trace_length': 3,
            'procedure': 'bad',
        },
        {
            'testcase_key': 'CASE001',
            'trace_file': str(selected_counterpart_path),
            'best_flow_type': 'g2b',
            'bug_trace_length': 8,
            'procedure': 'goodG2B',
        },
        {
            'testcase_key': 'CASE001',
            'trace_file': str(leftover_counterpart_path),
            'best_flow_type': 'b2g',
            'bug_trace_length': 4,
            'procedure': 'goodB2G',
        },
    ]
    trace_jsonl.write_text(
        '\n'.join(json.dumps(record) for record in records) + '\n',
        encoding='utf-8',
    )

    output_dir = tmp_path / 'paired-output'

    assert (
        run_module_main(
            module,
            [
                'stage05',
                '--trace-jsonl',
                str(trace_jsonl),
                '--output-dir',
                str(output_dir),
            ],
        )
        == 0
    )

    pairs = [
        json.loads(line)
        for line in (output_dir / 'pairs.jsonl').read_text(encoding='utf-8').splitlines()
    ]
    assert len(pairs) == 1
    assert pairs[0]['counterpart_flow_type'] == 'g2b'

    leftovers = [
        json.loads(line)
        for line in (output_dir / 'leftover_counterparts.jsonl')
        .read_text(encoding='utf-8')
        .splitlines()
    ]
    assert leftovers == [
        {
            'testcase_key': 'CASE001',
            'related_pair_id': pairs[0]['pair_id'],
            'trace_file': str(leftover_counterpart_path),
            'best_flow_type': 'b2g',
            'bug_trace_length': 4,
            'procedure': 'goodB2G',
            'primary_file': None,
            'primary_line': None,
            'dropped_reason': 'not_selected_longest_bug_trace',
        }
    ]

    paired_case_dir = output_dir / 'paired_signatures' / 'CASE001'
    assert (paired_case_dir / 'b2b.json').exists()
    assert (paired_case_dir / 'g2b.json').exists()
