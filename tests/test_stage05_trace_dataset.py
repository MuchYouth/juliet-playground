from __future__ import annotations

import json

from tests.helpers import REPO_ROOT, load_module_from_path


def test_make_trace_id_is_stable_across_run_roots():
    module = load_module_from_path(
        'test_stage05_trace_dataset_module',
        REPO_ROOT / 'tools/stage/stage05_trace_dataset.py',
    )

    left_record = module.StrictTraceRecord(
        testcase_key='CASE001',
        trace_file=REPO_ROOT / 'run-a' / 'CASE001' / '7.json',
        best_flow_type='g2b',
        bug_trace_length=8,
        procedure='goodG2B',
    )
    right_record = module.StrictTraceRecord(
        testcase_key='CASE001',
        trace_file=REPO_ROOT / 'run-b' / 'CASE001' / '7.json',
        best_flow_type='g2b',
        bug_trace_length=8,
        procedure='goodG2B',
    )
    payload = {'hash': 'same-hash'}

    assert module.make_trace_id(left_record, payload) == module.make_trace_id(right_record, payload)


def test_build_trace_dataset_writes_trace_rows_and_summary(tmp_path):
    module = load_module_from_path(
        'test_stage05_trace_dataset_build',
        REPO_ROOT / 'tools/stage/stage05_trace_dataset.py',
    )

    sig_dir = tmp_path / 'signatures' / 'CASE001'
    sig_dir.mkdir(parents=True)
    b2b_path = sig_dir / 'b2b.json'
    g2b_path = sig_dir / 'g2b.json'
    b2b_path.write_text(json.dumps({'hash': 'hash-b2b'}), encoding='utf-8')
    g2b_path.write_text(json.dumps({'hash': 'hash-g2b'}), encoding='utf-8')

    trace_jsonl = tmp_path / 'trace_flow_match_strict.jsonl'
    trace_jsonl.write_text(
        '\n'.join(
            [
                json.dumps(
                    {
                        'testcase_key': 'CASE001',
                        'trace_file': str(b2b_path),
                        'best_flow_type': 'b2b',
                        'bug_trace_length': 3,
                        'procedure': 'bad',
                    }
                ),
                json.dumps(
                    {
                        'testcase_key': 'CASE001',
                        'trace_file': str(g2b_path),
                        'best_flow_type': 'g2b',
                        'bug_trace_length': 8,
                        'procedure': 'goodG2B',
                    }
                ),
            ]
        )
        + '\n',
        encoding='utf-8',
    )

    output_dir = tmp_path / '05_trace_ds'
    result = module.build_trace_dataset(trace_jsonl=trace_jsonl, output_dir=output_dir)

    traces_path = output_dir / 'traces.jsonl'
    summary_path = output_dir / 'summary.json'
    assert traces_path.exists()
    assert summary_path.exists()
    assert result['artifacts']['traces_jsonl'] == str(traces_path)

    rows = [
        json.loads(line) for line in traces_path.read_text(encoding='utf-8').splitlines() if line
    ]
    assert len(rows) == 2
    assert {row['target'] for row in rows} == {0, 1}
    assert {row['best_flow_type'] for row in rows} == {'b2b', 'g2b'}

    summary = json.loads(summary_path.read_text(encoding='utf-8'))
    assert summary['stats']['records_total'] == 2
    assert summary['stats']['traces_total'] == 2
    assert summary['stats']['testcases_total'] == 1
