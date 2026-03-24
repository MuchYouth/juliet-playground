from __future__ import annotations

import json

from tests.helpers import REPO_ROOT, load_module_from_path


def test_generate_trace_slices_writes_slice_file_and_summary(tmp_path):
    module = load_module_from_path(
        'test_stage06_trace_slices_module',
        REPO_ROOT / 'tools/stage/stage06_trace_slices.py',
    )

    source_file = tmp_path / 'sample.c'
    source_file.write_text('line 1\nline 2\n', encoding='utf-8')

    trace_file = tmp_path / 'CASE001' / '7.json'
    trace_file.parent.mkdir(parents=True)
    trace_file.write_text(
        json.dumps(
            {
                'file': str(source_file),
                'bug_trace': [{'filename': str(source_file), 'line_number': 2}],
            }
        ),
        encoding='utf-8',
    )

    traces_jsonl = tmp_path / 'traces.jsonl'
    traces_jsonl.write_text(
        json.dumps(
            {
                'trace_id': 'trace-001',
                'trace_file': str(trace_file),
                'testcase_key': 'CASE001',
                'best_flow_type': 'b2b',
            }
        )
        + '\n',
        encoding='utf-8',
    )

    output_dir = tmp_path / '06_trace_slices'
    result = module.generate_trace_slices(traces_jsonl=traces_jsonl, output_dir=output_dir)

    slice_path = output_dir / 'slice' / 'slice_trace-001.c'
    assert slice_path.exists()
    assert slice_path.read_text(encoding='utf-8') == 'line 2\n'
    assert result['artifacts']['slice_dir'] == str(output_dir / 'slice')

    summary = json.loads((output_dir / 'summary.json').read_text(encoding='utf-8'))
    assert summary['stats']['traces_total'] == 1
    assert summary['stats']['generated'] == 1


def test_generate_trace_slices_tracks_skipped_rows_and_errors(tmp_path):
    module = load_module_from_path(
        'test_stage06_trace_slices_counters',
        REPO_ROOT / 'tools/stage/stage06_trace_slices.py',
    )

    empty_trace_file = tmp_path / 'CASE001' / 'empty.json'
    empty_trace_file.parent.mkdir(parents=True)
    empty_trace_file.write_text(json.dumps({'bug_trace': []}), encoding='utf-8')

    traces_jsonl = tmp_path / 'traces.jsonl'
    traces_jsonl.write_text(
        '\n'.join(
            [
                json.dumps({'trace_id': '', 'trace_file': '', 'testcase_key': 'CASE001'}),
                json.dumps(
                    {
                        'trace_id': 'missing-file',
                        'trace_file': str(tmp_path / 'CASE001' / 'missing.json'),
                        'testcase_key': 'CASE001',
                    }
                ),
                json.dumps(
                    {
                        'trace_id': 'empty-bug-trace',
                        'trace_file': str(empty_trace_file),
                        'testcase_key': 'CASE001',
                    }
                ),
            ]
        )
        + '\n',
        encoding='utf-8',
    )

    output_dir = tmp_path / '06_trace_slices'
    result = module.generate_trace_slices(traces_jsonl=traces_jsonl, output_dir=output_dir)

    assert result['stats']['generated'] == 0
    assert result['stats']['skipped'] == 3
    assert result['stats']['counts']['skipped_missing_trace_fields'] == 1
    assert result['stats']['counts']['skipped_missing_trace_file'] == 1
    assert result['stats']['counts']['skipped_empty_bug_trace'] == 1
