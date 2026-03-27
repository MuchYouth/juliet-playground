from __future__ import annotations

import csv
import json

from tests.helpers import REPO_ROOT, load_module_from_path, write_json, write_text


def test_manual_line_filter_keeps_only_matching_traces(tmp_path):
    module = load_module_from_path(
        'test_stage05b_manual_line_filter',
        REPO_ROOT / 'tools/stage/stage05b_manual_line_filter.py',
    )

    source_root = tmp_path / 'project'
    write_text(
        source_root / 'src' / 'manager.c',
        ''.join(f'line_{idx}\n' for idx in range(1, 16)),
    )

    manual_csv = tmp_path / 'manual_line_truth.csv'
    with manual_csv.open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['testcase_key', 'file_path', 'line_number', 'label', 'note'])
        writer.writerow(
            [
                'demo-case',
                str(source_root / 'src' / 'manager.c'),
                '5,7',
                '1',
                'confirmed',
            ]
        )

    signatures_dir = tmp_path / 'signatures'
    testcase_dir = signatures_dir / 'demo-case'
    testcase_dir.mkdir(parents=True)
    write_json(
        testcase_dir / '1.json',
        {
            'procedure': 'demo_proc',
            'file': str(source_root / 'src' / 'manager.c'),
            'line': 7,
            'bug_trace': [
                {'filename': str(source_root / 'src' / 'manager.c'), 'line_number': 3},
                {'filename': str(source_root / 'src' / 'manager.c'), 'line_number': 5},
            ],
        },
    )
    write_json(
        testcase_dir / '2.json',
        {
            'procedure': 'demo_proc',
            'file': str(source_root / 'src' / 'manager.c'),
            'line': 2,
            'bug_trace': [
                {'filename': str(source_root / 'src' / 'manager.c'), 'line_number': 1},
                {'filename': str(source_root / 'src' / 'manager.c'), 'line_number': 2},
            ],
        },
    )

    result = module.filter_traces_by_manual_lines(
        signatures_dir=signatures_dir,
        manual_line_truth_csv=manual_csv,
        source_root=source_root,
        output_dir=tmp_path / 'out',
    )

    kept_rows = [
        json.loads(line)
        for line in (tmp_path / 'out' / 'traces.jsonl').read_text(encoding='utf-8').splitlines()
        if line.strip()
    ]
    dropped_rows = [
        json.loads(line)
        for line in (tmp_path / 'out' / 'dropped_traces.jsonl')
        .read_text(encoding='utf-8')
        .splitlines()
        if line.strip()
    ]

    assert result['stats']['traces_kept'] == 1
    assert len(kept_rows) == 1
    assert kept_rows[0]['target'] == 1
    assert kept_rows[0]['matched_primary_only'] is True
    assert kept_rows[0]['matched_source_lines'] == [
        {'file_path': 'src/manager.c', 'line_number': 5},
        {'file_path': 'src/manager.c', 'line_number': 7},
    ]
    assert dropped_rows == [
        {
            'testcase_key': 'demo-case',
            'trace_file': str(testcase_dir / '2.json'),
            'drop_reason': 'no_manual_line_hit',
        }
    ]
