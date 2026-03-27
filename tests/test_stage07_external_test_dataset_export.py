from __future__ import annotations

import csv
import json
from types import SimpleNamespace

from tests.helpers import (
    REPO_ROOT,
    deterministic_tokenizer_context,
    load_module_from_path,
    write_json,
    write_jsonl,
    write_text,
)


def test_external_test_dataset_export_writes_test_only_csv_and_manifest(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_stage07_external_test_dataset_export',
        REPO_ROOT / 'tools/stage/stage07_external_test_dataset_export.py',
    )

    monkeypatch.setattr(
        module._stage07_trace_dataset_export,
        'build_source_file_candidates',
        lambda payload, hint: [],
    )
    monkeypatch.setattr(
        module._stage07_trace_dataset_export,
        'collect_identifier_inventory',
        lambda path, parsers: (
            SimpleNamespace(function_names=set(), type_names=set(), variable_names=set()),
            None,
        ),
    )
    monkeypatch.setattr(module, 'load_tree_sitter_parsers', lambda: {})
    monkeypatch.setattr(
        module._stage07_trace_dataset_export, 'load_tree_sitter_parsers', lambda: {}
    )

    source_root = tmp_path / 'project'
    write_text(
        source_root / 'src' / 'demo.c',
        ''.join(f'code_{idx}();\n' for idx in range(1, 10)),
    )
    signature_path = tmp_path / 'signatures' / 'trace-a.json'
    write_json(
        signature_path,
        {
            'file': str(source_root / 'src' / 'demo.c'),
            'line': 9,
            'bug_trace': [
                {'filename': str(source_root / 'src' / 'demo.c'), 'line_number': 3},
                {'filename': str(source_root / 'src' / 'demo.c'), 'line_number': 5},
            ],
        },
    )
    write_jsonl(
        tmp_path / 'traces.jsonl',
        [
            {
                'trace_id': 'trace-a',
                'testcase_key': 'demo-case',
                'best_flow_type': 'b2b',
                'target': 1,
                'trace_file': str(signature_path),
                'bug_trace_length': 2,
                'procedure': 'demo_proc',
                'matched_source_lines': [
                    {'file_path': 'src/demo.c', 'line_number': 5},
                    {'file_path': 'src/demo.c', 'line_number': 9},
                ],
                'matched_primary_only': True,
            }
        ],
    )
    slice_dir = tmp_path / 'slice'
    write_text(slice_dir / 'slice_trace-a.c', 'code_3();\ncode_5();\n')

    with deterministic_tokenizer_context():
        result = module.export_external_test_dataset(
            traces_jsonl=tmp_path / 'traces.jsonl',
            slice_dir=slice_dir,
            output_dir=tmp_path / 'out',
            source_root=source_root,
            project_name='DemoProject',
        )

    with (tmp_path / 'out' / 'Real_Vul_data.csv').open('r', encoding='utf-8', newline='') as f:
        rows = list(csv.DictReader(f))
    manifest_rows = [
        json.loads(line)
        for line in (tmp_path / 'out' / 'trace_row_manifest.jsonl')
        .read_text(encoding='utf-8')
        .splitlines()
        if line.strip()
    ]

    assert result['stats']['counts']['rows_written'] == 1
    assert rows == [
        {
            'file_name': '1',
            'unique_id': '1',
            'target': '1',
            'vulnerable_line_numbers': '2',
            'project': 'DemoProject',
            'source_signature_path': str(signature_path),
            'commit_hash': '',
            'dataset_type': 'test',
            'processed_func': 'code_3();\ncode_5();\n',
        }
    ]
    assert manifest_rows == [
        {
            'row_id': 1,
            'trace_id': 'trace-a',
            'testcase_key': 'demo-case',
            'trace_file': str(signature_path),
            'source_signature_path': str(signature_path),
            'matched_source_lines': [
                {'file_path': 'src/demo.c', 'line_number': 5},
                {'file_path': 'src/demo.c', 'line_number': 9},
            ],
            'matched_slice_line_numbers': [2],
            'matched_primary_only': True,
        }
    ]
