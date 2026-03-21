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


def test_trace_dataset_export_prunes_multi_b2b_and_writes_trace_split_manifest(
    tmp_path,
    monkeypatch,
):
    module = load_module_from_path(
        'test_stage07_trace_dataset_export',
        REPO_ROOT / 'tools/stage/stage07_trace_dataset_export.py',
    )

    monkeypatch.setattr(module, 'build_source_file_candidates', lambda payload, hint: [])
    monkeypatch.setattr(
        module,
        'collect_identifier_inventory',
        lambda path, parsers: (
            SimpleNamespace(function_names=set(), type_names=set(), variable_names=set()),
            None,
        ),
    )
    monkeypatch.setattr(module, 'load_tree_sitter_parsers', lambda: {})

    sig_dir = tmp_path / 'signatures'
    slice_dir = tmp_path / 'slice'
    output_dir = tmp_path / 'out'
    sig_dir.mkdir()
    slice_dir.mkdir()

    trace_rows = []
    for trace_id in [
        'b2b-long',
        'b2b-short',
        'cp-one',
        'cp-two',
        'cp-dup',
        'collide-bad',
        'collide-good',
        'case5-bad',
        'case5-good',
        'case6-bad',
        'case6-good',
    ]:
        signature_path = sig_dir / f'{trace_id}.json'
        write_json(signature_path, {'file': ''})
        trace_rows.append(
            {
                'trace_id': trace_id,
                'testcase_key': {
                    'b2b-long': 'CASE1',
                    'b2b-short': 'CASE1',
                    'cp-one': 'CASE1',
                    'cp-two': 'CASE1',
                    'cp-dup': 'CASE2',
                    'collide-bad': 'CASE3',
                    'collide-good': 'CASE4',
                    'case5-bad': 'CASE5',
                    'case5-good': 'CASE5',
                    'case6-bad': 'CASE6',
                    'case6-good': 'CASE6',
                }[trace_id],
                'best_flow_type': {
                    'b2b-long': 'b2b',
                    'b2b-short': 'b2b',
                    'cp-one': 'g2b',
                    'cp-two': 'g2b2',
                    'cp-dup': 'g2b',
                    'collide-bad': 'b2b',
                    'collide-good': 'g2b',
                    'case5-bad': 'b2b',
                    'case5-good': 'g2b',
                    'case6-bad': 'b2b',
                    'case6-good': 'g2b',
                }[trace_id],
                'target': {
                    'b2b-long': 1,
                    'b2b-short': 1,
                    'cp-one': 0,
                    'cp-two': 0,
                    'cp-dup': 0,
                    'collide-bad': 1,
                    'collide-good': 0,
                    'case5-bad': 1,
                    'case5-good': 0,
                    'case6-bad': 1,
                    'case6-good': 0,
                }[trace_id],
                'trace_file': str(signature_path),
                'bug_trace_length': {
                    'b2b-long': 7,
                    'b2b-short': 3,
                    'cp-one': 2,
                    'cp-two': 4,
                    'cp-dup': 5,
                    'collide-bad': 6,
                    'collide-good': 1,
                    'case5-bad': 2,
                    'case5-good': 3,
                    'case6-bad': 4,
                    'case6-good': 5,
                }[trace_id],
                'procedure': 'demo_proc',
            }
        )

    write_jsonl(tmp_path / 'traces.jsonl', trace_rows)

    write_text(slice_dir / 'slice_b2b-long.c', 'bad_long();\n')
    write_text(slice_dir / 'slice_b2b-short.c', 'bad_short();\n')
    write_text(slice_dir / 'slice_cp-one.c', 'good_one();\n')
    write_text(slice_dir / 'slice_cp-two.c', 'good_two();\n')
    write_text(slice_dir / 'slice_cp-dup.c', 'good_one();\n')
    write_text(slice_dir / 'slice_collide-bad.c', 'shared();\n')
    write_text(slice_dir / 'slice_collide-good.c', 'shared();\n')
    write_text(slice_dir / 'slice_case5-bad.c', 'case5_bad();\n')
    write_text(slice_dir / 'slice_case5-good.c', 'case5_good();\n')
    write_text(slice_dir / 'slice_case6-bad.c', 'case6_bad();\n')
    write_text(slice_dir / 'slice_case6-good.c', 'case6_good();\n')

    with deterministic_tokenizer_context():
        module.export_trace_dataset_from_pipeline(
            traces_jsonl=tmp_path / 'traces.jsonl',
            slice_dir=slice_dir,
            output_dir=output_dir,
            split_seed=1234,
            train_ratio=0.8,
            dedup_mode='row',
        )

    with (output_dir / 'summary.json').open('r', encoding='utf-8') as f:
        summary = json.load(f)
    with (output_dir / 'split_manifest.json').open('r', encoding='utf-8') as f:
        split_manifest = json.load(f)
    with (output_dir / 'Real_Vul_data.csv').open('r', encoding='utf-8', newline='') as f:
        csv_rows = list(csv.DictReader(f))
    with (output_dir / 'vuln_patch' / 'Real_Vul_data.csv').open(
        'r', encoding='utf-8', newline=''
    ) as f:
        vuln_patch_rows = list(csv.DictReader(f))
    vuln_patch_summary = json.loads(
        (output_dir / 'vuln_patch' / 'summary.json').read_text(encoding='utf-8')
    )
    dropped_rows = [
        json.loads(line)
        for line in (output_dir / 'trace_dedup_dropped.jsonl')
        .read_text(encoding='utf-8')
        .splitlines()
        if line.strip()
    ]

    assert split_manifest['counts']['traces_total'] == 4
    assert split_manifest['counts']['train_val_traces'] == 2
    assert split_manifest['counts']['test_traces'] == 2
    assert sorted(
        split_manifest['testcase_keys']['train_val'] + split_manifest['testcase_keys']['test']
    ) == [
        'CASE5',
        'CASE6',
    ]
    assert sorted(
        split_manifest['trace_ids']['train_val'] + split_manifest['trace_ids']['test']
    ) == [
        'case5-bad',
        'case5-good',
        'case6-bad',
        'case6-good',
    ]
    assert 'pair_ids' not in split_manifest

    assert summary['stats']['counts']['traces_total'] == 11
    assert summary['stats']['counts']['traces_survived_pre_vuln_patch_holdout'] == 7
    assert summary['stats']['counts']['traces_survived'] == 4
    assert summary['stats']['filtered_trace_reasons'] == {
        'same_label_duplicate': 1,
        'cross_label_collision': 2,
        'multi_b2b_pruned': 1,
    }
    assert summary['stats']['structural_pruning']['b2b_rows_pruned'] == 1
    assert summary['stats']['vuln_patch_holdout'] == {
        'testcases_selected': 1,
        'rows_written': 2,
        'rows_removed_from_main_dataset': 3,
    }

    assert len(csv_rows) == 4
    assert sorted(row['target'] for row in csv_rows) == ['0', '0', '1', '1']
    assert sorted({row['dataset_type'] for row in csv_rows}) == ['test', 'train_val']
    assert all(
        not row['source_signature_path'].endswith(
            ('/b2b-short.json', '/cp-one.json', '/cp-two.json')
        )
        for row in csv_rows
    )

    assert len(vuln_patch_rows) == 2
    assert [row['target'] for row in vuln_patch_rows] == ['1', '0']
    assert {row['dataset_type'] for row in vuln_patch_rows} == {'test'}
    assert vuln_patch_rows[0]['source_signature_path'].endswith('/b2b-short.json')
    assert vuln_patch_rows[1]['source_signature_path'].endswith('/cp-one.json')
    assert vuln_patch_summary['stats']['counts']['eligible_testcases'] == 1
    assert vuln_patch_summary['stats']['counts']['rows_written'] == 2
    assert vuln_patch_summary['stats']['selected_testcases'] == [
        {
            'testcase_key': 'CASE1',
            'counterpart_candidates_total': 2,
            'selected_b2b_source_signature_path': str(sig_dir / 'b2b-short.json'),
            'selected_counterpart_source_signature_path': str(sig_dir / 'cp-one.json'),
        }
    ]

    assert {row['drop_reason'] for row in dropped_rows} == {
        'same_label_duplicate',
        'cross_label_collision',
        'multi_b2b_pruned',
    }
