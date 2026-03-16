from __future__ import annotations

import csv
from pathlib import Path

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main, write_json, write_jsonl


def write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def make_dataset_export_dir(root: Path, *, pairs_total: int, processed_suffix: str) -> Path:
    write_json(
        root / 'summary.json',
        {
            'artifacts': {
                'csv_path': str(root / 'Real_Vul_data.csv'),
                'normalized_slices_dir': str(root / 'normalized_slices'),
                'split_manifest_json': str(root / 'split_manifest.json'),
                'summary_json': str(root / 'summary.json'),
            },
            'stats': {
                'counts': {'pairs_total': pairs_total, 'pairs_survived': pairs_total},
                'filtered_pair_reasons': {},
                'dedup': {'pairs_before': pairs_total, 'pairs_after': pairs_total},
            },
        },
    )
    write_json(
        root / 'split_manifest.json',
        {'counts': {'pairs_total': pairs_total, 'train_val': max(0, pairs_total - 1), 'test': 1}},
    )
    write_csv(
        root / 'Real_Vul_data.csv',
        [
            'file_name',
            'unique_id',
            'target',
            'vulnerable_line_numbers',
            'project',
            'source_signature_path',
            'commit_hash',
            'dataset_type',
            'processed_func',
        ],
        [
            ['1', '1', '1', '1', 'Juliet', 'sig/a.json', '', 'train_val', f'int a_{processed_suffix};'],
            ['2', '2', '0', '', 'Juliet', 'sig/b.json', '', 'test', f'int b_{processed_suffix};'],
        ],
    )
    write_json(
        root / 'train_patched_counterparts_summary.json',
        {'artifacts': {}, 'stats': {'counts': {'pairs_total': 1, 'pairs_survived': 1}}},
    )
    write_json(
        root / 'train_patched_counterparts_split_manifest.json',
        {'counts': {'pairs_total': 1, 'train_val': 1, 'test': 0}},
    )
    write_csv(
        root / 'train_patched_counterparts.csv',
        [
            'file_name',
            'unique_id',
            'target',
            'vulnerable_line_numbers',
            'project',
            'source_signature_path',
            'commit_hash',
            'dataset_type',
            'processed_func',
        ],
        [['1', '1', '1', '1', 'Juliet', 'sig/patched.json', '', 'train_val', f'int patched_{processed_suffix};']],
    )
    return root


def make_pair_trace_dir(root: Path, *, flow: str) -> Path:
    write_json(
        root / 'summary.json',
        {'artifacts': {'pairs_jsonl': str(root / 'pairs.jsonl')}, 'stats': {'paired_testcases': 1}},
    )
    write_jsonl(
        root / 'pairs.jsonl',
        [
            {
                'pair_id': 'pair-1',
                'testcase_key': 'CASE1',
                'counterpart_flow_type': flow,
                'b2b_path': str(root / 'paired_signatures' / 'CASE1' / 'b2b.json'),
                'counterpart_path': str(root / 'paired_signatures' / 'CASE1' / f'{flow}.json'),
            }
        ],
    )
    write_jsonl(
        root / 'leftover_counterparts.jsonl',
        [{'testcase_key': 'CASE1', 'best_flow_type': flow, 'bug_trace_length': 1, 'trace_file': 'leftover.json'}],
    )
    return root


def make_run_dir(root: Path, *, flow: str, pairs_total: int, processed_suffix: str) -> Path:
    write_json(root / '03_infer_summary.json', {'artifacts': {}, 'stats': {'pairs_total': pairs_total}})
    make_pair_trace_dir(root / '05_pair_trace_ds', flow=flow)
    make_dataset_export_dir(root / '07_dataset_export', pairs_total=pairs_total, processed_suffix=processed_suffix)
    return root


def test_detect_artifact_kind_for_dataset_export_and_run(tmp_path):
    module = load_module_from_path(
        'test_compare_artifacts_detect', REPO_ROOT / 'tools/compare-artifacts.py'
    )

    dataset_dir = make_dataset_export_dir(tmp_path / '07_dataset_export', pairs_total=2, processed_suffix='a')
    run_dir = make_run_dir(tmp_path / 'run-foo', flow='g2b', pairs_total=2, processed_suffix='a')

    assert module.detect_artifact_kind(dataset_dir) == 'dataset_export'
    assert module.detect_artifact_kind(run_dir) == 'pipeline_run'


def test_main_reports_dataset_export_differences(tmp_path, capsys):
    module = load_module_from_path(
        'test_compare_artifacts_dataset', REPO_ROOT / 'tools/compare-artifacts.py'
    )

    before = make_dataset_export_dir(tmp_path / 'before_export', pairs_total=2, processed_suffix='a')
    after = make_dataset_export_dir(tmp_path / 'after_export', pairs_total=3, processed_suffix='b')

    assert run_module_main(module, [str(before), str(after), '--limit', '5']) == 0
    out = capsys.readouterr().out
    assert 'Kind: dataset_export' in out
    assert 'Dataset Export' in out
    assert 'summary.json: changed' in out
    assert 'Real_Vul_data.csv: added=2 removed=2 changed=0' in out


def test_main_reports_pair_trace_differences_for_run_dirs(tmp_path, capsys):
    module = load_module_from_path(
        'test_compare_artifacts_run', REPO_ROOT / 'tools/compare-artifacts.py'
    )

    before = make_run_dir(tmp_path / 'run_before', flow='g2b', pairs_total=2, processed_suffix='a')
    after = make_run_dir(tmp_path / 'run_after', flow='g2b1', pairs_total=3, processed_suffix='b')

    assert run_module_main(module, [str(before), str(after)]) == 0
    out = capsys.readouterr().out
    assert 'Kind: pipeline_run' in out
    assert 'Pair Trace Dataset' in out
    assert '05_pair_trace_ds/pairs.jsonl: added=0 removed=0 changed=1' in out
    assert 'Dataset Export' in out
    assert 'Differences found in' in out


def test_main_errors_on_kind_mismatch(tmp_path, capsys):
    module = load_module_from_path(
        'test_compare_artifacts_mismatch', REPO_ROOT / 'tools/compare-artifacts.py'
    )

    run_dir = make_run_dir(tmp_path / 'run_before', flow='g2b', pairs_total=2, processed_suffix='a')
    dataset_dir = make_dataset_export_dir(tmp_path / 'after_export', pairs_total=2, processed_suffix='a')

    assert run_module_main(module, [str(run_dir), str(dataset_dir)]) == 1
    err = capsys.readouterr().err
    assert 'Artifact kind mismatch' in err
