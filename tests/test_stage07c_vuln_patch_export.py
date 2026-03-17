from __future__ import annotations

import csv
import json

from tests.helpers import REPO_ROOT, load_module_from_path


def write_dataset_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    header = [
        'file_name',
        'unique_id',
        'target',
        'vulnerable_line_numbers',
        'project',
        'source_signature_path',
        'commit_hash',
        'dataset_type',
        'processed_func',
    ]
    with path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def test_export_vuln_patch_dataset_selects_first_counterpart_and_rewrites_dataset_type(tmp_path):
    module = load_module_from_path(
        'test_stage07c_vuln_patch_export',
        REPO_ROOT / 'tools/stage/stage07c_vuln_patch_export.py',
    )

    source_csv_path = tmp_path / 'Real_Vul_data.csv'
    write_dataset_csv(
        source_csv_path,
        [
            [
                '10',
                '10',
                '1',
                '1',
                'Juliet',
                'artifacts/pipeline-runs/demo/03_signatures/non_empty/CASE1/b2b.json',
                '',
                'train_val',
                'bad();',
            ],
            [
                '11',
                '11',
                '0',
                '',
                'Juliet',
                'artifacts/pipeline-runs/demo/03_signatures/non_empty/CASE1/g2b1.json',
                '',
                'train_val',
                'good_one();',
            ],
            [
                '12',
                '12',
                '0',
                '',
                'Juliet',
                'artifacts/pipeline-runs/demo/03_signatures/non_empty/CASE1/g2b2.json',
                '',
                'test',
                'good_two();',
            ],
            [
                '13',
                '13',
                '1',
                '1',
                'Juliet',
                'artifacts/pipeline-runs/demo/03_signatures/non_empty/CASE2/b2b.json',
                '',
                'train_val',
                'bad_case2();',
            ],
            [
                '14',
                '14',
                '0',
                '',
                'Juliet',
                'artifacts/pipeline-runs/demo/03_signatures/non_empty/CASE2/g2b.json',
                '',
                'train_val',
                'good_case2();',
            ],
            [
                '15',
                '15',
                '1',
                '1',
                'Juliet',
                'artifacts/pipeline-runs/demo/03_signatures/non_empty/CASE3/b2b_a.json',
                '',
                'train_val',
                'bad_case3_a();',
            ],
            [
                '16',
                '16',
                '1',
                '1',
                'Juliet',
                'artifacts/pipeline-runs/demo/03_signatures/non_empty/CASE3/b2b_b.json',
                '',
                'train_val',
                'bad_case3_b();',
            ],
            [
                '17',
                '17',
                '0',
                '',
                'Juliet',
                'artifacts/pipeline-runs/demo/03_signatures/non_empty/CASE3/g2b.json',
                '',
                'train_val',
                'good_case3_a();',
            ],
            [
                '18',
                '18',
                '0',
                '',
                'Juliet',
                'artifacts/pipeline-runs/demo/03_signatures/non_empty/CASE3/g2b2.json',
                '',
                'train_val',
                'good_case3_b();',
            ],
            [
                '19',
                '19',
                '0',
                '',
                'Juliet',
                'artifacts/pipeline-runs/demo/03_signatures/non_empty/CASE4/g2b.json',
                '',
                'train_val',
                'good_case4();',
            ],
        ],
    )

    result = module.export_vuln_patch_dataset(
        source_csv_path=source_csv_path,
        output_dir=tmp_path / 'vuln_patch',
    )

    with (tmp_path / 'vuln_patch' / 'Real_Vul_data.csv').open(
        'r', encoding='utf-8', newline=''
    ) as f:
        rows = list(csv.DictReader(f))
    summary = json.loads((tmp_path / 'vuln_patch' / 'summary.json').read_text(encoding='utf-8'))

    assert len(rows) == 2
    assert [row['file_name'] for row in rows] == ['1', '2']
    assert [row['unique_id'] for row in rows] == ['1', '2']
    assert [row['target'] for row in rows] == ['1', '0']
    assert {row['dataset_type'] for row in rows} == {'test'}
    assert rows[0]['source_signature_path'].endswith('/CASE1/b2b.json')
    assert rows[1]['source_signature_path'].endswith('/CASE1/g2b1.json')

    assert result['artifacts']['csv_path'].endswith('vuln_patch/Real_Vul_data.csv')
    assert summary['stats']['selection_policy'] == 'first_counterpart_in_existing_csv_order'
    assert summary['stats']['counts']['eligible_testcases'] == 1
    assert summary['stats']['counts']['rows_written'] == 2
    assert summary['stats']['ineligible_testcase_reasons'] == {
        'missing_b2b': 1,
        'multi_b2b': 1,
        'counterpart_lt2': 1,
    }
    assert summary['stats']['counterpart_count_distribution'] == {'2': 1}
    assert summary['stats']['selected_testcases'] == [
        {
            'testcase_key': 'CASE1',
            'counterpart_candidates_total': 2,
            'selected_b2b_source_signature_path': (
                'artifacts/pipeline-runs/demo/03_signatures/non_empty/CASE1/b2b.json'
            ),
            'selected_counterpart_source_signature_path': (
                'artifacts/pipeline-runs/demo/03_signatures/non_empty/CASE1/g2b1.json'
            ),
        }
    ]
