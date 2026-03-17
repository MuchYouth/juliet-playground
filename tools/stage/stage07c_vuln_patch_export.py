from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from shared.jsonio import write_stage_summary

DATASET_CSV_FIELDNAMES = [
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


def build_vuln_patch_paths(output_dir: Path) -> dict[str, Path]:
    output_dir = Path(output_dir)
    return {
        'output_dir': output_dir,
        'csv_path': output_dir / 'Real_Vul_data.csv',
        'summary_json': output_dir / 'summary.json',
    }


def testcase_key_from_row(row: dict[str, str]) -> str:
    testcase_key = str(row.get('testcase_key') or '').strip()
    if testcase_key:
        return testcase_key
    source_signature_path = str(row.get('source_signature_path') or '').strip()
    if not source_signature_path:
        return ''
    return Path(source_signature_path).parent.name


def _selected_testcase_payload(
    *,
    testcase_key: str,
    b2b_row: dict[str, str],
    counterpart_row: dict[str, str],
    counterpart_candidates_total: int,
) -> dict[str, Any]:
    return {
        'testcase_key': testcase_key,
        'counterpart_candidates_total': counterpart_candidates_total,
        'selected_b2b_source_signature_path': str(b2b_row.get('source_signature_path') or ''),
        'selected_counterpart_source_signature_path': str(
            counterpart_row.get('source_signature_path') or ''
        ),
    }


def _renumber_row(row: dict[str, str], *, row_id: int) -> dict[str, str]:
    updated = dict(row)
    updated['file_name'] = str(row_id)
    updated['unique_id'] = str(row_id)
    updated['dataset_type'] = 'test'
    return updated


def _build_selection_stats(
    *,
    source_rows_total: int,
    source_testcases_total: int,
    skipped_rows: int,
    selection_counts: Counter[str],
    counterpart_count_distribution: Counter[str],
    selected_testcases: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        'selection_policy': 'first_counterpart_in_existing_csv_order',
        'counts': {
            'source_rows_total': source_rows_total,
            'source_testcases_total': source_testcases_total,
            'rows_skipped_missing_testcase_key': skipped_rows,
            'eligible_testcases': int(selection_counts['eligible_testcases']),
            'rows_written': len(selected_testcases) * 2,
        },
        'ineligible_testcase_reasons': {
            'missing_b2b': int(selection_counts['missing_b2b']),
            'multi_b2b': int(selection_counts['multi_b2b']),
            'counterpart_lt2': int(selection_counts['counterpart_lt2']),
        },
        'counterpart_count_distribution': dict(counterpart_count_distribution),
        'selected_testcases': selected_testcases,
    }


def select_vuln_patch_rows(
    *,
    source_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    rows_by_testcase: dict[str, list[dict[str, Any]]] = defaultdict(list)
    skipped_rows = 0
    for row in source_rows:
        testcase_key = testcase_key_from_row(row)
        if not testcase_key:
            skipped_rows += 1
            continue
        rows_by_testcase[testcase_key].append(row)

    selected_rows: list[dict[str, Any]] = []
    selection_counts = Counter()
    counterpart_count_distribution = Counter()
    selected_testcases: list[dict[str, Any]] = []

    for testcase_key in sorted(rows_by_testcase):
        testcase_rows = rows_by_testcase[testcase_key]
        b2b_rows = [row for row in testcase_rows if str(row.get('target', '')).strip() == '1']
        counterpart_rows = [
            row for row in testcase_rows if str(row.get('target', '')).strip() == '0'
        ]

        if not b2b_rows:
            selection_counts['missing_b2b'] += 1
            continue
        if len(b2b_rows) > 1:
            selection_counts['multi_b2b'] += 1
            continue
        if len(counterpart_rows) < 2:
            selection_counts['counterpart_lt2'] += 1
            continue

        counterpart_count_distribution[str(len(counterpart_rows))] += 1
        selected_b2b = b2b_rows[0]
        selected_counterpart = counterpart_rows[0]
        selected_rows.append(selected_b2b)
        selected_rows.append(selected_counterpart)
        selection_counts['eligible_testcases'] += 1
        selected_testcases.append(
            _selected_testcase_payload(
                testcase_key=testcase_key,
                b2b_row=selected_b2b,
                counterpart_row=selected_counterpart,
                counterpart_candidates_total=len(counterpart_rows),
            )
        )

    stats = _build_selection_stats(
        source_rows_total=len(source_rows),
        source_testcases_total=len(rows_by_testcase),
        skipped_rows=skipped_rows,
        selection_counts=selection_counts,
        counterpart_count_distribution=counterpart_count_distribution,
        selected_testcases=selected_testcases,
    )
    return {
        'selected_rows': selected_rows,
        'selected_testcase_keys': [item['testcase_key'] for item in selected_testcases],
        'stats': stats,
    }


def write_vuln_patch_dataset(
    *,
    rows: list[dict[str, Any]],
    output_dir: Path,
    stats: dict[str, Any],
    fieldnames: list[str] | None = None,
) -> dict[str, Any]:
    paths = build_vuln_patch_paths(output_dir)
    paths['output_dir'].mkdir(parents=True, exist_ok=True)

    output_fieldnames = list(fieldnames or DATASET_CSV_FIELDNAMES)
    with paths['csv_path'].open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=output_fieldnames)
        writer.writeheader()
        for row_id, row in enumerate(rows, start=1):
            writer.writerow(_renumber_row(row, row_id=row_id))

    artifacts = {key: str(value) for key, value in paths.items()}
    write_stage_summary(paths['summary_json'], artifacts=artifacts, stats=stats)
    return {'artifacts': artifacts, 'stats': stats}


def export_vuln_patch_dataset(
    *,
    source_csv_path: Path,
    output_dir: Path,
) -> dict[str, Any]:
    if not source_csv_path.exists():
        raise FileNotFoundError(f'Source dataset CSV not found: {source_csv_path}')

    with source_csv_path.open('r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        if not fieldnames:
            raise ValueError(f'Failed to read CSV header from {source_csv_path}')
        source_rows = list(reader)

    selection = select_vuln_patch_rows(source_rows=source_rows)
    return write_vuln_patch_dataset(
        rows=selection['selected_rows'],
        output_dir=output_dir,
        stats=selection['stats'],
        fieldnames=fieldnames,
    )
