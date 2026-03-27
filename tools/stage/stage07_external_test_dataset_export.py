from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from shared.artifact_layout import build_dataset_export_paths, path_strings
from shared.csvio import write_csv_rows
from shared.dataset_sources import load_tree_sitter_parsers
from shared.external_inputs import normalize_source_path
from shared.jsonio import load_jsonl, write_jsonl, write_stage_summary
from shared.traces import extract_std_bug_trace

from stage import stage07_trace_dataset_export as _stage07_trace_dataset_export
from stage.stage07c_vuln_patch_export import DATASET_CSV_FIELDNAMES


def build_external_dataset_export_paths(output_dir: Path) -> dict[str, Path]:
    export_paths = build_dataset_export_paths(output_dir)
    return {
        **export_paths,
        'trace_row_manifest_jsonl': output_dir / 'trace_row_manifest.jsonl',
    }


def _load_trace_rows(path: Path) -> list[dict[str, Any]]:
    rows = load_jsonl(path)
    for lineno, row in enumerate(rows, start=1):
        if not row.get('trace_id') or not row.get('trace_file'):
            raise ValueError(f'Missing trace_id/trace_file at line {lineno} in {path}')
    return rows


def _unique_bug_trace_points(
    payload: dict[str, Any],
    *,
    source_root: Path,
) -> list[tuple[str, int]]:
    points: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for node in extract_std_bug_trace(payload.get('bug_trace', [])):
        file_path = normalize_source_path(node.get('filename') or '', source_root=source_root)
        line_number = int(node.get('line_number', 0) or 0)
        point = (file_path, line_number)
        if not file_path or line_number <= 0 or point in seen:
            continue
        points.append(point)
        seen.add(point)
    return points


def _matched_slice_line_numbers(
    *,
    payload: dict[str, Any],
    matched_source_lines: list[dict[str, Any]],
    source_root: Path,
) -> list[int]:
    point_to_line_index = {
        point: index
        for index, point in enumerate(
            _unique_bug_trace_points(payload, source_root=source_root),
            start=1,
        )
    }
    line_numbers: list[int] = []
    for matched in matched_source_lines:
        file_path = normalize_source_path(matched.get('file_path') or '', source_root=source_root)
        source_line = int(matched.get('line_number', 0) or 0)
        mapped = point_to_line_index.get((file_path, source_line))
        if mapped is None or mapped in line_numbers:
            continue
        line_numbers.append(mapped)
    return sorted(line_numbers)


def _dataset_csv_row(
    *,
    row_id: int,
    project_name: str,
    source_signature_path: str,
    vulnerable_line_numbers: list[int],
    processed_func: str,
) -> list[Any]:
    return [
        row_id,
        row_id,
        1,
        ','.join(str(line_number) for line_number in vulnerable_line_numbers),
        project_name,
        source_signature_path,
        '',
        'test',
        processed_func,
    ]


def export_external_test_dataset(
    *,
    traces_jsonl: Path,
    slice_dir: Path,
    output_dir: Path,
    source_root: Path,
    project_name: str,
) -> dict[str, Any]:
    from shared.slice_tokenizer import load_tokenizer

    if not traces_jsonl.exists():
        raise FileNotFoundError(f'Trace JSONL not found: {traces_jsonl}')
    if not slice_dir.exists():
        raise FileNotFoundError(f'Slice dir not found: {slice_dir}')
    if not source_root.exists():
        raise FileNotFoundError(f'Source root not found: {source_root}')

    trace_rows = _load_trace_rows(traces_jsonl)
    output_paths = build_external_dataset_export_paths(output_dir)
    output_paths['output_dir'].mkdir(parents=True, exist_ok=True)
    output_paths['normalized_slices_dir'].mkdir(parents=True, exist_ok=True)

    runtime = {
        'tokenizer': load_tokenizer('microsoft/codebert-base'),
        'parsers': load_tree_sitter_parsers(),
        'source_inventory_cache': {},
    }

    candidate_rows: list[dict[str, Any]] = []
    filtered_reasons = Counter({'traces_total': len(trace_rows)})

    for trace_row in trace_rows:
        record, reason = _stage07_trace_dataset_export._candidate_record(
            trace_row=trace_row,
            slice_dir=slice_dir,
            runtime=runtime,
        )
        if reason is not None:
            filtered_reasons[reason] += 1
            continue
        assert record is not None
        payload = json.loads(Path(trace_row['trace_file']).read_text(encoding='utf-8'))
        matched_source_lines = list(trace_row.get('matched_source_lines') or [])
        matched_slice_line_numbers = _matched_slice_line_numbers(
            payload=payload,
            matched_source_lines=matched_source_lines,
            source_root=source_root,
        )
        row = dict(record)
        row['matched_source_lines'] = matched_source_lines
        row['matched_slice_line_numbers'] = matched_slice_line_numbers
        row['matched_primary_only'] = bool(trace_row.get('matched_primary_only'))
        candidate_rows.append(row)

    ordered_rows = sorted(
        candidate_rows,
        key=lambda row: (
            str(row.get('testcase_key') or ''),
            str(row.get('trace_id') or ''),
        ),
    )

    manifest_rows: list[dict[str, Any]] = []
    csv_rows: list[list[Any]] = []
    for row_id, row in enumerate(ordered_rows, start=1):
        output_filename = f'{row_id}{row["extension"]}'
        (output_paths['normalized_slices_dir'] / output_filename).write_text(
            str(row['normalized_code']),
            encoding='utf-8',
        )
        csv_rows.append(
            _dataset_csv_row(
                row_id=row_id,
                project_name=project_name,
                source_signature_path=str(row['source_signature_path']),
                vulnerable_line_numbers=list(row['matched_slice_line_numbers']),
                processed_func=str(row['normalized_code']),
            )
        )
        manifest_rows.append(
            {
                'row_id': row_id,
                'trace_id': str(row['trace_id']),
                'testcase_key': str(row['testcase_key']),
                'trace_file': str(row['trace_file']),
                'source_signature_path': str(row['source_signature_path']),
                'matched_source_lines': list(row['matched_source_lines']),
                'matched_slice_line_numbers': list(row['matched_slice_line_numbers']),
                'matched_primary_only': bool(row['matched_primary_only']),
            }
        )

    write_csv_rows(output_paths['csv_path'], DATASET_CSV_FIELDNAMES, csv_rows)
    write_jsonl(output_paths['trace_row_manifest_jsonl'], manifest_rows)

    artifacts = path_strings(output_paths)
    stats = {
        'mode': 'external_test_only',
        'counts': {
            'traces_total': len(trace_rows),
            'candidate_rows': len(candidate_rows),
            'rows_written': len(csv_rows),
            'rows_with_slice_line_hits': sum(
                1 for row in ordered_rows if row['matched_slice_line_numbers']
            ),
            'rows_without_slice_line_hits': sum(
                1 for row in ordered_rows if not row['matched_slice_line_numbers']
            ),
        },
        'filtered_trace_reasons': {
            key: value for key, value in filtered_reasons.items() if key != 'traces_total'
        },
    }
    write_stage_summary(output_paths['summary_json'], artifacts=artifacts, stats=stats, echo=False)
    return {'artifacts': artifacts, 'stats': stats}
