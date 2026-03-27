from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from shared.artifact_layout import build_trace_dataset_paths, path_strings
from shared.external_inputs import (
    ManualLineRecord,
    load_manual_line_truth_csv,
    normalize_source_path,
)
from shared.jsonio import write_jsonl, write_stage_summary
from shared.signatures import load_signature_payload
from shared.traces import extract_std_bug_trace

from stage.stage05_trace_dataset import make_trace_id


def build_manual_line_filter_paths(output_dir: Path) -> dict[str, Path]:
    trace_paths = build_trace_dataset_paths(output_dir)
    return {
        **trace_paths,
        'normalized_manual_lines_jsonl': output_dir / 'normalized_manual_lines.jsonl',
        'dropped_traces_jsonl': output_dir / 'dropped_traces.jsonl',
    }


def _manual_line_index(
    records: list[ManualLineRecord],
) -> dict[str, set[tuple[str, int]]]:
    index: dict[str, set[tuple[str, int]]] = defaultdict(set)
    for record in records:
        if record.label != 'vuln':
            continue
        index[record.testcase_key].add((record.file_path, record.line_number))
    return index


def _manual_line_rows(records: list[ManualLineRecord]) -> list[dict[str, Any]]:
    return [
        {
            'testcase_key': record.testcase_key,
            'file_path': record.file_path,
            'line_number': record.line_number,
            'label': record.label,
            'note': record.note,
        }
        for record in sorted(
            records,
            key=lambda record: (
                record.testcase_key,
                record.file_path,
                record.line_number,
                record.label,
                record.note,
            ),
        )
    ]


def _payload_trace_points(
    payload: dict[str, Any],
    *,
    source_root: Path,
) -> tuple[list[tuple[str, int]], tuple[str, int] | None]:
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

    primary_file = normalize_source_path(payload.get('file') or '', source_root=source_root)
    primary_line = int(payload.get('line', 0) or 0)
    if not primary_file or primary_line <= 0:
        return points, None
    return points, (primary_file, primary_line)


def filter_traces_by_manual_lines(
    *,
    signatures_dir: Path,
    manual_line_truth_csv: Path,
    source_root: Path,
    output_dir: Path,
    overwrite: bool = False,
) -> dict[str, Any]:
    from shared.fs import prepare_output_dir
    from shared.strict_trace import StrictTraceRecord

    if not signatures_dir.exists():
        raise FileNotFoundError(f'Signature dir not found: {signatures_dir}')
    if not source_root.exists():
        raise FileNotFoundError(f'Source root not found: {source_root}')

    prepare_output_dir(output_dir, overwrite)
    paths = build_manual_line_filter_paths(output_dir)
    manual_records = load_manual_line_truth_csv(manual_line_truth_csv, source_root=source_root)
    manual_index = _manual_line_index(manual_records)

    kept_rows: list[dict[str, Any]] = []
    dropped_rows: list[dict[str, Any]] = []
    counters = Counter()

    for testcase_dir in sorted(path for path in signatures_dir.iterdir() if path.is_dir()):
        testcase_key = testcase_dir.name
        if testcase_key == 'analysis':
            continue
        candidate_lines = manual_index.get(testcase_key, set())
        if not candidate_lines:
            counters['testcases_without_manual_truth'] += 1

        for trace_file in sorted(testcase_dir.glob('*.json')):
            counters['traces_total'] += 1
            payload = load_signature_payload(trace_file)
            bug_trace_points, primary_point = _payload_trace_points(
                payload, source_root=source_root
            )
            matched_points = [point for point in bug_trace_points if point in candidate_lines]
            matched_primary_only = (
                primary_point is not None
                and primary_point in candidate_lines
                and primary_point not in matched_points
            )
            if not matched_points and not matched_primary_only:
                counters['traces_dropped_no_manual_line_hit'] += 1
                dropped_rows.append(
                    {
                        'testcase_key': testcase_key,
                        'trace_file': str(trace_file),
                        'drop_reason': 'no_manual_line_hit',
                    }
                )
                continue

            record = StrictTraceRecord(
                testcase_key=testcase_key,
                trace_file=trace_file,
                best_flow_type='b2b',
                bug_trace_length=len(extract_std_bug_trace(payload.get('bug_trace', []))),
                procedure=payload.get('procedure'),
            )
            trace_id = make_trace_id(record, payload)
            matched_source_lines = [
                {'file_path': file_path, 'line_number': line_number}
                for file_path, line_number in matched_points
            ]
            if matched_primary_only and primary_point is not None:
                matched_source_lines.append(
                    {'file_path': primary_point[0], 'line_number': primary_point[1]}
                )

            kept_rows.append(
                {
                    'trace_id': trace_id,
                    'testcase_key': testcase_key,
                    'best_flow_type': 'b2b',
                    'target': 1,
                    'trace_file': str(trace_file),
                    'bug_trace_length': len(extract_std_bug_trace(payload.get('bug_trace', []))),
                    'procedure': payload.get('procedure'),
                    'matched_source_lines': matched_source_lines,
                    'matched_primary_only': matched_primary_only,
                }
            )
            counters['traces_kept'] += 1
            if matched_primary_only and not matched_points:
                counters['traces_kept_primary_only'] += 1
            else:
                counters['traces_kept_bug_trace_hit'] += 1

    write_jsonl(paths['traces_jsonl'], kept_rows)
    write_jsonl(paths['normalized_manual_lines_jsonl'], _manual_line_rows(manual_records))
    write_jsonl(paths['dropped_traces_jsonl'], dropped_rows)

    artifacts = path_strings(paths)
    stats = {
        'manual_lines_total': len(manual_records),
        'testcases_with_manual_truth': len(manual_index),
        'traces_total': int(counters['traces_total']),
        'traces_kept': int(counters['traces_kept']),
        'traces_dropped_no_manual_line_hit': int(counters['traces_dropped_no_manual_line_hit']),
        'traces_kept_bug_trace_hit': int(counters['traces_kept_bug_trace_hit']),
        'traces_kept_primary_only': int(counters['traces_kept_primary_only']),
        'testcases_without_manual_truth': int(counters['testcases_without_manual_truth']),
    }
    write_stage_summary(paths['summary_json'], artifacts=artifacts, stats=stats, echo=False)
    return {'artifacts': artifacts, 'stats': stats}
