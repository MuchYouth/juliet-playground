from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from shared import slicing as _slicing
from shared.artifact_layout import build_slice_stage_paths, path_strings
from shared.fs import prepare_output_dir
from shared.jsonio import load_jsonl, write_stage_summary
from shared.traces import extract_std_bug_trace


def validate_args(traces_jsonl: Path) -> None:
    if not traces_jsonl.exists():
        raise FileNotFoundError(f'Trace dataset JSONL not found: {traces_jsonl}')
    if not traces_jsonl.is_file():
        raise FileNotFoundError(f'Trace dataset JSONL is not a file: {traces_jsonl}')


read_source_line = _slicing.read_source_line
classify_suffix = _slicing.classify_suffix


def guess_output_suffix(data: dict[str, Any], std_bug_trace: list[dict[str, Any]]) -> str:
    return _slicing.guess_output_suffix(data, std_bug_trace)


def build_slice(std_bug_trace: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    return _slicing.build_slice(std_bug_trace)


def generate_trace_slices(
    *,
    traces_jsonl: Path,
    output_dir: Path,
    overwrite: bool = False,
) -> dict[str, Any]:
    import json

    validate_args(traces_jsonl)
    prepare_output_dir(output_dir, overwrite)

    paths = build_slice_stage_paths(output_dir)
    slice_dir = paths['slice_dir']
    slice_dir.mkdir(parents=True, exist_ok=True)

    counters = Counter()
    trace_rows = load_jsonl(traces_jsonl)
    for row in trace_rows:
        counters['trace_rows_total'] += 1
        trace_id = str(row.get('trace_id') or '').strip()
        trace_file_raw = str(row.get('trace_file') or '').strip()
        if not trace_id or not trace_file_raw:
            counters['skipped_missing_trace_fields'] += 1
            continue

        trace_file = Path(trace_file_raw)
        if not trace_file.exists():
            counters['skipped_missing_trace_file'] += 1
            continue

        try:
            payload = json.loads(trace_file.read_text(encoding='utf-8'))
        except Exception:
            counters['errors'] += 1
            continue

        std_bug_trace = extract_std_bug_trace(payload.get('bug_trace', []))
        if not std_bug_trace:
            counters['skipped_empty_bug_trace'] += 1
            continue

        slice_content, reason = build_slice(std_bug_trace)
        if slice_content is None:
            counters[f'skipped_{reason}'] += 1
            continue

        suffix = guess_output_suffix(payload, std_bug_trace)
        output_path = slice_dir / f'slice_{trace_id}{suffix}'
        output_path.write_text(slice_content, encoding='utf-8')
        counters['generated'] += 1

    artifacts = path_strings(paths)
    stats = {
        'traces_total': len(trace_rows),
        'generated': int(counters['generated']),
        'skipped': sum(value for key, value in counters.items() if key.startswith('skipped_')),
        'errors': int(counters['errors']),
        'counts': dict(counters),
    }
    write_stage_summary(paths['summary_json'], artifacts=artifacts, stats=stats)
    return {'artifacts': artifacts, 'stats': stats}
