"""
Signature-style JSON 디렉터리로부터 bug_trace를 읽어 슬라이스 파일을 생성한다.

기본 동작:
- --signature-db-dir 미지정 시 최신 pipeline run의
  05_pair_trace_ds/paired_signatures 를 사용
- --output-dir 미지정 시 같은 run 아래 06_slices/ 를 사용
- 생성된 슬라이스는 <output-dir>/slice/ 아래 저장
- bug_trace 가 list[dict] 이면 그대로 사용
- bug_trace 가 jagged list[list[dict]] 이면 가장 긴 서브트레이스를 사용
- 출력 확장자는 trace/source path 기준으로 .c 또는 .cpp 로 유지
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from shared import slicing as _slicing
from shared.artifact_layout import build_slice_stage_paths, path_strings
from shared.fs import prepare_output_dir
from shared.jsonio import write_stage_summary
from shared.traces import extract_std_bug_trace


def validate_args(signature_db_dir: Path) -> None:
    if not signature_db_dir.exists():
        raise FileNotFoundError(f'Signature DB dir not found: {signature_db_dir}')
    if not signature_db_dir.is_dir():
        raise NotADirectoryError(f'Signature DB dir is not a directory: {signature_db_dir}')


read_source_line = _slicing.read_source_line
classify_suffix = _slicing.classify_suffix


def guess_output_suffix(data: dict[str, Any], std_bug_trace: list[dict[str, Any]]) -> str:
    return _slicing.guess_output_suffix(
        data,
        std_bug_trace,
        extra_candidates=[data.get('primary_file')],
    )


def build_slice(std_bug_trace: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    return _slicing.build_slice(std_bug_trace)


def process_signature_db(signature_db_dir: Path, slice_dir: Path) -> dict[str, Any]:
    slice_dir.mkdir(parents=True, exist_ok=True)

    testcase_dirs = sorted(
        directory for directory in signature_db_dir.iterdir() if directory.is_dir()
    )
    total_slices = 0
    counters = Counter()

    for testcase_dir in testcase_dirs:
        counters['testcase_dirs_total'] += 1
        json_files = sorted(
            path for path in testcase_dir.iterdir() if path.is_file() and path.suffix == '.json'
        )
        for json_path in json_files:
            counters['json_files_total'] += 1
            try:
                data = json.loads(json_path.read_text(encoding='utf-8'))
                std_bug_trace = extract_std_bug_trace(data.get('bug_trace', []))
                if not std_bug_trace:
                    counters['skipped_empty_bug_trace'] += 1
                    continue

                slice_content, skip_reason = build_slice(std_bug_trace)
                if slice_content is None:
                    counters[f'skipped_{skip_reason}'] += 1
                    continue

                suffix = guess_output_suffix(data, std_bug_trace)
                output_filename = f'slice_{testcase_dir.name}_{json_path.stem}{suffix}'
                (slice_dir / output_filename).write_text(slice_content, encoding='utf-8')
                total_slices += 1
                counters['generated'] += 1
            except Exception as exc:
                print(f'[ERROR] {json_path}: {exc}')
                counters['errors'] += 1

    skipped = sum(value for key, value in counters.items() if key.startswith('skipped_'))
    return {
        'total_slices': total_slices,
        'generated': int(counters['generated']),
        'skipped': skipped,
        'errors': int(counters['errors']),
        'counts': dict(counters),
    }


def generate_slices(
    *,
    signature_db_dir: Path,
    output_dir: Path,
    overwrite: bool = False,
    run_dir: Path | None = None,
    dataset_basename: str | None = None,
) -> dict[str, Any]:
    del run_dir, dataset_basename
    validate_args(signature_db_dir)
    prepare_output_dir(output_dir, overwrite)

    paths = build_slice_stage_paths(output_dir)
    stats = process_signature_db(
        signature_db_dir=signature_db_dir,
        slice_dir=paths['slice_dir'],
    )
    artifacts = path_strings(paths)
    write_stage_summary(paths['summary_json'], artifacts=artifacts, stats=stats)
    return {'artifacts': artifacts, 'stats': stats}
