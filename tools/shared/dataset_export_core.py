from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from shared.artifact_layout import DatasetExportPaths
from shared.csvio import write_csv_rows
from shared.dataset_dedup import ROLE_SORT_ORDER, dedupe_pairs_by_normalized_rows
from shared.dataset_normalize import normalize_slice_function_names
from shared.dataset_sources import (
    find_slice_path,
    load_tree_sitter_parsers,
    normalize_artifact_path,
)
from shared.jsonio import write_json, write_summary_json


@dataclass(frozen=True)
class DatasetExportRequest:
    pairs: list[dict[str, Any]]
    paired_signatures_dir: Path
    slice_dir: Path
    export_paths: DatasetExportPaths
    dedup_mode: str
    split_assignments_fn: Callable[[list[str]], dict[str, str]]
    collect_defined_function_names_fn: Callable[
        [Path, dict[str, object]], tuple[set[str], str | None]
    ]
    build_source_file_candidates_fn: Callable[[dict[str, Any], str | None], list[Path]]
    dataset_basename: str | None = None
    prepare_target_fn: Callable[[Path, bool], None] | None = None
    overwrite: bool = False
    minimal_outputs: bool = False


@dataclass
class ExportRuntime:
    tokenizer: object
    parsers: dict[str, object]
    content_token_limit: int
    count_code_tokens_fn: Callable[[object, str], int]
    source_func_cache: dict[str, set[str]] = field(default_factory=dict)
    source_parse_error_cache: dict[str, str] = field(default_factory=dict)
    source_files_seen: set[str] = field(default_factory=set)
    source_files_failed: set[str] = field(default_factory=set)


@dataclass
class ExportAccumulator:
    surviving_pairs: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    filtered_pair_reasons: Counter[str] = field(default_factory=Counter)
    counts: Counter[str] = field(default_factory=Counter)


def _prepare_export_outputs(*, export_paths: DatasetExportPaths) -> None:
    export_paths.csv_path.parent.mkdir(parents=True, exist_ok=True)
    export_paths.normalized_slices_dir.mkdir(parents=True, exist_ok=True)


def run_configured_step07_export(request: DatasetExportRequest) -> dict[str, Any]:
    if not request.paired_signatures_dir.exists():
        raise FileNotFoundError(f'Paired signatures dir not found: {request.paired_signatures_dir}')
    if not request.slice_dir.exists():
        raise FileNotFoundError(f'Slice dir not found: {request.slice_dir}')
    if request.dedup_mode not in {'none', 'row'}:
        raise ValueError(f'Unsupported dedup_mode: {request.dedup_mode}')

    request.export_paths.output_dir.mkdir(parents=True, exist_ok=True)
    if request.prepare_target_fn is not None:
        targets = [
            request.export_paths.csv_path,
            request.export_paths.normalized_slices_dir,
            request.export_paths.split_manifest_json,
        ]
        if not request.minimal_outputs:
            targets.extend(
                [
                    request.export_paths.dedup_dropped_csv,
                    request.export_paths.token_counts_csv,
                    request.export_paths.token_distribution_png,
                    request.export_paths.summary_json,
                ]
            )
        for target in targets:
            request.prepare_target_fn(target, request.overwrite)

    return run_step07_export_core(request)


def _build_role_specs(pair: dict[str, Any]) -> list[dict[str, Any]]:
    output_files = pair.get('output_files') or {}
    counterpart_flow_type = str(pair.get('counterpart_flow_type') or '')
    return [
        {
            'role': 'b2b',
            'role_name': 'b2b',
            'target': 1,
            'signature_info': pair.get('b2b_signature') or {},
            'signature_path_raw': str(output_files.get('b2b') or ''),
        },
        {
            'role': 'counterpart',
            'role_name': counterpart_flow_type,
            'target': 0,
            'signature_info': pair.get('counterpart_signature') or {},
            'signature_path_raw': str(output_files.get(counterpart_flow_type) or ''),
        },
    ]


def _load_signature_payload(signature_path: Path) -> dict[str, Any]:
    return json.loads(signature_path.read_text(encoding='utf-8'))


def _collect_user_defined_function_names(
    *,
    source_candidates: list[Path],
    request: DatasetExportRequest,
    runtime: ExportRuntime,
) -> set[str]:
    user_defined_function_names: set[str] = set()
    for source_path in source_candidates:
        source_key = str(source_path)
        if source_path.exists():
            runtime.source_files_seen.add(source_key)
        if source_key not in runtime.source_func_cache:
            if source_path.exists():
                names, error = request.collect_defined_function_names_fn(
                    source_path, runtime.parsers
                )
            else:
                names, error = set(), 'missing_source_file'
            runtime.source_func_cache[source_key] = names
            if error is not None:
                runtime.source_parse_error_cache[source_key] = error
                if source_path.exists():
                    runtime.source_files_failed.add(source_key)
        user_defined_function_names.update(runtime.source_func_cache[source_key])
    return user_defined_function_names


def _build_pair_role_record(
    *,
    pair_id: str,
    testcase_key: str,
    role: dict[str, Any],
    request: DatasetExportRequest,
    runtime: ExportRuntime,
) -> tuple[dict[str, Any] | None, str | None]:
    role_name = str(role['role_name'])
    if not role_name:
        return None, 'missing_role_name'

    signature_path_raw = str(role['signature_path_raw'])
    if not signature_path_raw:
        return None, 'missing_signature_path'

    signature_path = Path(signature_path_raw)
    if not signature_path.exists():
        return None, 'missing_signature_file'

    slice_path = find_slice_path(request.slice_dir, testcase_key, role_name)
    if slice_path is None:
        return None, 'missing_slice_file'

    signature_payload = _load_signature_payload(signature_path)
    primary_file_hint = role['signature_info'].get('primary_file')
    source_candidates = request.build_source_file_candidates_fn(
        signature_payload, primary_file_hint
    )
    user_defined_function_names = _collect_user_defined_function_names(
        source_candidates=source_candidates,
        request=request,
        runtime=runtime,
    )

    original_code = slice_path.read_text(encoding='utf-8', errors='replace')
    normalized_code, _, _ = normalize_slice_function_names(
        original_code,
        user_defined_function_names,
    )
    token_count = runtime.count_code_tokens_fn(runtime.tokenizer, normalized_code)
    exceeds_limit = token_count > runtime.content_token_limit
    input_token_count = min(token_count, runtime.content_token_limit) + 2

    return {
        'pair_id': pair_id,
        'testcase_key': testcase_key,
        'role': str(role['role']),
        'role_name': role_name,
        'target': int(role['target']),
        'slice_filename': slice_path.name,
        'extension': slice_path.suffix.lower(),
        'slice_path': str(slice_path),
        'signature_path': str(signature_path),
        'source_signature_path': normalize_artifact_path(signature_path),
        'normalized_code': normalized_code,
        'code_token_count': token_count,
        'input_token_count_with_special': input_token_count,
        'exceeds_510': exceeds_limit,
    }, None


def _validate_pair_records(pair_records: list[dict[str, Any]]) -> str | None:
    if len(pair_records) != 2:
        return 'invalid_pair_cardinality'
    if any(record['exceeds_510'] for record in pair_records):
        return 'over_limit'
    return None


def _collect_surviving_pairs(
    request: DatasetExportRequest,
    runtime: ExportRuntime,
) -> ExportAccumulator:
    accumulator = ExportAccumulator(counts=Counter({'pairs_total': len(request.pairs)}))

    for pair in request.pairs:
        pair_id = str(pair['pair_id'])
        testcase_key = str(pair['testcase_key'])
        roles = _build_role_specs(pair)

        pair_records: list[dict[str, Any]] = []
        pair_invalid_reason: str | None = None
        for role in roles:
            record, pair_invalid_reason = _build_pair_role_record(
                pair_id=pair_id,
                testcase_key=testcase_key,
                role=role,
                request=request,
                runtime=runtime,
            )
            if pair_invalid_reason is not None:
                break
            assert record is not None
            pair_records.append(record)

        if pair_invalid_reason is None:
            pair_invalid_reason = _validate_pair_records(pair_records)

        if pair_invalid_reason is not None:
            accumulator.filtered_pair_reasons[pair_invalid_reason] += 1
            continue

        accumulator.surviving_pairs[pair_id] = pair_records

    return accumulator


def _write_token_counts_csv(token_count_rows: list[dict[str, Any]], token_counts_csv: Path) -> None:
    write_csv_rows(
        token_counts_csv,
        [
            'pair_id',
            'filename',
            'extension',
            'role',
            'code_token_count',
            'input_token_count_with_special',
            'exceeds_510',
        ],
        (
            [
                row['pair_id'],
                row['slice_filename'],
                row['extension'],
                row['role'],
                row['code_token_count'],
                row['input_token_count_with_special'],
                row['exceeds_510'],
            ]
            for row in token_count_rows
        ),
    )


def _build_ordered_rows(
    surviving_pairs: dict[str, list[dict[str, Any]]],
    split_assignments: dict[str, str],
) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    dataset_type_order = [
        label for label in ('train_val', 'test') if label in split_assignments.values()
    ]
    dataset_type_order.extend(
        sorted(
            label for label in set(split_assignments.values()) if label not in {'train_val', 'test'}
        )
    )

    ordered_rows: list[dict[str, Any]] = []
    pair_ids_by_dataset_type: dict[str, list[str]] = {}
    for dataset_type in dataset_type_order:
        pair_ids = sorted(
            pair_id
            for pair_id, value in split_assignments.items()
            if value == dataset_type and pair_id in surviving_pairs
        )
        pair_ids_by_dataset_type[dataset_type] = pair_ids
        for pair_id in pair_ids:
            pair_records = sorted(
                surviving_pairs[pair_id],
                key=lambda row: ROLE_SORT_ORDER.get(str(row['role']), 99),
            )
            for row in pair_records:
                row_with_split = dict(row)
                row_with_split['dataset_type'] = dataset_type
                ordered_rows.append(row_with_split)

    return ordered_rows, pair_ids_by_dataset_type


def _write_dataset_csv_and_slices(
    ordered_rows: list[dict[str, Any]],
    csv_path: Path,
    normalized_slices_dir: Path,
) -> dict[tuple[str, str], int]:
    kept_unique_id_by_pair_role: dict[tuple[str, str], int] = {}
    rows: list[list[Any]] = []
    for idx, row in enumerate(ordered_rows, start=1):
        output_filename = f'{idx}{row["extension"]}'
        (normalized_slices_dir / output_filename).write_text(
            row['normalized_code'], encoding='utf-8'
        )
        vulnerable_line_numbers = 1 if int(row['target']) == 1 else ''
        kept_unique_id_by_pair_role[(str(row['pair_id']), str(row['role']))] = idx
        rows.append(
            [
                idx,
                idx,
                row['target'],
                vulnerable_line_numbers,
                'Juliet',
                row['source_signature_path'],
                '',
                row['dataset_type'],
                row['normalized_code'],
            ]
        )
    write_csv_rows(
        csv_path,
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
        rows,
    )

    return kept_unique_id_by_pair_role


def _write_dedup_audit_csv(dedup_audit_rows: list[dict[str, Any]], dedup_dropped_csv: Path) -> None:
    write_csv_rows(
        dedup_dropped_csv,
        [
            'dropped_row_id',
            'pair_id',
            'testcase_key',
            'role',
            'role_name',
            'target',
            'project',
            'source_signature_path',
            'normalized_code_hash',
            'dedup_reason',
            'dedup_trigger_hashes',
            'matched_kept_pair_id',
            'matched_kept_role',
            'matched_kept_source_signature_path',
            'matched_kept_unique_id',
            'processed_func',
        ],
        (
            [
                dropped_row_id,
                row['pair_id'],
                row['testcase_key'],
                row['role'],
                row['role_name'],
                row['target'],
                row['project'],
                row['source_signature_path'],
                row['normalized_code_hash'],
                row['dedup_reason'],
                row['dedup_trigger_hashes'],
                row['matched_kept_pair_id'],
                row['matched_kept_role'],
                row['matched_kept_source_signature_path'],
                row['matched_kept_unique_id'],
                row['processed_func'],
            ]
            for dropped_row_id, row in enumerate(dedup_audit_rows, start=1)
        ),
    )


def _apply_dedup(
    accumulator: ExportAccumulator,
    *,
    dedup_mode: str,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any], list[dict[str, Any]]]:
    return dedupe_pairs_by_normalized_rows(
        surviving_pairs=accumulator.surviving_pairs,
        filtered_pair_reasons=accumulator.filtered_pair_reasons,
        dedup_mode=dedup_mode,
    )


def _write_export_artifacts(
    *,
    request: DatasetExportRequest,
    surviving_pairs: dict[str, list[dict[str, Any]]],
    dedup_audit_rows: list[dict[str, Any]],
    plot_distribution_fn: Callable[[list[dict[str, Any]], Path], None],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, list[str]]]:
    token_count_rows = sorted(
        [row for pair_records in surviving_pairs.values() for row in pair_records],
        key=lambda row: (
            row['pair_id'],
            ROLE_SORT_ORDER.get(str(row['role']), 99),
            row['slice_filename'],
        ),
    )
    if not request.minimal_outputs:
        _write_token_counts_csv(token_count_rows, request.export_paths.token_counts_csv)
        plot_distribution_fn(token_count_rows, request.export_paths.token_distribution_png)

    split_assignments = request.split_assignments_fn(list(surviving_pairs.keys()))
    ordered_rows, pair_ids_by_dataset_type = _build_ordered_rows(surviving_pairs, split_assignments)
    kept_unique_id_by_pair_role = _write_dataset_csv_and_slices(
        ordered_rows,
        request.export_paths.csv_path,
        request.export_paths.normalized_slices_dir,
    )

    for audit_row in dedup_audit_rows:
        matched_pair_id = str(audit_row.get('matched_kept_pair_id') or '')
        matched_role = str(audit_row.get('matched_kept_role') or '')
        if matched_pair_id and matched_role:
            audit_row['matched_kept_unique_id'] = str(
                kept_unique_id_by_pair_role.get((matched_pair_id, matched_role), '')
            )

    if not request.minimal_outputs:
        _write_dedup_audit_csv(dedup_audit_rows, request.export_paths.dedup_dropped_csv)
    return token_count_rows, ordered_rows, pair_ids_by_dataset_type


def _build_split_manifest(
    pair_ids_by_dataset_type: dict[str, list[str]],
    *,
    surviving_pairs_total: int,
) -> dict[str, Any]:
    return {
        'counts': {
            'pairs_total': surviving_pairs_total,
            'train_val': len(pair_ids_by_dataset_type.get('train_val', [])),
            'test': len(pair_ids_by_dataset_type.get('test', [])),
        },
        'pair_ids': {
            'train_val': pair_ids_by_dataset_type.get('train_val', []),
            'test': pair_ids_by_dataset_type.get('test', []),
        },
    }


def _build_summary_payload(
    *,
    request: DatasetExportRequest,
    runtime: ExportRuntime,
    accumulator: ExportAccumulator,
    dedup_summary: dict[str, Any],
    surviving_pairs: dict[str, list[dict[str, Any]]],
    pair_ids_by_dataset_type: dict[str, list[str]],
    ordered_rows: list[dict[str, Any]],
    token_count_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    token_values = [int(row['code_token_count']) for row in token_count_rows]
    mean_value = (sum(token_values) / len(token_values)) if token_values else 0.0
    sorted_values = sorted(token_values)
    median_value = sorted_values[len(sorted_values) // 2] if sorted_values else 0

    summary_payload: dict[str, Any] = {}
    if request.dataset_basename is not None:
        summary_payload['dataset_basename'] = request.dataset_basename
    summary_payload.update(
        {
            'dedup': dedup_summary,
            'token_stats': {
                'total': len(token_values),
                'mean': round(mean_value, 6),
                'median': median_value,
                'over_limit_count': sum(
                    1 for value in token_values if value > runtime.content_token_limit
                ),
            },
            'filtered_pair_reasons': dict(accumulator.filtered_pair_reasons),
            'counts': {
                'pairs_total': int(accumulator.counts['pairs_total']),
                'pairs_survived': len(surviving_pairs),
                'pairs_filtered_out': sum(accumulator.filtered_pair_reasons.values()),
                'rows_written': len(ordered_rows),
                'train_val_pairs': len(pair_ids_by_dataset_type.get('train_val', [])),
                'test_pairs': len(pair_ids_by_dataset_type.get('test', [])),
            },
        }
    )
    return summary_payload


def run_step07_export_core(request: DatasetExportRequest) -> dict[str, Any]:
    from shared.slice_tokenizer import (
        CONTENT_TOKEN_LIMIT,
        count_code_tokens,
        load_tokenizer,
        plot_distribution,
    )

    _prepare_export_outputs(export_paths=request.export_paths)

    print('Loading tokenizer for normalized slices...')
    runtime = ExportRuntime(
        tokenizer=load_tokenizer('microsoft/codebert-base'),
        parsers=load_tree_sitter_parsers(),
        content_token_limit=CONTENT_TOKEN_LIMIT,
        count_code_tokens_fn=count_code_tokens,
    )

    accumulator = _collect_surviving_pairs(request, runtime)
    surviving_pairs, dedup_summary, dedup_audit_rows = _apply_dedup(
        accumulator,
        dedup_mode=request.dedup_mode,
    )
    token_count_rows, ordered_rows, pair_ids_by_dataset_type = _write_export_artifacts(
        request=request,
        surviving_pairs=surviving_pairs,
        dedup_audit_rows=dedup_audit_rows,
        plot_distribution_fn=plot_distribution,
    )

    split_manifest = _build_split_manifest(
        pair_ids_by_dataset_type,
        surviving_pairs_total=len(surviving_pairs),
    )
    counts = {
        'pairs_total': int(accumulator.counts['pairs_total']),
        'pairs_survived': len(surviving_pairs),
        'pairs_filtered_out': sum(accumulator.filtered_pair_reasons.values()),
        'rows_written': len(ordered_rows),
        'train_val_pairs': len(pair_ids_by_dataset_type.get('train_val', [])),
        'test_pairs': len(pair_ids_by_dataset_type.get('test', [])),
    }

    write_json(request.export_paths.split_manifest_json, split_manifest)
    if not request.minimal_outputs:
        summary_payload = _build_summary_payload(
            request=request,
            runtime=runtime,
            accumulator=accumulator,
            dedup_summary=dedup_summary,
            surviving_pairs=surviving_pairs,
            pair_ids_by_dataset_type=pair_ids_by_dataset_type,
            ordered_rows=ordered_rows,
            token_count_rows=token_count_rows,
        )
        write_summary_json(request.export_paths.summary_json, summary_payload)
    dataset_fields = ('output_dir', 'csv_path', 'normalized_slices_dir', 'split_manifest_json')
    if not request.minimal_outputs:
        dataset_fields = (
            'output_dir',
            'csv_path',
            'dedup_dropped_csv',
            'normalized_slices_dir',
            'token_counts_csv',
            'token_distribution_png',
            'split_manifest_json',
            'summary_json',
        )
    return {
        'dataset': request.export_paths.to_payload(include=dataset_fields),
        'counts': counts,
    }
