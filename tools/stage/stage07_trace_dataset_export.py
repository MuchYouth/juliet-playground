#!/usr/bin/env python3
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from shared.artifact_layout import build_dataset_export_paths, path_strings
from shared.csvio import write_csv_rows
from shared.dataset_normalize import normalize_slice_function_names, normalized_code_md5
from shared.dataset_sources import (
    build_source_file_candidates,
    collect_defined_function_names,
    load_tree_sitter_parsers,
    normalize_artifact_path,
)
from shared.jsonio import load_jsonl, write_json, write_jsonl, write_stage_summary
from shared.pairing import build_trace_priority_key
from shared.signatures import stable_trace_ref

from stage import stage07c_vuln_patch_export as _stage07c_vuln_patch_export

DATASET_CSV_FIELDNAMES = _stage07c_vuln_patch_export.DATASET_CSV_FIELDNAMES


def load_traces_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = load_jsonl(path)
    for lineno, row in enumerate(rows, start=1):
        if not row.get('trace_id') or not row.get('testcase_key'):
            raise ValueError(f'Missing trace_id/testcase_key at line {lineno} in {path}')
    return rows


def compute_testcase_split(
    testcase_keys: list[str],
    *,
    train_ratio: float,
    seed: int,
) -> dict[str, str]:
    import random

    keys = sorted(set(testcase_keys))
    shuffled = list(keys)
    random.Random(seed).shuffle(shuffled)

    test_ratio = 1.0 - train_ratio
    test_count = int(round(len(shuffled) * test_ratio))
    if len(shuffled) > 1:
        test_count = max(1, min(len(shuffled) - 1, test_count))
    else:
        test_count = 0

    test_keys = set(shuffled[:test_count])
    return {
        testcase_key: ('test' if testcase_key in test_keys else 'train_val')
        for testcase_key in shuffled
    }


def find_trace_slice_path(slice_dir: Path, trace_id: str) -> Path | None:
    candidates = [slice_dir / f'slice_{trace_id}.c', slice_dir / f'slice_{trace_id}.cpp']
    existing = [path for path in candidates if path.exists()]
    if len(existing) > 1:
        raise RuntimeError(f'Multiple slice candidates found for trace_id={trace_id}: {existing}')
    return existing[0] if existing else None


def _candidate_record(
    *,
    trace_row: dict[str, Any],
    slice_dir: Path,
    runtime: dict[str, Any],
) -> tuple[dict[str, Any] | None, str | None]:
    from shared.slice_tokenizer import CONTENT_TOKEN_LIMIT, count_code_tokens

    trace_id = str(trace_row.get('trace_id') or '')
    testcase_key = str(trace_row.get('testcase_key') or '')
    trace_file_raw = str(trace_row.get('trace_file') or '')
    if not trace_id or not testcase_key or not trace_file_raw:
        return None, 'missing_trace_fields'

    trace_file = Path(trace_file_raw)
    if not trace_file.exists():
        return None, 'missing_trace_file'

    slice_path = find_trace_slice_path(slice_dir, trace_id)
    if slice_path is None:
        return None, 'missing_slice_file'

    signature_payload = json.loads(trace_file.read_text(encoding='utf-8'))
    primary_file_hint = str(signature_payload.get('file') or '') or None
    source_candidates = build_source_file_candidates(signature_payload, primary_file_hint)

    user_defined_function_names: set[str] = set()
    for source_path in source_candidates:
        source_key = str(source_path)
        if source_key not in runtime['source_func_cache']:
            if source_path.exists():
                names, _error = collect_defined_function_names(source_path, runtime['parsers'])
            else:
                names = set()
            runtime['source_func_cache'][source_key] = names
        user_defined_function_names.update(runtime['source_func_cache'][source_key])

    original_code = slice_path.read_text(encoding='utf-8', errors='replace')
    normalized_code, _, _ = normalize_slice_function_names(
        original_code,
        user_defined_function_names,
    )
    token_count = count_code_tokens(runtime['tokenizer'], normalized_code)
    if token_count > CONTENT_TOKEN_LIMIT:
        return None, 'over_limit'

    return {
        'trace_id': trace_id,
        'testcase_key': testcase_key,
        'best_flow_type': str(trace_row.get('best_flow_type') or ''),
        'target': int(trace_row.get('target', 0) or 0),
        'trace_file': str(trace_file),
        'bug_trace_length': int(trace_row.get('bug_trace_length', 0) or 0),
        'procedure': trace_row.get('procedure'),
        'extension': slice_path.suffix.lower(),
        'slice_path': str(slice_path),
        'source_signature_path': normalize_artifact_path(trace_file),
        'normalized_code': normalized_code,
        'normalized_code_hash': normalized_code_md5(normalized_code),
        'code_token_count': token_count,
        'input_token_count_with_special': token_count + 2,
    }, None


def _trace_order_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        str(row['testcase_key']),
        build_trace_priority_key(
            bug_trace_length=int(row.get('bug_trace_length', 0) or 0),
            trace_file=str(row.get('trace_file') or ''),
            best_flow_type=str(row.get('best_flow_type') or ''),
            procedure=row.get('procedure'),
        ),
        str(row['trace_id']),
    )


def _build_audit_row(
    *,
    row: dict[str, Any],
    drop_reason: str,
    matched_kept_row: dict[str, Any] | None = None,
    trigger_hash: str | None = None,
) -> dict[str, Any]:
    return {
        'trace_id': str(row['trace_id']),
        'testcase_key': str(row['testcase_key']),
        'best_flow_type': str(row.get('best_flow_type') or ''),
        'target': int(row.get('target', 0) or 0),
        'trace_file': str(row.get('trace_file') or ''),
        'bug_trace_length': int(row.get('bug_trace_length', 0) or 0),
        'procedure': str(row.get('procedure') or ''),
        'normalized_code_hash': str(row.get('normalized_code_hash') or ''),
        'drop_reason': drop_reason,
        'trigger_hash': str(trigger_hash or ''),
        'matched_kept_trace_id': str(matched_kept_row.get('trace_id') or '')
        if matched_kept_row
        else '',
        'matched_kept_trace_file': str(matched_kept_row.get('trace_file') or '')
        if matched_kept_row
        else '',
    }


def _trace_dataset_row_order_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        str(row['testcase_key']),
        0 if int(row['target']) == 1 else 1,
        str(row.get('best_flow_type') or ''),
        stable_trace_ref(str(row.get('trace_file') or '')),
        str(row['trace_id']),
    )


def _trace_row_to_dataset_csv_record(
    row: dict[str, Any],
    *,
    dataset_type: str,
) -> dict[str, Any]:
    return {
        'file_name': '',
        'unique_id': '',
        'target': int(row['target']),
        'vulnerable_line_numbers': 1 if int(row['target']) == 1 else '',
        'project': 'Juliet',
        'source_signature_path': str(row['source_signature_path']),
        'commit_hash': '',
        'dataset_type': str(dataset_type),
        'processed_func': str(row['normalized_code']),
    }


def _dataset_csv_values(row: dict[str, Any], *, row_id: int) -> list[Any]:
    updated = dict(row)
    updated['file_name'] = row_id
    updated['unique_id'] = row_id
    return [updated[column] for column in DATASET_CSV_FIELDNAMES]


def _apply_row_dedup(
    candidate_rows: list[dict[str, Any]],
    *,
    dedup_mode: str,
) -> tuple[list[dict[str, Any]], Counter[str], list[dict[str, Any]], dict[str, Any]]:
    if dedup_mode not in {'none', 'row'}:
        raise ValueError(f'Unsupported dedup_mode: {dedup_mode}')

    ordered_rows = list(candidate_rows)
    row_occurrences: dict[str, list[dict[str, Any]]] = defaultdict(list)
    label_by_hash: dict[str, int] = {}
    collision_hashes: set[str] = set()
    for row in ordered_rows:
        code_hash = str(row['normalized_code_hash'])
        row_occurrences[code_hash].append(row)
        target = int(row['target'])
        old_target = label_by_hash.get(code_hash)
        if old_target is None:
            label_by_hash[code_hash] = target
        elif old_target != target:
            collision_hashes.add(code_hash)

    filtered_reasons = Counter()
    audit_rows: list[dict[str, Any]] = []
    if dedup_mode == 'none':
        kept_rows = ordered_rows
    else:
        kept_rows = []
        kept_by_hash: dict[str, dict[str, Any]] = {}
        seen_hashes: set[str] = set()
        for row in ordered_rows:
            code_hash = str(row['normalized_code_hash'])
            if code_hash in collision_hashes:
                filtered_reasons['cross_label_collision'] += 1
                audit_rows.append(
                    _build_audit_row(
                        row=row,
                        drop_reason='cross_label_collision',
                        trigger_hash=code_hash,
                    )
                )
                continue
            if code_hash in seen_hashes:
                filtered_reasons['same_label_duplicate'] += 1
                audit_rows.append(
                    _build_audit_row(
                        row=row,
                        drop_reason='same_label_duplicate',
                        matched_kept_row=kept_by_hash[code_hash],
                        trigger_hash=code_hash,
                    )
                )
                continue

            seen_hashes.add(code_hash)
            kept_by_hash[code_hash] = row
            kept_rows.append(row)

    dedup_summary = {
        'mode': dedup_mode,
        'row_hash_method': 'md5(compact_whitespace(normalized_code))',
        'traces_before': len(candidate_rows),
        'traces_after': len(kept_rows),
        'same_label_duplicate_groups': sum(
            1
            for code_hash, rows in row_occurrences.items()
            if code_hash not in collision_hashes and len(rows) > 1
        ),
        'same_label_duplicates_removed': int(filtered_reasons['same_label_duplicate']),
        'cross_label_collision_groups': len(collision_hashes),
        'cross_label_collision_rows': int(filtered_reasons['cross_label_collision']),
        'row_hashes_unique': len(row_occurrences),
    }
    return kept_rows, filtered_reasons, audit_rows, dedup_summary


def _apply_multi_b2b_pruning(
    rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], Counter[str], list[dict[str, Any]], dict[str, Any]]:
    rows_by_testcase: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        rows_by_testcase[str(row['testcase_key'])].append(row)

    kept_rows: list[dict[str, Any]] = []
    filtered_reasons = Counter()
    audit_rows: list[dict[str, Any]] = []
    testcases_with_multi_b2b = 0
    b2b_rows_pruned = 0

    for testcase_key in sorted(rows_by_testcase):
        testcase_rows = rows_by_testcase[testcase_key]
        b2b_rows = [row for row in testcase_rows if int(row['target']) == 1]
        counterpart_rows = [row for row in testcase_rows if int(row['target']) == 0]

        kept_rows.extend(counterpart_rows)
        if len(b2b_rows) <= 1:
            kept_rows.extend(b2b_rows)
            continue

        testcases_with_multi_b2b += 1
        selected_b2b = sorted(
            b2b_rows,
            key=lambda row: (
                int(row.get('bug_trace_length', 0) or 0),
                stable_trace_ref(str(row.get('trace_file') or '')),
                str(row.get('procedure') or ''),
                str(row['trace_id']),
            ),
        )[0]
        kept_rows.append(selected_b2b)
        for row in b2b_rows:
            if row is selected_b2b:
                continue
            filtered_reasons['multi_b2b_pruned'] += 1
            b2b_rows_pruned += 1
            audit_rows.append(
                _build_audit_row(
                    row=row,
                    drop_reason='multi_b2b_pruned',
                    matched_kept_row=selected_b2b,
                )
            )

    pruning_summary = {
        'testcases_with_multi_b2b': testcases_with_multi_b2b,
        'b2b_rows_pruned': b2b_rows_pruned,
    }
    return sorted(kept_rows, key=_trace_order_key), filtered_reasons, audit_rows, pruning_summary


def _write_dataset_csv_and_slices(
    ordered_rows: list[dict[str, Any]],
    *,
    csv_path: Path,
    normalized_slices_dir: Path,
) -> None:
    normalized_slices_dir.mkdir(parents=True, exist_ok=True)
    csv_rows: list[list[Any]] = []
    for idx, row in enumerate(ordered_rows, start=1):
        output_filename = f'{idx}{row["extension"]}'
        (normalized_slices_dir / output_filename).write_text(
            str(row['normalized_code']),
            encoding='utf-8',
        )
        csv_rows.append(
            _dataset_csv_values(
                _trace_row_to_dataset_csv_record(row, dataset_type=str(row['dataset_type'])),
                row_id=idx,
            )
        )
    write_csv_rows(
        csv_path,
        DATASET_CSV_FIELDNAMES,
        csv_rows,
    )


def export_trace_dataset_from_pipeline(
    *,
    traces_jsonl: Path,
    slice_dir: Path,
    output_dir: Path,
    split_seed: int,
    train_ratio: float,
    dedup_mode: str,
) -> dict[str, Any]:
    from shared.slice_tokenizer import load_tokenizer

    if not traces_jsonl.exists():
        raise FileNotFoundError(f'Trace dataset JSONL not found: {traces_jsonl}')
    if not slice_dir.exists():
        raise FileNotFoundError(f'Trace slice dir not found: {slice_dir}')
    if not (0.0 < train_ratio < 1.0):
        raise ValueError(f'train_ratio must be between 0 and 1: {train_ratio}')

    trace_rows = load_traces_jsonl(traces_jsonl)
    export_paths = build_dataset_export_paths(output_dir)
    export_paths['output_dir'].mkdir(parents=True, exist_ok=True)
    export_paths['normalized_slices_dir'].mkdir(parents=True, exist_ok=True)
    dropped_audit_path = export_paths['output_dir'] / 'trace_dedup_dropped.jsonl'

    print('Loading tokenizer for trace-first normalized slices...')
    runtime = {
        'tokenizer': load_tokenizer('microsoft/codebert-base'),
        'parsers': load_tree_sitter_parsers(),
        'source_func_cache': {},
    }

    candidate_rows: list[dict[str, Any]] = []
    filtered_reasons = Counter({'traces_total': len(trace_rows)})
    for trace_row in trace_rows:
        record, reason = _candidate_record(
            trace_row=trace_row,
            slice_dir=slice_dir,
            runtime=runtime,
        )
        if reason is not None:
            filtered_reasons[reason] += 1
            continue
        assert record is not None
        candidate_rows.append(record)

    deduped_rows, dedup_filtered, dedup_audit_rows, dedup_summary = _apply_row_dedup(
        candidate_rows,
        dedup_mode=dedup_mode,
    )
    final_rows, structural_filtered, structural_audit_rows, structural_summary = (
        _apply_multi_b2b_pruning(deduped_rows)
    )
    ordered_final_rows = sorted(final_rows, key=_trace_dataset_row_order_key)
    vuln_patch_selection = _stage07c_vuln_patch_export.select_vuln_patch_rows(
        source_rows=ordered_final_rows,
    )
    vuln_patch_testcase_keys = set(vuln_patch_selection['selected_testcase_keys'])
    main_rows = [
        row
        for row in ordered_final_rows
        if str(row['testcase_key']) not in vuln_patch_testcase_keys
    ]

    testcase_split_assignments = compute_testcase_split(
        [str(row['testcase_key']) for row in main_rows],
        train_ratio=train_ratio,
        seed=split_seed,
    )

    ordered_rows: list[dict[str, Any]] = []
    trace_ids_by_dataset_type: dict[str, list[str]] = {'train_val': [], 'test': []}
    testcase_keys_by_dataset_type: dict[str, list[str]] = {'train_val': [], 'test': []}
    for dataset_type in ('train_val', 'test'):
        testcase_keys = sorted(
            testcase_key
            for testcase_key, value in testcase_split_assignments.items()
            if value == dataset_type
        )
        testcase_keys_by_dataset_type[dataset_type] = testcase_keys
        for testcase_key in testcase_keys:
            testcase_rows = [row for row in main_rows if str(row['testcase_key']) == testcase_key]
            for row in testcase_rows:
                trace_ids_by_dataset_type[dataset_type].append(str(row['trace_id']))
                row_with_split = dict(row)
                row_with_split['dataset_type'] = dataset_type
                ordered_rows.append(row_with_split)

    _write_dataset_csv_and_slices(
        ordered_rows,
        csv_path=export_paths['csv_path'],
        normalized_slices_dir=export_paths['normalized_slices_dir'],
    )
    vuln_patch_result = _stage07c_vuln_patch_export.write_vuln_patch_dataset(
        rows=[
            _trace_row_to_dataset_csv_record(row, dataset_type='test')
            for row in vuln_patch_selection['selected_rows']
        ],
        output_dir=export_paths['output_dir'] / 'vuln_patch',
        stats=vuln_patch_selection['stats'],
        fieldnames=DATASET_CSV_FIELDNAMES,
    )

    split_manifest = {
        'counts': {
            'traces_total': len(main_rows),
            'train_val_traces': len(trace_ids_by_dataset_type['train_val']),
            'test_traces': len(trace_ids_by_dataset_type['test']),
            'train_val_testcases': len(testcase_keys_by_dataset_type['train_val']),
            'test_testcases': len(testcase_keys_by_dataset_type['test']),
        },
        'trace_ids': trace_ids_by_dataset_type,
        'testcase_keys': testcase_keys_by_dataset_type,
    }
    write_json(export_paths['split_manifest_json'], split_manifest)

    dropped_audit_rows = [*dedup_audit_rows, *structural_audit_rows]
    write_jsonl(dropped_audit_path, dropped_audit_rows)

    combined_filtered_reasons = Counter()
    combined_filtered_reasons.update(filtered_reasons)
    combined_filtered_reasons.update(dedup_filtered)
    combined_filtered_reasons.update(structural_filtered)
    filtered_total = sum(
        value for key, value in combined_filtered_reasons.items() if key != 'traces_total'
    )

    artifacts = path_strings(export_paths)
    artifacts['trace_dedup_dropped_jsonl'] = str(dropped_audit_path)
    artifacts['vuln_patch_csv_path'] = str(vuln_patch_result['artifacts']['csv_path'])
    artifacts['vuln_patch_summary_json'] = str(vuln_patch_result['artifacts']['summary_json'])
    stats = {
        'mode': 'trace_first',
        'dedup': dedup_summary,
        'structural_pruning': structural_summary,
        'filtered_trace_reasons': {
            key: value for key, value in combined_filtered_reasons.items() if key != 'traces_total'
        },
        'vuln_patch_holdout': {
            'testcases_selected': len(vuln_patch_selection['selected_testcase_keys']),
            'rows_written': len(vuln_patch_selection['selected_rows']),
            'rows_removed_from_main_dataset': len(final_rows) - len(main_rows),
        },
        'counts': {
            'traces_total': len(trace_rows),
            'candidate_rows': len(candidate_rows),
            'traces_survived_pre_vuln_patch_holdout': len(final_rows),
            'traces_survived': len(main_rows),
            'traces_filtered_out': filtered_total,
            'rows_written': len(ordered_rows),
            'train_val_traces': len(trace_ids_by_dataset_type['train_val']),
            'test_traces': len(trace_ids_by_dataset_type['test']),
            'train_val_testcases': len(testcase_keys_by_dataset_type['train_val']),
            'test_testcases': len(testcase_keys_by_dataset_type['test']),
        },
    }
    write_stage_summary(export_paths['summary_json'], artifacts=artifacts, stats=stats)
    return {'artifacts': artifacts, 'stats': stats}
