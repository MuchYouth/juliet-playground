from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from shared import fs as _fs_utils
from shared.artifact_layout import (
    TRAIN_PATCHED_COUNTERPARTS_BASENAME,
    build_dataset_export_paths,
    build_pair_trace_paths,
    build_patched_pairing_paths,
    build_slice_stage_paths,
    path_strings,
)
from shared.dataset_export_core import DatasetExportRequest, run_configured_step07_export
from shared.dataset_sources import (
    build_source_file_candidates,
    collect_identifier_inventory,
    expand_source_candidates_for_identifier_inventory,
)
from shared.jsonio import load_json, load_jsonl, write_json, write_jsonl
from shared.pairing import build_trace_priority_key, make_pair_id
from shared.signatures import load_signature_payload

from stage.stage06_slices import generate_slices

DATASET_BASENAME = TRAIN_PATCHED_COUNTERPARTS_BASENAME
prepare_target = _fs_utils.prepare_target


def build_stage07b_paths(run_dir: Path) -> dict[str, Any]:
    resolved_run_dir = run_dir.resolve()
    pair_dir = resolved_run_dir / '05_pair_trace_ds'
    dataset_export_dir = resolved_run_dir / '07_dataset_export'
    return {
        'run_dir': resolved_run_dir,
        'pair_dir': pair_dir,
        'dataset_export_dir': dataset_export_dir,
        'pairing': build_patched_pairing_paths(pair_dir, DATASET_BASENAME),
        'slices': build_slice_stage_paths(resolved_run_dir / '06_slices' / DATASET_BASENAME),
        'dataset': build_dataset_export_paths(dataset_export_dir, DATASET_BASENAME),
        'primary_split_manifest_json': build_dataset_export_paths(dataset_export_dir)[
            'split_manifest_json'
        ],
    }


def leftover_sort_key(record: dict[str, Any]) -> tuple[Any, ...]:
    return build_trace_priority_key(
        bug_trace_length=int(record.get('bug_trace_length', 0) or 0),
        trace_file=str(record.get('trace_file') or ''),
        best_flow_type=str(record.get('best_flow_type') or ''),
        procedure=None,
    )


def _selection_stats(
    selection_counts: Counter[str], train_val_pair_ids_total: int
) -> dict[str, Any]:
    return {
        'counts': dict(selection_counts),
        'train_val_pair_ids_total': train_val_pair_ids_total,
        'selected_testcases': int(selection_counts.get('selected_pairs', 0)),
    }


def build_train_patched_counterparts(*, run_dir: Path) -> dict[str, Any]:
    paths = build_stage07b_paths(run_dir)
    pair_trace_paths = build_pair_trace_paths(paths['pair_dir'])

    if not pair_trace_paths['pairs_jsonl'].exists():
        raise FileNotFoundError(f'Pairs JSONL not found: {pair_trace_paths["pairs_jsonl"]}')
    if not pair_trace_paths['leftover_counterparts_jsonl'].exists():
        raise FileNotFoundError(
            'Leftover counterparts JSONL not found: '
            f'{pair_trace_paths["leftover_counterparts_jsonl"]}'
        )
    if not paths['primary_split_manifest_json'].exists():
        raise FileNotFoundError(
            f'Primary split manifest not found: {paths["primary_split_manifest_json"]}'
        )

    prepare_target(paths['pairing']['signatures_dir'], overwrite=False)
    prepare_target(paths['pairing']['pairs_jsonl'], overwrite=False)
    paths['pairing']['signatures_dir'].mkdir(parents=True, exist_ok=True)
    paths['pairing']['pairs_jsonl'].parent.mkdir(parents=True, exist_ok=True)

    split_manifest = json.loads(paths['primary_split_manifest_json'].read_text(encoding='utf-8'))
    train_val_pair_ids = set(split_manifest.get('pair_ids', {}).get('train_val') or [])
    if not train_val_pair_ids:
        raise ValueError(f'No train_val pair_ids found in {paths["primary_split_manifest_json"]}')

    primary_pairs = load_jsonl(pair_trace_paths['pairs_jsonl'])
    primary_pairs_by_testcase = {
        str(pair.get('testcase_key') or ''): pair
        for pair in primary_pairs
        if str(pair.get('pair_id') or '') in train_val_pair_ids
    }

    leftovers = load_jsonl(pair_trace_paths['leftover_counterparts_jsonl'])
    leftovers_by_testcase: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in leftovers:
        testcase_key = str(record.get('testcase_key') or '')
        if testcase_key:
            leftovers_by_testcase[testcase_key].append(record)

    selected_pairs: list[dict[str, Any]] = []
    selection_counts = Counter()

    for testcase_key, primary_pair in sorted(primary_pairs_by_testcase.items()):
        selection_counts['primary_train_val_pairs_total'] += 1
        candidate_leftovers = sorted(
            leftovers_by_testcase.get(testcase_key, []), key=leftover_sort_key
        )
        if not candidate_leftovers:
            selection_counts['primary_train_val_pairs_without_leftover'] += 1
            continue

        selected_leftover = candidate_leftovers[0]
        output_files = primary_pair.get('output_files') or {}
        b2b_signature_path = Path(
            str(primary_pair.get('b2b_path') or output_files.get('b2b') or '')
        )
        counterpart_trace_path = Path(str(selected_leftover.get('trace_file') or ''))
        if not b2b_signature_path.exists():
            selection_counts['skipped_missing_b2b_signature'] += 1
            continue
        if not counterpart_trace_path.exists():
            selection_counts['skipped_missing_counterpart_signature'] += 1
            continue

        counterpart_flow_type = str(selected_leftover.get('best_flow_type') or '').strip()
        if not counterpart_flow_type:
            selection_counts['skipped_missing_counterpart_flow_type'] += 1
            continue

        b2b_payload = load_signature_payload(b2b_signature_path)
        counterpart_payload = load_signature_payload(counterpart_trace_path)
        pair_id = make_pair_id(
            testcase_key=testcase_key,
            b2b_payload=b2b_payload,
            b2b_trace_file=str(b2b_signature_path),
            b2b_flow_type='b2b',
            counterpart_payload=counterpart_payload,
            counterpart_trace_file=str(counterpart_trace_path),
            counterpart_flow_type=counterpart_flow_type,
            dataset_namespace=DATASET_BASENAME,
        )

        testcase_dir = paths['pairing']['signatures_dir'] / testcase_key
        testcase_dir.mkdir(parents=True, exist_ok=True)
        b2b_output_path = testcase_dir / 'b2b.json'
        counterpart_output_path = testcase_dir / f'{counterpart_flow_type}.json'
        write_json(b2b_output_path, b2b_payload)
        write_json(counterpart_output_path, counterpart_payload)

        selected_pairs.append(
            {
                'pair_id': pair_id,
                'testcase_key': testcase_key,
                'source_primary_pair_id': primary_pair.get('pair_id'),
                'counterpart_flow_type': counterpart_flow_type,
                'b2b_path': str(b2b_output_path),
                'counterpart_path': str(counterpart_output_path),
            }
        )
        selection_counts['selected_pairs'] += 1
        selection_counts[f'selected_counterpart_flow_{counterpart_flow_type}'] += 1
        if len(candidate_leftovers) > 1:
            selection_counts['selected_pairs_with_extra_leftovers'] += 1

    write_jsonl(paths['pairing']['pairs_jsonl'], selected_pairs)
    return {
        'pairs': selected_pairs,
        'artifacts': path_strings(paths['pairing']),
        'stats': _selection_stats(selection_counts, len(train_val_pair_ids)),
    }


def export_dataset(
    *,
    pairs: list[dict[str, Any]],
    paired_signatures_dir: Path,
    slice_dir: Path,
    dataset_paths: dict[str, Path],
    dedup_mode: str,
) -> dict[str, Any]:
    return run_configured_step07_export(
        DatasetExportRequest(
            pairs=pairs,
            paired_signatures_dir=paired_signatures_dir,
            slice_dir=slice_dir,
            export_paths=dataset_paths,
            dedup_mode=dedup_mode,
            split_assignments_fn=lambda pair_ids: {pair_id: 'train_val' for pair_id in pair_ids},
            collect_identifier_inventory_fn=collect_identifier_inventory,
            build_source_file_candidates_fn=build_source_file_candidates,
            expand_inventory_source_candidates_fn=expand_source_candidates_for_identifier_inventory,
            dataset_basename=DATASET_BASENAME,
        )
    )


def _merge_patched_summary(summary_path: Path, selection_stats: dict[str, Any]) -> dict[str, Any]:
    payload = load_json(summary_path)
    stats = dict(payload.get('stats') or {})
    stats['selection'] = selection_stats
    payload['stats'] = stats
    write_json(summary_path, payload)
    return payload


def export_patched_dataset(*, run_dir: Path, dedup_mode: str) -> dict[str, Any]:
    paths = build_stage07b_paths(run_dir)
    selected = build_train_patched_counterparts(run_dir=run_dir)

    generate_slices(
        signature_db_dir=Path(selected['artifacts']['signatures_dir']),
        output_dir=paths['slices']['output_dir'],
        overwrite=False,
    )

    export_dataset(
        pairs=selected['pairs'],
        paired_signatures_dir=Path(selected['artifacts']['signatures_dir']),
        slice_dir=paths['slices']['slice_dir'],
        dataset_paths=paths['dataset'],
        dedup_mode=dedup_mode,
    )
    merged_summary = _merge_patched_summary(paths['dataset']['summary_json'], selected['stats'])

    artifacts = {
        'pairing_pairs_jsonl': str(paths['pairing']['pairs_jsonl']),
        'pairing_signatures_dir': str(paths['pairing']['signatures_dir']),
        'slice_dir': str(paths['slices']['slice_dir']),
        'csv_path': str(paths['dataset']['csv_path']),
        'normalized_slices_dir': str(paths['dataset']['normalized_slices_dir']),
        'split_manifest_json': str(paths['dataset']['split_manifest_json']),
        'summary_json': str(paths['dataset']['summary_json']),
    }
    return {'artifacts': artifacts, 'stats': merged_summary['stats']}
