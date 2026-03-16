from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shared import fs as _fs_utils
from shared.artifact_layout import (
    TRAIN_PATCHED_COUNTERPARTS_BASENAME,
    build_dataset_export_paths,
    build_pair_trace_paths,
    build_patched_pairing_paths,
    build_slice_stage_paths,
)
from shared.dataset_export_core import run_configured_step07_export, run_step07_export_core
from shared.dataset_sources import build_source_file_candidates, collect_defined_function_names
from shared.jsonio import load_jsonl, write_json, write_jsonl
from shared.pair_dataset import build_pair_dataset_row, write_pair_signature_exports
from shared.pairing import (
    build_pairing_meta,
    build_signature_meta,
    build_trace_priority_key,
    make_pair_id,
)
from shared.paths import RESULT_DIR
from shared.pipeline_layout import require_existing_dir, resolve_run_dir, validate_prefix_pair
from shared.signatures import load_signature_payload

from stage.stage06_slices import generate_slices

DATASET_BASENAME = TRAIN_PATCHED_COUNTERPARTS_BASENAME
prepare_target = _fs_utils.prepare_target


@dataclass(frozen=True)
class PatchedDatasetExportParams:
    run_dir: Path
    pair_dir: Path
    dataset_export_dir: Path
    signature_output_dir: Path
    slice_output_dir: Path
    output_pairs_jsonl: Path
    selection_summary_json: Path
    dedup_mode: str
    overwrite: bool
    old_prefix: str | None
    new_prefix: str | None


@dataclass(frozen=True)
class PatchedDatasetExportResult:
    dataset_basename: str
    run_dir: Path
    pair_dir: Path
    dataset_export_dir: Path
    signature_output_dir: Path
    slice_output_dir: Path
    slice_dir: Path
    slice_summary_json: Path
    selection_summary_json: Path
    pairs_jsonl: Path
    csv_path: Path
    dedup_dropped_csv: Path
    normalized_slices_dir: Path
    token_counts_csv: Path
    token_distribution_png: Path
    split_manifest_json: Path
    dedup_mode: str
    summary_json: Path

    def to_payload(self) -> dict[str, object]:
        return {
            'dataset_basename': self.dataset_basename,
            'run_dir': str(self.run_dir),
            'pair_dir': str(self.pair_dir),
            'dataset_export_dir': str(self.dataset_export_dir),
            'signature_output_dir': str(self.signature_output_dir),
            'slice_output_dir': str(self.slice_output_dir),
            'slice_dir': str(self.slice_dir),
            'slice_summary_json': str(self.slice_summary_json),
            'selection_summary_json': str(self.selection_summary_json),
            'pairs_jsonl': str(self.pairs_jsonl),
            'csv_path': str(self.csv_path),
            'dedup_dropped_csv': str(self.dedup_dropped_csv),
            'normalized_slices_dir': str(self.normalized_slices_dir),
            'token_counts_csv': str(self.token_counts_csv),
            'token_distribution_png': str(self.token_distribution_png),
            'split_manifest_json': str(self.split_manifest_json),
            'dedup_mode': self.dedup_mode,
            'summary_json': str(self.summary_json),
        }


def infer_run_dir_from_pair_dir(pair_dir: Path) -> Path | None:
    if pair_dir.name != '05_pair_trace_ds':
        return None
    return pair_dir.parent


def resolve_paths(
    *,
    run_dir: Path | None = None,
    pair_dir: Path | None = None,
    dataset_export_dir: Path | None = None,
    signature_output_dir: Path | None = None,
    slice_output_dir: Path | None = None,
    pipeline_root: Path = Path(RESULT_DIR) / 'pipeline-runs',
) -> dict[str, Path | None]:
    resolved_run_dir = resolve_run_dir(
        run_dir=run_dir,
        pipeline_root=pipeline_root,
        inferred_from_path=pair_dir,
        infer_run_dir_fn=infer_run_dir_from_pair_dir,
        use_latest_if_unresolved=pair_dir is None,
    )
    if run_dir is not None:
        resolved_pair_dir = (
            pair_dir.resolve() if pair_dir is not None else resolved_run_dir / '05_pair_trace_ds'
        )
    elif pair_dir is not None:
        resolved_pair_dir = pair_dir.resolve()
    else:
        assert resolved_run_dir is not None
        resolved_pair_dir = resolved_run_dir / '05_pair_trace_ds'

    if dataset_export_dir is None:
        if resolved_run_dir is None:
            raise ValueError('--dataset-export-dir is required when run-dir cannot be inferred.')
        resolved_dataset_export_dir = resolved_run_dir / '07_dataset_export'
    else:
        resolved_dataset_export_dir = dataset_export_dir.resolve()

    if signature_output_dir is None:
        resolved_signature_output_dir = build_patched_pairing_paths(
            resolved_pair_dir, DATASET_BASENAME
        )['signatures_dir']
    else:
        resolved_signature_output_dir = signature_output_dir.resolve()

    if slice_output_dir is None:
        if resolved_run_dir is None:
            raise ValueError('--slice-output-dir is required when run-dir cannot be inferred.')
        resolved_slice_output_dir = resolved_run_dir / '06_slices' / DATASET_BASENAME
    else:
        resolved_slice_output_dir = slice_output_dir.resolve()

    paths: dict[str, Path | None] = {
        'run_dir': resolved_run_dir,
        'pair_dir': resolved_pair_dir,
        'dataset_export_dir': resolved_dataset_export_dir,
        'signature_output_dir': resolved_signature_output_dir,
        'slice_output_dir': resolved_slice_output_dir,
    }
    return paths


def validate_args(
    *,
    pair_dir: Path | None,
    dataset_export_dir: Path | None,
    old_prefix: str | None = None,
    new_prefix: str | None = None,
) -> None:
    if pair_dir is None or dataset_export_dir is None:
        raise ValueError('Resolved pair_dir and dataset_export_dir are required.')
    require_existing_dir(
        pair_dir,
        missing_message=f'Pair dir not found: {pair_dir}',
        not_dir_message=f'Pair dir is not a directory: {pair_dir}',
    )
    require_existing_dir(
        dataset_export_dir,
        missing_message=f'Dataset export dir not found: {dataset_export_dir}',
        not_dir_message=f'Dataset export dir is not a directory: {dataset_export_dir}',
    )
    validate_prefix_pair(old_prefix, new_prefix)


def leftover_sort_key(record: dict[str, Any]) -> tuple[Any, ...]:
    return build_trace_priority_key(
        bug_trace_length=int(record.get('bug_trace_length', 0) or 0),
        trace_file=str(record.get('trace_file') or ''),
        best_flow_type=str(record.get('best_flow_type') or ''),
        procedure=record.get('procedure'),
    )


def build_train_patched_counterparts(
    *,
    pair_dir: Path,
    dataset_export_dir: Path,
    signature_output_dir: Path,
    output_pairs_jsonl: Path,
    selection_summary_json: Path,
    overwrite: bool,
) -> dict[str, Any]:
    pair_trace_paths = build_pair_trace_paths(pair_dir)
    pairs_jsonl = pair_trace_paths['pairs_jsonl']
    leftovers_jsonl = pair_trace_paths['leftover_counterparts_jsonl']
    source_split_manifest_json = build_dataset_export_paths(dataset_export_dir)[
        'split_manifest_json'
    ]
    summary_json = selection_summary_json

    if not pairs_jsonl.exists():
        raise FileNotFoundError(f'Pairs JSONL not found: {pairs_jsonl}')
    if not leftovers_jsonl.exists():
        raise FileNotFoundError(f'Leftover counterparts JSONL not found: {leftovers_jsonl}')
    if not source_split_manifest_json.exists():
        raise FileNotFoundError(f'Primary split manifest not found: {source_split_manifest_json}')

    prepare_target(signature_output_dir, overwrite=overwrite)
    prepare_target(output_pairs_jsonl, overwrite=overwrite)
    prepare_target(summary_json, overwrite=overwrite)
    signature_output_dir.mkdir(parents=True, exist_ok=True)
    output_pairs_jsonl.parent.mkdir(parents=True, exist_ok=True)
    summary_json.parent.mkdir(parents=True, exist_ok=True)

    split_manifest = json.loads(source_split_manifest_json.read_text(encoding='utf-8'))
    train_val_pair_ids = set(split_manifest.get('pair_ids', {}).get('train_val') or [])
    if not train_val_pair_ids:
        raise ValueError(f'No train_val pair_ids found in {source_split_manifest_json}')

    primary_pairs = load_jsonl(pairs_jsonl)
    primary_pairs_by_testcase = {
        str(pair.get('testcase_key') or ''): pair
        for pair in primary_pairs
        if str(pair.get('pair_id') or '') in train_val_pair_ids
    }

    leftovers = load_jsonl(leftovers_jsonl)
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
        b2b_signature_path = Path(str((primary_pair.get('output_files') or {}).get('b2b') or ''))
        counterpart_trace_path = Path(str(selected_leftover.get('trace_file') or ''))
        if not b2b_signature_path.exists():
            selection_counts['skipped_missing_b2b_signature'] += 1
            continue
        if not counterpart_trace_path.exists():
            selection_counts['skipped_missing_counterpart_signature'] += 1
            continue

        b2b_payload = load_signature_payload(b2b_signature_path)
        counterpart_payload = load_signature_payload(counterpart_trace_path)
        counterpart_flow_type = str(selected_leftover.get('best_flow_type') or '').strip()
        if not counterpart_flow_type:
            selection_counts['skipped_missing_counterpart_flow_type'] += 1
            continue

        pair_id = make_pair_id(
            testcase_key=testcase_key,
            b2b_payload=b2b_payload,
            b2b_trace_file=str(primary_pair.get('b2b_trace_file') or ''),
            b2b_flow_type=str(primary_pair.get('b2b_flow_type') or ''),
            counterpart_payload=counterpart_payload,
            counterpart_trace_file=str(selected_leftover.get('trace_file') or ''),
            counterpart_flow_type=counterpart_flow_type,
            dataset_namespace=DATASET_BASENAME,
        )

        output_files = write_pair_signature_exports(
            signatures_dir=signature_output_dir,
            testcase_key=testcase_key,
            counterpart_flow_type=counterpart_flow_type,
            b2b_payload=b2b_payload,
            b2b_pairing_meta=build_pairing_meta(
                pair_id=pair_id,
                testcase_key=testcase_key,
                role='b2b',
                selection_reason='train_val_primary_pair',
                source_primary_pair_id=str(primary_pair.get('pair_id') or '') or None,
                trace_file=str(primary_pair.get('b2b_trace_file') or ''),
                best_flow_type=str(primary_pair.get('b2b_flow_type') or ''),
                bug_trace_length=int(primary_pair.get('b2b_bug_trace_length', 0) or 0),
            ),
            counterpart_payload=counterpart_payload,
            counterpart_pairing_meta=build_pairing_meta(
                pair_id=pair_id,
                testcase_key=testcase_key,
                role='counterpart',
                selection_reason='top_leftover_train_val',
                source_primary_pair_id=str(primary_pair.get('pair_id') or '') or None,
                trace_file=str(selected_leftover.get('trace_file') or ''),
                best_flow_type=counterpart_flow_type,
                bug_trace_length=int(selected_leftover.get('bug_trace_length', 0) or 0),
                leftover_rank=1,
                leftover_candidates_total=len(candidate_leftovers),
            ),
        )

        selected_pairs.append(
            build_pair_dataset_row(
                pair_id=pair_id,
                testcase_key=testcase_key,
                selection_reason='top_leftover_train_val',
                leading_fields={
                    'source_primary_pair_id': primary_pair.get('pair_id'),
                    'source_primary_dataset_type': 'train_val',
                },
                b2b_flow_type=str(primary_pair.get('b2b_flow_type') or ''),
                b2b_trace_file=str(primary_pair.get('b2b_trace_file') or ''),
                b2b_bug_trace_length=int(primary_pair.get('b2b_bug_trace_length', 0) or 0),
                b2b_signature=primary_pair.get('b2b_signature'),
                counterpart_flow_type=counterpart_flow_type,
                counterpart_trace_file=str(selected_leftover.get('trace_file') or ''),
                counterpart_bug_trace_length=int(
                    selected_leftover.get('bug_trace_length', 0) or 0
                ),
                counterpart_signature=build_signature_meta(
                    payload=counterpart_payload,
                    trace_file=str(selected_leftover.get('trace_file') or ''),
                    best_flow_type=counterpart_flow_type,
                    bug_trace_length=int(selected_leftover.get('bug_trace_length', 0) or 0),
                    procedure=selected_leftover.get('procedure'),
                    primary_file=selected_leftover.get('primary_file'),
                    primary_line=selected_leftover.get('primary_line'),
                ),
                output_files=output_files,
            )
        )
        selection_counts['selected_pairs'] += 1
        selection_counts[f'selected_counterpart_flow_{counterpart_flow_type}'] += 1
        if len(candidate_leftovers) > 1:
            selection_counts['selected_pairs_with_extra_leftovers'] += 1

    write_jsonl(output_pairs_jsonl, selected_pairs)

    summary_payload = {
        'dataset_basename': DATASET_BASENAME,
        'pair_dir': str(pair_dir),
        'source_pairs_jsonl': str(pairs_jsonl),
        'source_leftover_counterparts_jsonl': str(leftovers_jsonl),
        'source_split_manifest_json': str(source_split_manifest_json),
        'signature_output_dir': str(signature_output_dir),
        'output_pairs_jsonl': str(output_pairs_jsonl),
        'counts': dict(selection_counts),
        'train_val_pair_ids_total': len(train_val_pair_ids),
        'selected_testcases': len(selected_pairs),
    }
    write_json(summary_json, summary_payload)
    print(json.dumps(summary_payload, ensure_ascii=False))
    return {
        'pairs': selected_pairs,
        'output_pairs_jsonl': output_pairs_jsonl,
        'selection_summary_json': summary_json,
        'signature_output_dir': signature_output_dir,
        'selection_counts': dict(selection_counts),
    }


def export_dataset(
    *,
    pairs: list[dict[str, Any]],
    paired_signatures_dir: Path,
    slice_dir: Path,
    dataset_export_dir: Path,
    overwrite: bool,
    dedup_mode: str,
) -> dict[str, Any]:
    export_paths = build_dataset_export_paths(dataset_export_dir, DATASET_BASENAME)
    export_result, _export_paths = run_configured_step07_export(
        pairs=pairs,
        paired_signatures_dir=paired_signatures_dir,
        slice_dir=slice_dir,
        output_dir=dataset_export_dir,
        dedup_mode=dedup_mode,
        dataset_basename=DATASET_BASENAME,
        prepare_target_fn=prepare_target,
        overwrite=overwrite,
        split_assignments_fn=lambda pair_ids: {pair_id: 'train_val' for pair_id in pair_ids},
        summary_metadata={
            'dataset_basename': DATASET_BASENAME,
            'paired_signatures_dir': str(paired_signatures_dir),
            'slice_dir': str(slice_dir),
            'output_dir': str(dataset_export_dir),
            'csv_path': str(export_paths['csv_path']),
        },
        split_manifest_metadata={
            'dataset_basename': DATASET_BASENAME,
            'output_dir': str(dataset_export_dir),
            'paired_signatures_dir': str(paired_signatures_dir),
            'slice_dir': str(slice_dir),
            'split_unit': 'pair_id',
            'split_mode': 'inherited_train_val_only',
        },
        collect_defined_function_names_fn=collect_defined_function_names,
        build_source_file_candidates_fn=build_source_file_candidates,
        run_step07_export_core_fn=run_step07_export_core,
    )
    return export_result


def export_patched_dataset(params: PatchedDatasetExportParams) -> PatchedDatasetExportResult:
    selected = build_train_patched_counterparts(
        pair_dir=params.pair_dir,
        dataset_export_dir=params.dataset_export_dir,
        signature_output_dir=params.signature_output_dir,
        output_pairs_jsonl=params.output_pairs_jsonl,
        selection_summary_json=params.selection_summary_json,
        overwrite=params.overwrite,
    )

    prepare_target(params.slice_output_dir, overwrite=params.overwrite)
    params.slice_output_dir.mkdir(parents=True, exist_ok=True)
    generate_slices(
        signature_db_dir=params.signature_output_dir,
        output_dir=params.slice_output_dir,
        old_prefix=params.old_prefix,
        new_prefix=params.new_prefix,
        overwrite=False,
        run_dir=params.run_dir,
        summary_metadata={'dataset_basename': DATASET_BASENAME},
    )
    slice_stage_paths = build_slice_stage_paths(params.slice_output_dir)
    slice_dir = slice_stage_paths['slice_dir']
    slice_summary_json = slice_stage_paths['summary_json']

    export_result = export_dataset(
        pairs=selected['pairs'],
        paired_signatures_dir=params.signature_output_dir,
        slice_dir=slice_dir,
        dataset_export_dir=params.dataset_export_dir,
        overwrite=params.overwrite,
        dedup_mode=params.dedup_mode,
    )

    return PatchedDatasetExportResult(
        dataset_basename=DATASET_BASENAME,
        run_dir=params.run_dir,
        pair_dir=params.pair_dir,
        dataset_export_dir=params.dataset_export_dir,
        signature_output_dir=params.signature_output_dir,
        slice_output_dir=params.slice_output_dir,
        slice_dir=slice_dir,
        slice_summary_json=slice_summary_json,
        selection_summary_json=Path(selected['selection_summary_json']),
        pairs_jsonl=Path(selected['output_pairs_jsonl']),
        csv_path=Path(export_result['csv_path']),
        dedup_dropped_csv=Path(export_result['dedup_dropped_csv']),
        normalized_slices_dir=Path(export_result['normalized_slices_dir']),
        token_counts_csv=Path(export_result['token_counts_csv']),
        token_distribution_png=Path(export_result['token_distribution_png']),
        split_manifest_json=Path(export_result['split_manifest_json']),
        dedup_mode=params.dedup_mode,
        summary_json=Path(export_result['summary_json']),
    )
