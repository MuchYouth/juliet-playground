#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime
import json
from pathlib import Path
from typing import Any

from shared import fs as _fs_utils
from shared.jsonio import load_json
from shared.paths import RESULT_DIR
from shared.pipeline_runs import find_latest_pipeline_run_dir

from stage import stage07_dataset_export as _dataset_export
from stage import stage07b_patched_export as _patched_export

prepare_target = _fs_utils.prepare_target
PrimaryDatasetExportParams = _dataset_export.PrimaryDatasetExportParams
PrimaryDatasetExportResult = _dataset_export.PrimaryDatasetExportResult
export_primary_dataset = _dataset_export.export_primary_dataset
PatchedDatasetExportParams = _patched_export.PatchedDatasetExportParams
PatchedDatasetExportResult = _patched_export.PatchedDatasetExportResult
export_patched_dataset = _patched_export.export_patched_dataset


def now_ts_compact() -> str:
    return datetime.datetime.now().strftime('%Y%m%d_%H%M%S')


def now_iso_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            'Re-run pipeline Step 07 (dataset export) for an existing run using the already '
            'generated Step 05/06 artifacts. By default it re-runs both Step 07 and Step 07b.'
        )
    )
    parser.add_argument(
        '--run-dir',
        type=Path,
        default=None,
        help='Pipeline run directory. If omitted, use the latest run under --pipeline-root.',
    )
    parser.add_argument(
        '--pipeline-root',
        type=Path,
        default=Path(RESULT_DIR) / 'pipeline-runs',
        help='Root directory containing run-* pipeline outputs.',
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=None,
        help=(
            'Target directory for Step 07 outputs; default is <run-dir>/07_dataset_export_<ts> '
            'for the normal 07+07b rerun, or <run-dir>/07_dataset_export for --only-07b.'
        ),
    )
    parser.add_argument(
        '--dedup-mode',
        choices=['none', 'row'],
        default='row',
        help='Normalized-slice dedup mode to use for Step 07 export.',
    )
    parser.add_argument(
        '--overwrite',
        action='store_true',
        help='Replace an existing --output-dir.',
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        '--only-07',
        action='store_true',
        help='Run only Step 07.',
    )
    mode_group.add_argument(
        '--only-07b',
        action='store_true',
        help='Run only Step 07b against an existing Step 07 output directory.',
    )
    parser.add_argument(
        '--old-prefix',
        type=str,
        default=None,
        help='Optional old path prefix to pass through when re-running Step 07b.',
    )
    parser.add_argument(
        '--new-prefix',
        type=str,
        default=None,
        help='Optional new path prefix to pass through when re-running Step 07b.',
    )
    return parser.parse_args()


def resolve_run_dir(args: argparse.Namespace) -> Path:
    if args.run_dir is not None:
        return args.run_dir.resolve()
    return find_latest_pipeline_run_dir(args.pipeline_root.resolve()).resolve()


def validate_args(args: argparse.Namespace) -> None:
    if bool(args.old_prefix) != bool(args.new_prefix):
        raise ValueError('--old-prefix and --new-prefix must be provided together.')


def choose_run_config(run_dir: Path) -> dict[str, Any]:
    run_summary_path = run_dir / 'run_summary.json'
    if not run_summary_path.exists():
        raise FileNotFoundError(f'run_summary.json not found: {run_summary_path}')
    run_summary = load_json(run_summary_path)
    outputs = run_summary.get('outputs') or {}
    if not isinstance(outputs, dict):
        outputs = {}

    pairs_jsonl = Path(
        str(outputs.get('pairs_jsonl') or (run_dir / '05_pair_trace_ds' / 'pairs.jsonl'))
    )
    paired_signatures_dir = Path(
        str(
            outputs.get('paired_signatures_dir')
            or (run_dir / '05_pair_trace_ds' / 'paired_signatures')
        )
    )
    slice_dir = Path(str(outputs.get('slice_dir') or (run_dir / '06_slices' / 'slice')))

    split_seed = int(run_summary.get('pair_split_seed', 1234))
    train_ratio = float(run_summary.get('pair_train_ratio', 0.8))

    config = {
        'run_summary_path': run_summary_path,
        'pairs_jsonl': pairs_jsonl,
        'paired_signatures_dir': paired_signatures_dir,
        'slice_dir': slice_dir,
        'split_seed': split_seed,
        'train_ratio': train_ratio,
    }
    return config


def validate_inputs(run_dir: Path, config: dict[str, Any]) -> None:
    if not run_dir.exists():
        raise FileNotFoundError(f'Run dir not found: {run_dir}')
    if not run_dir.is_dir():
        raise NotADirectoryError(f'Run dir is not a directory: {run_dir}')

    for key in ('pairs_jsonl', 'paired_signatures_dir', 'slice_dir'):
        path = config[key]
        if not isinstance(path, Path):
            raise ValueError(f'Invalid path for {key}: {path}')
        if not path.exists():
            raise FileNotFoundError(f'Required input not found for {key}: {path}')


def infer_suffix_from_output_dir(output_dir: Path) -> str:
    prefix = '07_dataset_export_'
    if output_dir.name.startswith(prefix):
        suffix = output_dir.name[len(prefix) :].strip()
        if suffix:
            return suffix
    return now_ts_compact()


def resolve_output_dir(*, run_dir: Path, args: argparse.Namespace, run_suffix: str) -> Path:
    if args.output_dir is not None:
        return args.output_dir.resolve()
    if args.only_07b:
        return run_dir / '07_dataset_export'
    return run_dir / f'07_dataset_export_{run_suffix}'


def validate_step07_output_dir(output_dir: Path) -> None:
    if not output_dir.exists():
        raise FileNotFoundError(f'Step 07 output dir not found: {output_dir}')
    if not output_dir.is_dir():
        raise NotADirectoryError(f'Step 07 output path is not a directory: {output_dir}')
    summary_json = output_dir / 'summary.json'
    split_manifest_json = output_dir / 'split_manifest.json'
    if not summary_json.exists():
        raise FileNotFoundError(f'Step 07 summary.json not found: {summary_json}')
    if not split_manifest_json.exists():
        raise FileNotFoundError(f'Step 07 split_manifest.json not found: {split_manifest_json}')


def rerun_step07(
    *, run_dir: Path, output_dir: Path, dedup_mode: str, overwrite: bool
) -> dict[str, Any]:
    config = choose_run_config(run_dir)
    validate_inputs(run_dir, config)

    prepare_target(output_dir, overwrite=overwrite)

    print(f'[Step07] run_dir={run_dir}')
    print(f'[Step07] output_dir={output_dir}')
    print(
        f'[Step07] split_seed={config["split_seed"]} '
        f'train_ratio={config["train_ratio"]} dedup_mode={dedup_mode}'
    )

    result = export_primary_dataset(
        PrimaryDatasetExportParams(
            pairs_jsonl=config['pairs_jsonl'],
            paired_signatures_dir=config['paired_signatures_dir'],
            slice_dir=config['slice_dir'],
            output_dir=output_dir,
            split_seed=config['split_seed'],
            train_ratio=config['train_ratio'],
            dedup_mode=dedup_mode,
        )
    )
    if not isinstance(result, PrimaryDatasetExportResult):
        raise ValueError('Step 07 export returned a non-PrimaryDatasetExportResult result.')
    return result.to_payload()


def rerun_step07b(
    *,
    run_dir: Path,
    dataset_export_dir: Path,
    run_suffix: str,
    dedup_mode: str,
    overwrite: bool,
    old_prefix: str | None,
    new_prefix: str | None,
) -> dict[str, Any]:
    pair_dir = run_dir / '05_pair_trace_ds'
    slice_root_dir = run_dir / '06_slices'
    signature_output_dir = pair_dir / f'train_patched_counterparts_signatures_{run_suffix}'
    slice_output_dir = slice_root_dir / f'train_patched_counterparts_{run_suffix}'
    output_pairs_jsonl = pair_dir / f'train_patched_counterparts_pairs_{run_suffix}.jsonl'
    selection_summary_json = (
        pair_dir / f'train_patched_counterparts_selection_summary_{run_suffix}.json'
    )
    result = export_patched_dataset(
        PatchedDatasetExportParams(
            run_dir=run_dir,
            pair_dir=pair_dir,
            dataset_export_dir=dataset_export_dir,
            signature_output_dir=signature_output_dir,
            slice_output_dir=slice_output_dir,
            output_pairs_jsonl=output_pairs_jsonl,
            selection_summary_json=selection_summary_json,
            dedup_mode=dedup_mode,
            overwrite=overwrite,
            old_prefix=old_prefix,
            new_prefix=new_prefix,
        )
    )
    if not isinstance(result, PatchedDatasetExportResult):
        raise ValueError('Step 07b export returned a non-PatchedDatasetExportResult result.')

    return {
        'executor': 'internal',
        'returncode': 0,
        'signature_output_dir': str(result.signature_output_dir),
        'slice_output_dir': str(result.slice_output_dir),
        'output_pairs_jsonl': str(result.pairs_jsonl),
        'selection_summary_json': str(result.selection_summary_json),
        'summary_json': str(result.summary_json),
    }


def write_rerun_metadata(
    *,
    run_dir: Path,
    output_dir: Path,
    started_at: str,
    args: argparse.Namespace,
    run_step07: bool,
    run_step07b: bool,
    step07_result: dict[str, Any] | None,
    step07b_result: dict[str, Any] | None,
) -> Path:
    payload = {
        'started_at': started_at,
        'ended_at': now_iso_utc(),
        'run_dir': str(run_dir),
        'output_dir': str(output_dir),
        'dedup_mode': args.dedup_mode,
        'ran_step07': run_step07,
        'ran_step07b': run_step07b,
        'overwrite': bool(args.overwrite),
        'step07_result': step07_result,
        'step07b_result': step07b_result,
    }
    metadata_path = output_dir / 'rerun_step07_metadata.json'
    metadata_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
    )
    return metadata_path


def run_rerun_step07(
    *,
    run_dir: Path | None = None,
    pipeline_root: Path = Path(RESULT_DIR) / 'pipeline-runs',
    output_dir: Path | None = None,
    dedup_mode: str = 'row',
    overwrite: bool = False,
    only_07: bool = False,
    only_07b: bool = False,
    old_prefix: str | None = None,
    new_prefix: str | None = None,
) -> dict[str, Any]:
    args = argparse.Namespace(
        run_dir=run_dir,
        pipeline_root=pipeline_root,
        output_dir=output_dir,
        dedup_mode=dedup_mode,
        overwrite=overwrite,
        only_07=only_07,
        only_07b=only_07b,
        old_prefix=old_prefix,
        new_prefix=new_prefix,
    )
    validate_args(args)
    resolved_run_dir = resolve_run_dir(args)
    run_suffix = now_ts_compact()
    resolved_output_dir = resolve_output_dir(
        run_dir=resolved_run_dir, args=args, run_suffix=run_suffix
    )
    run_step07 = not args.only_07b
    run_step07b = not args.only_07
    step07b_suffix = infer_suffix_from_output_dir(resolved_output_dir)

    started_at = now_iso_utc()
    step07_result: dict[str, Any] | None = None
    if run_step07:
        step07_result = rerun_step07(
            run_dir=resolved_run_dir,
            output_dir=resolved_output_dir,
            dedup_mode=args.dedup_mode,
            overwrite=args.overwrite,
        )
    else:
        validate_step07_output_dir(resolved_output_dir)

    step07b_result: dict[str, Any] | None = None
    if run_step07b:
        step07b_result = rerun_step07b(
            run_dir=resolved_run_dir,
            dataset_export_dir=resolved_output_dir,
            run_suffix=step07b_suffix,
            dedup_mode=args.dedup_mode,
            overwrite=args.overwrite,
            old_prefix=args.old_prefix,
            new_prefix=args.new_prefix,
        )

    metadata_path = write_rerun_metadata(
        run_dir=resolved_run_dir,
        output_dir=resolved_output_dir,
        started_at=started_at,
        args=args,
        run_step07=run_step07,
        run_step07b=run_step07b,
        step07_result=step07_result,
        step07b_result=step07b_result,
    )

    return {
        'run_dir': str(resolved_run_dir),
        'output_dir': str(resolved_output_dir),
        'dedup_mode': args.dedup_mode,
        'ran_step07': run_step07,
        'ran_step07b': run_step07b,
        'metadata_json': str(metadata_path),
        'step07_summary_json': str(resolved_output_dir / 'summary.json'),
        'step07_split_manifest_json': str(resolved_output_dir / 'split_manifest.json'),
        'step07b_summary_json': str(resolved_output_dir / 'train_patched_counterparts_summary.json')
        if run_step07b
        else None,
    }


def main() -> int:
    args = parse_args()
    result = run_rerun_step07(
        run_dir=args.run_dir,
        pipeline_root=args.pipeline_root,
        output_dir=args.output_dir,
        dedup_mode=args.dedup_mode,
        overwrite=args.overwrite,
        only_07=args.only_07,
        only_07b=args.only_07b,
        old_prefix=args.old_prefix,
        new_prefix=args.new_prefix,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
