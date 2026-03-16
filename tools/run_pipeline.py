#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from shared import dataset_dedup as _dataset_dedup
from shared.artifact_layout import (
    TRAIN_PATCHED_COUNTERPARTS_BASENAME,
    DatasetExportPaths,
    PairTracePaths,
    PatchedPairingPaths,
    SliceStagePaths,
    build_dataset_export_paths,
    build_pair_trace_paths,
    build_patched_pairing_paths,
    build_slice_stage_paths,
)
from shared.paths import PROJECT_HOME, PULSE_TAINT_CONFIG, RESULT_DIR
from stage import stage01_manifest as _stage01_manifest
from stage import stage02a_taint as _stage02a_taint
from stage import stage02b_flow as _stage02b_flow
from stage import stage03_infer as _stage03_infer
from stage import stage04_trace_flow as _stage04_trace_flow
from stage import stage05_pair_trace as _stage05_pair_trace
from stage import stage06_slices as _stage06_slices
from stage import stage07_dataset_export as _stage07_dataset_export
from stage import stage07b_patched_export as _stage07b_patched_export

PrimaryDatasetExportParams = _stage07_dataset_export.PrimaryDatasetExportParams
compute_pair_split = _stage07_dataset_export.compute_pair_split
dedupe_pairs_by_normalized_rows = _dataset_dedup.dedupe_pairs_by_normalized_rows
export_dataset_from_pipeline = _stage07_dataset_export.export_dataset_from_pipeline
export_primary_dataset = _stage07_dataset_export.export_primary_dataset
PatchedDatasetExportParams = _stage07b_patched_export.PatchedDatasetExportParams
export_patched_dataset = _stage07b_patched_export.export_patched_dataset


@dataclass(frozen=True)
class FullRunConfig:
    cwes: Optional[list[int]]
    all_cwes: bool
    files: list[str]
    manifest: Path
    source_root: Path
    pipeline_root: Path
    run_id: Optional[str]
    committed_taint_config: Path
    pair_split_seed: int
    pair_train_ratio: float
    dedup_mode: str


@dataclass(frozen=True)
class FullRunPaths:
    run_dir: Path
    manifest_dir: Path
    taint_dir: Path
    flow_dir: Path
    infer_results_root: Path
    signatures_root: Path
    trace_dir: Path
    logs_dir: Path
    manifest_with_comments_xml: Path
    generated_taint_config: Path
    infer_summary_json: Path
    trace_strict_jsonl: Path
    run_summary_path: Path
    source_testcases_root: Path
    stage02b: _stage02b_flow.Stage02BOutputPaths
    pair: PairTracePaths
    slices: SliceStagePaths
    dataset: DatasetExportPaths
    patched_pair: PatchedPairingPaths
    patched_slices: SliceStagePaths
    patched_dataset: DatasetExportPaths


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Unified runner for the full pipeline.')
    subparsers = parser.add_subparsers(dest='command', required=True)

    full = subparsers.add_parser('full', help='Run the full pipeline.')
    full.add_argument('cwes', nargs='*', type=int)
    full.add_argument('--all', action='store_true', dest='all_cwes')
    full.add_argument('--files', action='append', default=[])
    full.add_argument(
        '--manifest',
        type=Path,
        default=Path(PROJECT_HOME)
        / 'experiments'
        / 'epic001_manifest_comment_scan'
        / 'inputs'
        / 'manifest.xml',
    )
    full.add_argument(
        '--source-root',
        type=Path,
        default=Path(PROJECT_HOME) / 'juliet-test-suite-v1.3' / 'C',
    )
    full.add_argument(
        '--pipeline-root',
        type=Path,
        default=Path(RESULT_DIR) / 'pipeline-runs',
    )
    full.add_argument('--run-id', type=str, default=None)
    full.add_argument(
        '--committed-taint-config',
        type=Path,
        default=Path(PULSE_TAINT_CONFIG),
    )
    full.add_argument('--pair-split-seed', type=int, default=1234)
    full.add_argument('--pair-train-ratio', type=float, default=0.8)
    full.add_argument('--dedup-mode', choices=['none', 'row'], default='row')

    return parser.parse_args()


def now_ts() -> str:
    return datetime.datetime.now().strftime('%Y.%m.%d-%H:%M:%S')


def _build_full_run_paths(*, run_dir: Path, source_root: Path) -> FullRunPaths:
    run_dir = run_dir.resolve()
    source_root = source_root.resolve()

    manifest_dir = run_dir / '01_manifest'
    taint_dir = run_dir / '02a_taint'
    flow_dir = run_dir / '02b_flow'
    infer_results_root = run_dir / '03_infer-results'
    signatures_root = run_dir / '03_signatures'
    trace_dir = run_dir / '04_trace_flow'
    logs_dir = run_dir / 'logs'
    pair_paths = build_pair_trace_paths(run_dir / '05_pair_trace_ds')
    slice_paths = build_slice_stage_paths(run_dir / '06_slices')
    dataset_paths = build_dataset_export_paths(run_dir / '07_dataset_export')
    patched_pair_paths = build_patched_pairing_paths(
        pair_paths.output_dir,
        TRAIN_PATCHED_COUNTERPARTS_BASENAME,
    )
    patched_slice_paths = build_slice_stage_paths(
        slice_paths.output_dir / TRAIN_PATCHED_COUNTERPARTS_BASENAME
    )
    patched_dataset_paths = build_dataset_export_paths(
        dataset_paths.output_dir,
        TRAIN_PATCHED_COUNTERPARTS_BASENAME,
    )
    stage02b_output_paths = _stage02b_flow.build_stage02b_output_paths(flow_dir)

    return FullRunPaths(
        run_dir=run_dir,
        manifest_dir=manifest_dir,
        taint_dir=taint_dir,
        flow_dir=flow_dir,
        infer_results_root=infer_results_root,
        signatures_root=signatures_root,
        trace_dir=trace_dir,
        logs_dir=logs_dir,
        manifest_with_comments_xml=manifest_dir / 'manifest_with_comments.xml',
        generated_taint_config=taint_dir / 'pulse-taint-config.json',
        infer_summary_json=run_dir / '03_infer_summary.json',
        trace_strict_jsonl=trace_dir / 'trace_flow_match_strict.jsonl',
        run_summary_path=run_dir / 'run_summary.json',
        source_testcases_root=source_root / 'testcases',
        stage02b=stage02b_output_paths,
        pair=pair_paths,
        slices=slice_paths,
        dataset=dataset_paths,
        patched_pair=patched_pair_paths,
        patched_slices=patched_slice_paths,
        patched_dataset=patched_dataset_paths,
    )


def run_internal_step(
    step_key: str,
    logs_dir: Path,
    fn: Callable[[], dict[str, object]],
) -> dict[str, object]:
    del step_key, logs_dir
    payload = fn()
    if hasattr(payload, 'to_payload'):
        payload = payload.to_payload()
    if isinstance(payload, dict):
        return payload
    return {}


def _validate_full_inputs(config: FullRunConfig) -> None:
    if not config.manifest.exists():
        raise ValueError(f'Manifest not found: {config.manifest}')
    if not config.source_root.exists():
        raise ValueError(f'Source root not found: {config.source_root}')
    if not config.committed_taint_config.exists():
        raise ValueError(f'Committed taint config not found: {config.committed_taint_config}')
    if not config.files and not config.all_cwes and not config.cwes:
        raise ValueError('Provide cwes, use --all, or use --files')
    if not (0.0 < config.pair_train_ratio < 1.0):
        raise ValueError(f'pair_train_ratio must be between 0 and 1: {config.pair_train_ratio}')
    if config.dedup_mode not in {'none', 'row'}:
        raise ValueError(f'dedup_mode must be one of: none, row (got {config.dedup_mode})')


def _normalize_full_run_config(config: FullRunConfig) -> FullRunConfig:
    return FullRunConfig(
        cwes=config.cwes,
        all_cwes=config.all_cwes,
        files=list(config.files),
        manifest=config.manifest.resolve(),
        source_root=config.source_root.resolve(),
        pipeline_root=config.pipeline_root.resolve(),
        run_id=config.run_id or f'run-{now_ts()}',
        committed_taint_config=config.committed_taint_config.resolve(),
        pair_split_seed=config.pair_split_seed,
        pair_train_ratio=config.pair_train_ratio,
        dedup_mode=config.dedup_mode,
    )


def _require_exists(path: Path, error_message: str) -> None:
    if not path.exists():
        raise RuntimeError(error_message)


def _require_all(required_outputs: list[tuple[Path, str]]) -> None:
    for output_path, error_message in required_outputs:
        _require_exists(output_path, error_message)


def _run_checked_internal_step(
    *,
    step_key: str,
    logs_dir: Path,
    fn: Callable[[], dict[str, object]],
    required_outputs: list[tuple[Path, str]],
) -> dict[str, object]:
    result = run_internal_step(step_key, logs_dir=logs_dir, fn=fn)
    _require_all(required_outputs)
    return result


def _run_checked_stage_call(
    *,
    step_key: str,
    paths: FullRunPaths,
    runner: Callable[..., dict[str, object]],
    required_outputs: list[tuple[Path, str]],
    **runner_kwargs: object,
) -> dict[str, object]:
    return _run_checked_internal_step(
        step_key=step_key,
        logs_dir=paths.logs_dir,
        fn=lambda: runner(**runner_kwargs),
        required_outputs=required_outputs,
    )


def _select_taint_config(
    *,
    generated_taint_config: Path,
    committed_taint_config: Path,
) -> tuple[Path, str]:
    if generated_taint_config.exists():
        return generated_taint_config, 'generated'
    return committed_taint_config.resolve(), 'fallback_committed'


def run_step01_manifest_comment_scan(
    *,
    paths: FullRunPaths,
    manifest: Path,
    source_root: Path,
) -> dict[str, object]:
    output_xml = paths.manifest_with_comments_xml
    return _run_checked_stage_call(
        step_key='01_manifest_comment_scan',
        paths=paths,
        runner=_stage01_manifest.scan_manifest_comments,
        manifest=manifest,
        source_root=source_root,
        output_xml=output_xml,
        required_outputs=[
            (output_xml, f'Expected manifest_with_comments_xml not found: {output_xml}')
        ],
    )


def run_step02a_code_field_inventory(
    *,
    paths: FullRunPaths,
    source_root: Path,
) -> dict[str, object]:
    return _run_checked_stage_call(
        step_key='02a_code_field_inventory',
        paths=paths,
        runner=_stage02a_taint.extract_unique_code_fields,
        input_xml=paths.manifest_with_comments_xml,
        source_root=source_root,
        output_dir=paths.taint_dir,
        pulse_taint_config_output=paths.generated_taint_config,
        minimal_outputs=True,
        required_outputs=[
            (
                paths.generated_taint_config,
                f'Expected generated_taint_config not found: {paths.generated_taint_config}',
            )
        ],
    )


def run_step02b_flow_build(*, paths: FullRunPaths) -> dict[str, object]:
    result = run_internal_step(
        '02b_testcase_flow_build',
        logs_dir=paths.logs_dir,
        fn=lambda: _stage02b_flow.run_stage02b_flow(
            input_xml=paths.manifest_with_comments_xml,
            source_root=paths.source_testcases_root,
            output_dir=paths.flow_dir,
            minimal_outputs=True,
        ),
    )
    _require_all(
        [
            (
                paths.stage02b.manifest_with_testcase_flows_xml,
                'Expected manifest_with_testcase_flows_xml not found: '
                f'{paths.stage02b.manifest_with_testcase_flows_xml}',
            )
        ]
    )
    return result


def run_step03_infer_and_signature(
    *,
    paths: FullRunPaths,
    selected_taint_config: Path,
    files: list[str],
    all_cwes: bool,
    cwes: Optional[list[int]],
) -> tuple[dict[str, object], dict[str, object], Path]:
    result = run_internal_step(
        '03_infer_and_signature',
        logs_dir=paths.logs_dir,
        fn=lambda: _stage03_infer.run_infer_and_signature(
            cwes=cwes,
            global_result=False,
            all_cwes=all_cwes,
            files=files,
            pulse_taint_config=selected_taint_config,
            infer_results_root=paths.infer_results_root,
            signatures_root=paths.signatures_root,
            summary_json=None,
            minimal_outputs=True,
        ),
    )

    signature_non_empty_raw = result.get('signature_non_empty_dir')
    if signature_non_empty_raw:
        signature_non_empty_dir = Path(signature_non_empty_raw)
    else:
        signature_output_dir = result.get('signature_output_dir')
        if not signature_output_dir:
            raise RuntimeError('signature_output_dir not found in infer result')
        signature_non_empty_dir = Path(signature_output_dir) / 'non_empty'

    _require_all(
        [
            (
                signature_non_empty_dir,
                f'Signature non_empty directory not found: {signature_non_empty_dir}',
            )
        ]
    )

    return result, result, signature_non_empty_dir


def run_step04_trace_flow(
    *,
    paths: FullRunPaths,
    signature_non_empty_dir: Path,
) -> dict[str, object]:
    return _run_checked_stage_call(
        step_key='04_trace_flow_filter',
        paths=paths,
        runner=_stage04_trace_flow.filter_traces_by_flow,
        flow_xml=paths.stage02b.manifest_with_testcase_flows_xml,
        signatures_dir=signature_non_empty_dir,
        output_dir=paths.trace_dir,
        minimal_outputs=True,
        required_outputs=[
            (
                paths.trace_strict_jsonl,
                f'Expected trace_flow_match_strict_jsonl not found: {paths.trace_strict_jsonl}',
            )
        ],
    )


def run_step05_pair_trace(*, paths: FullRunPaths) -> dict[str, object]:
    return _run_checked_stage_call(
        step_key='05_pair_trace_dataset',
        paths=paths,
        runner=_stage05_pair_trace.build_paired_trace_dataset,
        trace_jsonl=paths.trace_strict_jsonl,
        output_dir=paths.pair.output_dir,
        overwrite=False,
        run_dir=paths.run_dir,
        minimal_outputs=True,
        required_outputs=paths.pair.required_outputs(),
    )


def run_step06_slices(*, paths: FullRunPaths) -> dict[str, object]:
    return _run_checked_stage_call(
        step_key='06_generate_slices',
        paths=paths,
        runner=_stage06_slices.generate_slices,
        signature_db_dir=paths.pair.paired_signatures_dir,
        output_dir=paths.slices.output_dir,
        overwrite=False,
        run_dir=paths.run_dir,
        minimal_outputs=True,
        required_outputs=paths.slices.required_outputs(),
    )


def run_step07_dataset_export(
    *,
    paths: FullRunPaths,
    pair_split_seed: int,
    pair_train_ratio: float,
    dedup_mode: str,
) -> dict[str, object]:
    return _run_checked_stage_call(
        step_key='07_dataset_export',
        paths=paths,
        runner=export_primary_dataset,
        params=PrimaryDatasetExportParams(
            pairs_jsonl=paths.pair.pairs_jsonl,
            paired_signatures_dir=paths.pair.paired_signatures_dir,
            slice_dir=paths.slices.slice_dir,
            output_dir=paths.dataset.output_dir,
            split_seed=pair_split_seed,
            train_ratio=pair_train_ratio,
            dedup_mode=dedup_mode,
            minimal_outputs=True,
        ),
        required_outputs=paths.dataset.required_outputs(),
    )


def run_step07b_train_patched_counterparts(
    *,
    paths: FullRunPaths,
    dedup_mode: str,
) -> dict[str, object]:
    required_outputs = (
        paths.patched_pair.required_outputs(prefix='pairing_')
        + paths.patched_slices.required_outputs(prefix='slices_')
        + paths.patched_dataset.required_outputs(prefix='dataset_')
    )
    return _run_checked_stage_call(
        step_key='07b_train_patched_counterparts_export',
        paths=paths,
        runner=export_patched_dataset,
        params=PatchedDatasetExportParams(run_dir=paths.run_dir, dedup_mode=dedup_mode),
        required_outputs=required_outputs,
    )


def run_full_pipeline(
    config: FullRunConfig,
) -> int:
    _validate_full_inputs(config)
    config = _normalize_full_run_config(config)

    assert config.run_id is not None
    run_dir = (config.pipeline_root / config.run_id).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    paths = _build_full_run_paths(run_dir=run_dir, source_root=config.source_root)

    try:
        run_step01_manifest_comment_scan(
            paths=paths,
            manifest=config.manifest,
            source_root=config.source_root,
        )
        run_step02a_code_field_inventory(
            paths=paths,
            source_root=config.source_root,
        )
        run_step02b_flow_build(paths=paths)

        selected_taint_config, _ = _select_taint_config(
            generated_taint_config=paths.generated_taint_config,
            committed_taint_config=config.committed_taint_config,
        )
        _, _, signature_non_empty_dir = run_step03_infer_and_signature(
            paths=paths,
            selected_taint_config=selected_taint_config,
            files=config.files,
            all_cwes=config.all_cwes,
            cwes=config.cwes,
        )
        run_step04_trace_flow(
            paths=paths,
            signature_non_empty_dir=signature_non_empty_dir,
        )
        run_step05_pair_trace(paths=paths)
        run_step06_slices(paths=paths)
        run_step07_dataset_export(
            paths=paths,
            pair_split_seed=config.pair_split_seed,
            pair_train_ratio=config.pair_train_ratio,
            dedup_mode=config.dedup_mode,
        )
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


def main() -> int:
    args = parse_args()
    try:
        return run_full_pipeline(
            FullRunConfig(
                cwes=args.cwes or None,
                all_cwes=args.all_cwes,
                files=args.files,
                manifest=args.manifest,
                source_root=args.source_root,
                pipeline_root=args.pipeline_root,
                run_id=args.run_id,
                committed_taint_config=args.committed_taint_config,
                pair_split_seed=args.pair_split_seed,
                pair_train_ratio=args.pair_train_ratio,
                dedup_mode=args.dedup_mode,
            )
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
