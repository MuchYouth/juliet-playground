#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from shared import bench_runner as _bench_runner
from shared.artifact_layout import build_dataset_export_paths
from shared.paths import RESULT_DIR

JULIET_LINEVUL_NAMESPACE = 'juliet-playground'
DEFAULT_VPBENCH_ROOT = Path('/home/sojeon/Desktop/VP-Bench')
DEFAULT_CONTAINER_NAME = 'linevul'
DEFAULT_TOKENIZER_NAME = 'microsoft/codebert-base'
DEFAULT_MODEL_NAME = 'microsoft/codebert-base'
DEFAULT_TRAIN_BATCH_SIZE = 8
DEFAULT_EVAL_BATCH_SIZE = 8
DEFAULT_NUM_TRAIN_EPOCHS = 10
PRIMARY_TARGET_NAME = 'primary'
VULN_PATCH_TARGET_NAME = 'vuln_patch'
REQUIRED_COLUMNS = _bench_runner.REQUIRED_COLUMNS
PRIMARY_REQUIRED_DATASET_TYPES = _bench_runner.PRIMARY_REQUIRED_DATASET_TYPES
TEST_ONLY_REQUIRED_DATASET_TYPES = _bench_runner.TEST_ONLY_REQUIRED_DATASET_TYPES
CONTAINER_DATASET_BASE = Path('/app/RealVul/Dataset')
CONTAINER_EXPERIMENT_BASE = Path('/app/RealVul/Experiments/LineVul')
CONTAINER_LINE_VUL_SCRIPT = CONTAINER_EXPERIMENT_BASE / 'line_vul.py'


@dataclass(frozen=True)
class LineVulRunConfig:
    run_dir: Path | None
    pipeline_root: Path
    vpbench_root: Path
    container_name: str
    tokenizer_name: str
    model_name: str
    train_batch_size: int
    eval_batch_size: int
    num_train_epochs: int
    overwrite: bool
    dry_run: bool


@dataclass(frozen=True)
class LineVulPaths:
    run_dir: Path
    run_name: str
    target_name: str
    display_name: str
    source_csv: Path
    host_dataset_dir: Path
    host_output_dir: Path
    host_dataset_csv: Path
    host_prepare_log: Path
    host_train_log: Path
    host_test_log: Path
    host_train_dataset_pkl: Path
    host_val_dataset_pkl: Path
    host_test_dataset_pkl: Path
    host_best_model_dir: Path
    host_test_predictions_csv: Path
    host_line_vul_script: Path
    container_dataset_dir: Path
    container_output_dir: Path
    container_dataset_csv: Path


@dataclass(frozen=True)
class LineVulCommandStep:
    paths: LineVulPaths
    phase: str
    command: list[str]

    @property
    def label(self) -> str:
        return f'{self.paths.target_name}/{self.phase}'


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Run VP-Bench LineVul prepare/train/test from a pipeline Stage 07 CSV.'
    )
    parser.add_argument('--run-dir', type=Path, default=None)
    parser.add_argument(
        '--pipeline-root',
        type=Path,
        default=Path(RESULT_DIR) / 'pipeline-runs',
    )
    parser.add_argument('--vpbench-root', type=Path, default=DEFAULT_VPBENCH_ROOT)
    parser.add_argument('--container-name', type=str, default=DEFAULT_CONTAINER_NAME)
    parser.add_argument('--tokenizer-name', type=str, default=DEFAULT_TOKENIZER_NAME)
    parser.add_argument('--model-name', type=str, default=DEFAULT_MODEL_NAME)
    parser.add_argument('--train-batch-size', type=int, default=DEFAULT_TRAIN_BATCH_SIZE)
    parser.add_argument('--eval-batch-size', type=int, default=DEFAULT_EVAL_BATCH_SIZE)
    parser.add_argument('--num-train-epochs', type=int, default=DEFAULT_NUM_TRAIN_EPOCHS)
    parser.add_argument('--overwrite', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    return parser.parse_args()


def normalize_config(config: LineVulRunConfig) -> LineVulRunConfig:
    return LineVulRunConfig(
        run_dir=config.run_dir.resolve() if config.run_dir is not None else None,
        pipeline_root=config.pipeline_root.resolve(),
        vpbench_root=config.vpbench_root.resolve(),
        container_name=config.container_name,
        tokenizer_name=config.tokenizer_name,
        model_name=config.model_name,
        train_batch_size=config.train_batch_size,
        eval_batch_size=config.eval_batch_size,
        num_train_epochs=config.num_train_epochs,
        overwrite=config.overwrite,
        dry_run=config.dry_run,
    )


def validate_config(config: LineVulRunConfig) -> None:
    if config.train_batch_size <= 0:
        raise ValueError(f'train_batch_size must be > 0: {config.train_batch_size}')
    if config.eval_batch_size <= 0:
        raise ValueError(f'eval_batch_size must be > 0: {config.eval_batch_size}')
    if config.num_train_epochs <= 0:
        raise ValueError(f'num_train_epochs must be > 0: {config.num_train_epochs}')


def resolve_run_dir(config: LineVulRunConfig) -> Path:
    return _bench_runner.resolve_run_dir(
        run_dir=config.run_dir,
        pipeline_root=config.pipeline_root,
    )


validate_stage07_csv = _bench_runner.validate_stage07_csv
_existing_output_targets = _bench_runner.existing_output_targets
_remove_host_output_path = _bench_runner.remove_host_output_path
stage_source_csv = _bench_runner.stage_source_csv
check_container_running = _bench_runner.check_container_running
run_logged_command = _bench_runner.run_logged_command
require_exists = _bench_runner.require_exists


def build_linevul_paths(
    config: LineVulRunConfig,
    run_dir: Path,
    *,
    target_name: str,
) -> LineVulPaths:
    if target_name == PRIMARY_TARGET_NAME:
        dataset_paths = build_dataset_export_paths(run_dir / '07_dataset_export')
        source_csv = dataset_paths['csv_path']
        relative_parts: tuple[str, ...] = ()
    elif target_name == VULN_PATCH_TARGET_NAME:
        source_csv = run_dir / '07_dataset_export' / 'vuln_patch' / 'Real_Vul_data.csv'
        relative_parts = (VULN_PATCH_TARGET_NAME,)
    else:
        raise ValueError(f'Unsupported LineVul target: {target_name}')

    run_name = run_dir.name
    display_name = '/'.join((run_name, *relative_parts)) if relative_parts else run_name
    base_host_dataset_dir = (
        config.vpbench_root
        / 'downloads'
        / 'RealVul'
        / 'datasets'
        / JULIET_LINEVUL_NAMESPACE
        / run_name
    )
    base_host_output_dir = (
        config.vpbench_root
        / 'baseline'
        / 'RealVul'
        / 'Experiments'
        / 'LineVul'
        / JULIET_LINEVUL_NAMESPACE
        / run_name
    )
    host_dataset_dir = base_host_dataset_dir.joinpath(*relative_parts)
    host_output_dir = base_host_output_dir.joinpath(*relative_parts)
    container_dataset_dir = (CONTAINER_DATASET_BASE / JULIET_LINEVUL_NAMESPACE / run_name).joinpath(
        *relative_parts
    )
    container_output_dir = (
        CONTAINER_EXPERIMENT_BASE / JULIET_LINEVUL_NAMESPACE / run_name
    ).joinpath(*relative_parts)
    return LineVulPaths(
        run_dir=run_dir,
        run_name=run_name,
        target_name=target_name,
        display_name=display_name,
        source_csv=source_csv,
        host_dataset_dir=host_dataset_dir,
        host_output_dir=host_output_dir,
        host_dataset_csv=host_dataset_dir / 'Real_Vul_data.csv',
        host_prepare_log=host_output_dir / 'prepare.log',
        host_train_log=host_output_dir / 'train.log',
        host_test_log=host_output_dir / 'test.log',
        host_train_dataset_pkl=host_dataset_dir / 'train_dataset.pkl',
        host_val_dataset_pkl=host_dataset_dir / 'val_dataset.pkl',
        host_test_dataset_pkl=host_dataset_dir / 'test_dataset.pkl',
        host_best_model_dir=host_output_dir / 'best_model',
        host_test_predictions_csv=host_output_dir / 'test_pred_with_code.csv',
        host_line_vul_script=(
            config.vpbench_root / 'baseline' / 'RealVul' / 'Experiments' / 'LineVul' / 'line_vul.py'
        ),
        container_dataset_dir=container_dataset_dir,
        container_output_dir=container_output_dir,
        container_dataset_csv=container_dataset_dir / 'Real_Vul_data.csv',
    )


def validate_paths(paths: LineVulPaths) -> None:
    if not paths.run_dir.exists():
        raise ValueError(f'Pipeline run dir not found: {paths.run_dir}')
    if not paths.source_csv.exists():
        raise ValueError(f'Stage 07 dataset CSV not found: {paths.source_csv}')
    if not paths.host_line_vul_script.exists():
        raise ValueError(f'VP-Bench line_vul.py not found: {paths.host_line_vul_script}')


def discover_linevul_targets(config: LineVulRunConfig, run_dir: Path) -> list[LineVulPaths]:
    primary_paths = build_linevul_paths(config, run_dir, target_name=PRIMARY_TARGET_NAME)
    vuln_patch_paths = build_linevul_paths(config, run_dir, target_name=VULN_PATCH_TARGET_NAME)
    targets = [primary_paths]
    if vuln_patch_paths.source_csv.exists():
        targets.append(vuln_patch_paths)
    return targets


def ensure_output_targets(paths_list: Sequence[LineVulPaths], *, overwrite: bool) -> None:
    _bench_runner.ensure_output_targets(paths_list, overwrite=overwrite, runner_name='LineVul')


def _remove_output_targets_via_container(container_name: str, paths: LineVulPaths) -> None:
    _bench_runner.remove_output_targets_via_container(
        container_name=container_name,
        paths=paths,
        runner_name='LineVul',
        subprocess_run=subprocess.run,
    )


def cleanup_output_targets(paths_list: Sequence[LineVulPaths], *, container_name: str) -> None:
    _bench_runner.cleanup_output_targets(
        paths_list,
        remove_host_output_path_fn=_remove_host_output_path,
        remove_container_targets_fn=lambda paths: _remove_output_targets_via_container(
            container_name,
            paths,
        ),
    )


def stage_reused_best_model(source_paths: LineVulPaths, target_paths: LineVulPaths) -> None:
    require_exists(source_paths.host_best_model_dir / 'config.json', 'best_model/config.json')
    target_paths.host_output_dir.mkdir(parents=True, exist_ok=True)

    if target_paths.host_best_model_dir.is_symlink() or target_paths.host_best_model_dir.is_file():
        target_paths.host_best_model_dir.unlink()
    elif target_paths.host_best_model_dir.exists():
        shutil.rmtree(target_paths.host_best_model_dir)

    try:
        relative_target = Path(
            os.path.relpath(
                source_paths.host_best_model_dir,
                start=target_paths.host_best_model_dir.parent,
            )
        )
        target_paths.host_best_model_dir.symlink_to(
            relative_target,
            target_is_directory=True,
        )
    except OSError:
        shutil.copytree(source_paths.host_best_model_dir, target_paths.host_best_model_dir)


def build_line_vul_command(
    config: LineVulRunConfig,
    paths: LineVulPaths,
    *,
    phase: str,
) -> list[str]:
    if phase == 'prepare':
        phase_flags = ['--prepare_dataset']
        train_batch_size = config.eval_batch_size
        eval_batch_size = config.eval_batch_size
    elif phase == 'train':
        phase_flags = ['--train']
        train_batch_size = config.train_batch_size
        eval_batch_size = config.train_batch_size
    elif phase == 'test':
        phase_flags = ['--test_predict']
        train_batch_size = config.eval_batch_size
        eval_batch_size = config.eval_batch_size
    else:
        raise ValueError(f'Unsupported LineVul phase: {phase}')

    return [
        'docker',
        'exec',
        config.container_name,
        'python',
        str(CONTAINER_LINE_VUL_SCRIPT),
        '--dataset_csv_path',
        str(paths.container_dataset_csv),
        '--dataset_path',
        str(paths.container_dataset_dir),
        '--output_dir',
        str(paths.container_output_dir),
        '--tokenizer_name',
        config.tokenizer_name,
        '--model_name',
        config.model_name,
        '--per_device_train_batch_size',
        str(train_batch_size),
        '--per_device_eval_batch_size',
        str(eval_batch_size),
        '--num_train_epochs',
        str(config.num_train_epochs),
        *phase_flags,
    ]


def build_command_steps(
    config: LineVulRunConfig,
    paths_list: Sequence[LineVulPaths],
) -> list[LineVulCommandStep]:
    commands: list[LineVulCommandStep] = []
    for paths in paths_list:
        if paths.target_name == PRIMARY_TARGET_NAME:
            phases = ('prepare', 'train', 'test')
        elif paths.target_name == VULN_PATCH_TARGET_NAME:
            phases = ('prepare', 'test')
        else:
            raise ValueError(f'Unsupported LineVul target: {paths.target_name}')

        for phase in phases:
            commands.append(
                LineVulCommandStep(
                    paths=paths,
                    phase=phase,
                    command=build_line_vul_command(config, paths, phase=phase),
                )
            )
    return commands


def print_planned_commands(
    commands: Sequence[LineVulCommandStep], paths_list: Sequence[LineVulPaths]
) -> None:
    if not paths_list:
        return
    print(f'Pipeline run: {paths_list[0].run_dir}')
    for paths in paths_list:
        print(f'Target [{paths.target_name}] Stage 07 CSV: {paths.source_csv}')
        print(f'Target [{paths.target_name}] Host dataset dir: {paths.host_dataset_dir}')
        print(f'Target [{paths.target_name}] Host output dir: {paths.host_output_dir}')
        print(f'Target [{paths.target_name}] Container dataset dir: {paths.container_dataset_dir}')
        print(f'Target [{paths.target_name}] Container output dir: {paths.container_output_dir}')
    for step in commands:
        print(f'[{step.label}] {" ".join(step.command)}')


def print_completion_summary(paths_list: Sequence[LineVulPaths]) -> None:
    print('LineVul run completed.')
    for paths in paths_list:
        print(f'  - [{paths.target_name}] staged_csv: {paths.host_dataset_csv}')
        print(f'  - [{paths.target_name}] dataset_pickles: {paths.host_dataset_dir}')
        print(f'  - [{paths.target_name}] best_model: {paths.host_best_model_dir}')
        print(f'  - [{paths.target_name}] test_predictions: {paths.host_test_predictions_csv}')
        print(f'  - [{paths.target_name}] logs: {paths.host_output_dir}')


def run_linevul_from_pipeline(config: LineVulRunConfig) -> int:
    validate_config(config)
    run_dir = resolve_run_dir(config)
    paths_list = discover_linevul_targets(config, run_dir)
    primary_paths = paths_list[0]
    vuln_patch_paths = next(
        (paths for paths in paths_list if paths.target_name == VULN_PATCH_TARGET_NAME),
        None,
    )

    for paths in paths_list:
        validate_paths(paths)
        required_dataset_types = (
            PRIMARY_REQUIRED_DATASET_TYPES
            if paths.target_name == PRIMARY_TARGET_NAME
            else TEST_ONLY_REQUIRED_DATASET_TYPES
        )
        validate_stage07_csv(paths.source_csv, required_dataset_types=required_dataset_types)

    ensure_output_targets(paths_list, overwrite=config.overwrite)
    commands = build_command_steps(config, paths_list)

    if config.dry_run:
        print_planned_commands(commands, paths_list)
        return 0

    check_container_running(config.container_name)
    if config.overwrite:
        cleanup_output_targets(paths_list, container_name=config.container_name)
    for paths in paths_list:
        stage_source_csv(paths)

    primary_prepare_step = next(
        step
        for step in commands
        if step.paths.target_name == PRIMARY_TARGET_NAME and step.phase == 'prepare'
    )
    print(f'Running LineVul prepare for {primary_prepare_step.paths.display_name}...')
    run_logged_command(primary_prepare_step.command, primary_paths.host_prepare_log)
    require_exists(primary_paths.host_train_dataset_pkl, 'train_dataset.pkl')
    require_exists(primary_paths.host_val_dataset_pkl, 'val_dataset.pkl')
    require_exists(primary_paths.host_test_dataset_pkl, 'test_dataset.pkl')

    primary_train_step = next(
        step
        for step in commands
        if step.paths.target_name == PRIMARY_TARGET_NAME and step.phase == 'train'
    )
    print(f'Running LineVul train for {primary_train_step.paths.display_name}...')
    run_logged_command(primary_train_step.command, primary_paths.host_train_log)
    require_exists(primary_paths.host_best_model_dir / 'config.json', 'best_model/config.json')

    primary_test_step = next(
        step
        for step in commands
        if step.paths.target_name == PRIMARY_TARGET_NAME and step.phase == 'test'
    )
    print(f'Running LineVul test for {primary_test_step.paths.display_name}...')
    run_logged_command(primary_test_step.command, primary_paths.host_test_log)
    require_exists(primary_paths.host_test_predictions_csv, 'test_pred_with_code.csv')

    if vuln_patch_paths is not None:
        stage_reused_best_model(primary_paths, vuln_patch_paths)

        vuln_patch_prepare_step = next(
            step
            for step in commands
            if step.paths.target_name == VULN_PATCH_TARGET_NAME and step.phase == 'prepare'
        )
        print(f'Running LineVul prepare for {vuln_patch_prepare_step.paths.display_name}...')
        run_logged_command(vuln_patch_prepare_step.command, vuln_patch_paths.host_prepare_log)
        require_exists(vuln_patch_paths.host_test_dataset_pkl, 'test_dataset.pkl')

        vuln_patch_test_step = next(
            step
            for step in commands
            if step.paths.target_name == VULN_PATCH_TARGET_NAME and step.phase == 'test'
        )
        print(f'Running LineVul test for {vuln_patch_test_step.paths.display_name}...')
        run_logged_command(vuln_patch_test_step.command, vuln_patch_paths.host_test_log)
        require_exists(
            vuln_patch_paths.host_best_model_dir / 'config.json', 'best_model/config.json'
        )
        require_exists(vuln_patch_paths.host_test_predictions_csv, 'test_pred_with_code.csv')

    print_completion_summary(paths_list)
    return 0


def main() -> int:
    args = parse_args()
    config = normalize_config(
        LineVulRunConfig(
            run_dir=args.run_dir,
            pipeline_root=args.pipeline_root,
            vpbench_root=args.vpbench_root,
            container_name=args.container_name,
            tokenizer_name=args.tokenizer_name,
            model_name=args.model_name,
            train_batch_size=args.train_batch_size,
            eval_batch_size=args.eval_batch_size,
            num_train_epochs=args.num_train_epochs,
            overwrite=args.overwrite,
            dry_run=args.dry_run,
        )
    )
    try:
        return run_linevul_from_pipeline(config)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
