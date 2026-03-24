from __future__ import annotations

import csv
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable, Protocol, Sequence

from shared.pipeline_runs import find_latest_pipeline_run_dir

REQUIRED_COLUMNS = {
    'processed_func',
    'vulnerable_line_numbers',
    'dataset_type',
    'target',
}
PRIMARY_REQUIRED_DATASET_TYPES = frozenset({'train_val', 'test'})
TEST_ONLY_REQUIRED_DATASET_TYPES = frozenset({'test'})


class RunnerPathSpec(Protocol):
    display_name: str
    host_dataset_dir: Path
    host_output_dir: Path
    container_dataset_dir: Path
    container_output_dir: Path
    source_csv: Path
    host_dataset_csv: Path


def resolve_run_dir(*, run_dir: Path | None, pipeline_root: Path) -> Path:
    if run_dir is not None:
        if not run_dir.exists():
            raise ValueError(f'Pipeline run dir not found: {run_dir}')
        return run_dir
    try:
        return find_latest_pipeline_run_dir(pipeline_root)
    except FileNotFoundError as exc:
        raise ValueError(str(exc)) from exc


def validate_stage07_csv(
    path: Path,
    *,
    required_dataset_types: frozenset[str] = PRIMARY_REQUIRED_DATASET_TYPES,
) -> dict[str, int]:
    with path.open(newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        fieldnames = set(reader.fieldnames or [])
        missing_columns = sorted(REQUIRED_COLUMNS - fieldnames)
        if missing_columns:
            raise ValueError(
                f'Stage 07 dataset CSV missing required columns: {", ".join(missing_columns)}'
            )

        dataset_type_counts: dict[str, int] = {}
        row_count = 0
        for row in reader:
            row_count += 1
            dataset_type = str(row.get('dataset_type') or '').strip()
            dataset_type_counts[dataset_type] = dataset_type_counts.get(dataset_type, 0) + 1

    if row_count == 0:
        raise ValueError(f'Stage 07 dataset CSV is empty: {path}')

    missing_dataset_types = sorted(
        label for label in required_dataset_types if dataset_type_counts.get(label, 0) == 0
    )
    if missing_dataset_types:
        if required_dataset_types == PRIMARY_REQUIRED_DATASET_TYPES:
            raise ValueError(
                'Stage 07 dataset CSV must contain both train_val and test rows; '
                f'missing: {", ".join(missing_dataset_types)}'
            )
        if required_dataset_types == TEST_ONLY_REQUIRED_DATASET_TYPES:
            raise ValueError(
                'Stage 07 dataset CSV must contain test rows; '
                f'missing: {", ".join(missing_dataset_types)}'
            )
        raise ValueError(
            'Stage 07 dataset CSV missing required dataset_type rows: '
            f'{", ".join(missing_dataset_types)}'
        )
    return dataset_type_counts


def existing_output_targets(paths_list: Sequence[RunnerPathSpec]) -> list[Path]:
    existing: list[Path] = []
    for paths in paths_list:
        for path in (paths.host_dataset_dir, paths.host_output_dir):
            if path.exists() or path.is_symlink():
                existing.append(path)
    return list(dict.fromkeys(existing))


def ensure_output_targets(
    paths_list: Sequence[RunnerPathSpec],
    *,
    overwrite: bool,
    runner_name: str,
) -> None:
    unique_existing = existing_output_targets(paths_list)
    if unique_existing and not overwrite:
        joined = ', '.join(str(path) for path in unique_existing)
        run_names = ', '.join(dict.fromkeys(paths.display_name for paths in paths_list))
        raise ValueError(
            f'{runner_name} output already exists for run {run_names}: {joined} '
            '(use --overwrite to replace it)'
        )


def remove_host_output_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def remove_output_targets_via_container(
    *,
    container_name: str,
    paths: RunnerPathSpec,
    runner_name: str,
    subprocess_run: Callable[..., Any] = subprocess.run,
) -> None:
    result = subprocess_run(
        [
            'docker',
            'exec',
            container_name,
            'rm',
            '-rf',
            str(paths.container_dataset_dir),
            str(paths.container_output_dir),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if getattr(result, 'returncode', 1) != 0:
        message = (
            str(getattr(result, 'stderr', '')).strip()
            or str(getattr(result, 'stdout', '')).strip()
            or 'unknown docker rm error'
        )
        raise RuntimeError(
            f'Failed to clean {runner_name} output via container '
            f'{container_name} for {paths.display_name}: {message}'
        )


def cleanup_output_targets(
    paths_list: Sequence[RunnerPathSpec],
    *,
    remove_host_output_path_fn: Callable[[Path], None] = remove_host_output_path,
    remove_container_targets_fn: Callable[[RunnerPathSpec], None],
) -> None:
    for paths in paths_list:
        try:
            for path in sorted(
                (paths.host_dataset_dir, paths.host_output_dir),
                key=lambda item: (len(item.parts), str(item)),
                reverse=True,
            ):
                remove_host_output_path_fn(path)
        except PermissionError:
            remove_container_targets_fn(paths)
            for path in sorted(
                (paths.host_dataset_dir, paths.host_output_dir),
                key=lambda item: (len(item.parts), str(item)),
                reverse=True,
            ):
                if path.exists() or path.is_symlink():
                    remove_host_output_path_fn(path)


def stage_source_csv(paths: RunnerPathSpec) -> None:
    paths.host_dataset_dir.mkdir(parents=True, exist_ok=True)
    paths.host_output_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(paths.source_csv, paths.host_dataset_csv)


def check_container_running(
    container_name: str,
    *,
    subprocess_run: Callable[..., Any] = subprocess.run,
) -> None:
    result = subprocess_run(
        ['docker', 'inspect', '--format', '{{.State.Running}}', container_name],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if getattr(result, 'returncode', 1) != 0:
        message = (
            str(getattr(result, 'stderr', '')).strip()
            or str(getattr(result, 'stdout', '')).strip()
            or 'unknown docker inspect error'
        )
        raise RuntimeError(f'Failed to inspect Docker container {container_name}: {message}')
    if str(getattr(result, 'stdout', '')).strip().lower() != 'true':
        raise RuntimeError(f'Docker container is not running: {container_name}')


def run_logged_command(command: Sequence[str], log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open('w', encoding='utf-8') as log_fp:
        log_fp.write(f'$ {" ".join(command)}\n')
        log_fp.flush()
        process = subprocess.Popen(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert process.stdout is not None
        try:
            for line in process.stdout:
                print(line, end='')
                log_fp.write(line)
                log_fp.flush()
        finally:
            process.stdout.close()
        return_code = process.wait()
    if return_code != 0:
        raise subprocess.CalledProcessError(return_code, list(command))


def require_exists(path: Path, label: str) -> None:
    if not path.exists():
        raise RuntimeError(f'Expected {label} not found: {path}')
