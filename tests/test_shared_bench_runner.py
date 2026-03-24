from __future__ import annotations

import csv
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.helpers import REPO_ROOT, load_module_from_path, write_text


@dataclass(frozen=True)
class DummyPaths:
    display_name: str
    host_dataset_dir: Path
    host_output_dir: Path
    container_dataset_dir: Path
    container_output_dir: Path
    source_csv: Path
    host_dataset_csv: Path


def _load_module():
    return load_module_from_path(
        'test_shared_bench_runner_module',
        REPO_ROOT / 'tools/shared/bench_runner.py',
    )


def _write_stage07_csv(path: Path, *, dataset_types: list[str]) -> None:
    fieldnames = [
        'file_name',
        'unique_id',
        'target',
        'vulnerable_line_numbers',
        'project',
        'source_signature_path',
        'commit_hash',
        'dataset_type',
        'processed_func',
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row_id, dataset_type in enumerate(dataset_types, start=1):
            writer.writerow(
                {
                    'file_name': str(row_id),
                    'unique_id': str(row_id),
                    'target': '1' if row_id == 1 else '0',
                    'vulnerable_line_numbers': '1' if row_id == 1 else '',
                    'project': 'Juliet',
                    'source_signature_path': f'sig-{row_id}.json',
                    'commit_hash': '',
                    'dataset_type': dataset_type,
                    'processed_func': f'int fn_{row_id}(void) {{ return {row_id}; }}\n',
                }
            )


def test_validate_stage07_csv_returns_dataset_type_counts(tmp_path):
    module = _load_module()
    csv_path = tmp_path / 'Real_Vul_data.csv'
    _write_stage07_csv(csv_path, dataset_types=['train_val', 'test'])

    counts = module.validate_stage07_csv(csv_path)

    assert counts == {'train_val': 1, 'test': 1}


def test_validate_stage07_csv_requires_test_rows_for_test_only_mode(tmp_path):
    module = _load_module()
    csv_path = tmp_path / 'Real_Vul_data.csv'
    _write_stage07_csv(csv_path, dataset_types=['train_val'])

    with pytest.raises(ValueError, match='must contain test rows'):
        module.validate_stage07_csv(
            csv_path,
            required_dataset_types=module.TEST_ONLY_REQUIRED_DATASET_TYPES,
        )


def test_ensure_output_targets_requires_overwrite(tmp_path):
    module = _load_module()
    source_csv = tmp_path / 'source.csv'
    write_text(source_csv, 'header\n')
    paths = DummyPaths(
        display_name='run-demo',
        host_dataset_dir=tmp_path / 'host-dataset',
        host_output_dir=tmp_path / 'host-output',
        container_dataset_dir=Path('/container/dataset'),
        container_output_dir=Path('/container/output'),
        source_csv=source_csv,
        host_dataset_csv=tmp_path / 'host-dataset' / 'Real_Vul_data.csv',
    )
    paths.host_output_dir.mkdir(parents=True)

    with pytest.raises(ValueError, match='use --overwrite to replace it'):
        module.ensure_output_targets([paths], overwrite=False, runner_name='DemoRunner')


def test_cleanup_output_targets_falls_back_to_container_cleanup_on_permission_error(tmp_path):
    module = _load_module()
    source_csv = tmp_path / 'source.csv'
    write_text(source_csv, 'header\n')
    paths = DummyPaths(
        display_name='run-demo',
        host_dataset_dir=tmp_path / 'host-dataset',
        host_output_dir=tmp_path / 'host-output',
        container_dataset_dir=Path('/container/dataset'),
        container_output_dir=Path('/container/output'),
        source_csv=source_csv,
        host_dataset_csv=tmp_path / 'host-dataset' / 'Real_Vul_data.csv',
    )
    write_text(paths.host_dataset_dir / 'train.json', '{}\n')
    write_text(paths.host_output_dir / 'train.log', 'log\n')

    removed_paths: list[Path] = []
    container_calls: list[str] = []

    def fake_remove_host_output_path(path: Path) -> None:
        removed_paths.append(path)
        if path == paths.host_output_dir and len(removed_paths) == 1:
            raise PermissionError('permission denied')
        module.remove_host_output_path(path)

    def fake_remove_container_targets(item: DummyPaths) -> None:
        container_calls.append(item.display_name)
        module.remove_host_output_path(item.host_output_dir)
        module.remove_host_output_path(item.host_dataset_dir)

    module.cleanup_output_targets(
        [paths],
        remove_host_output_path_fn=fake_remove_host_output_path,
        remove_container_targets_fn=fake_remove_container_targets,
    )

    assert not paths.host_dataset_dir.exists()
    assert not paths.host_output_dir.exists()
    assert container_calls == ['run-demo']


def test_run_logged_command_writes_log_and_raises_on_failure(tmp_path):
    module = _load_module()
    log_path = tmp_path / 'command.log'

    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        module.run_logged_command(
            [
                'python3',
                '-c',
                "print('hello from runner'); import sys; sys.exit(3)",
            ],
            log_path,
        )

    assert exc_info.value.returncode == 3
    log_text = log_path.read_text(encoding='utf-8')
    assert '$ python3 -c' in log_text
    assert 'hello from runner' in log_text
