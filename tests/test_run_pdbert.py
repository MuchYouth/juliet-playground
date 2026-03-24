from __future__ import annotations

import csv
import os
from pathlib import Path

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main, write_text


def _make_vpbench_root(root: Path) -> Path:
    baseline_root = root / 'baseline' / 'PDBERT'
    configs_dir = baseline_root / 'downstream' / 'configs' / 'vul_detect'
    experiment_dir = root / 'experiment' / 'scripts' / 'pdbert'

    write_text(baseline_root / 'prepare_dataset.py', '# stub prepare_dataset\n')
    write_text(
        baseline_root / 'downstream' / 'train_eval_from_config.py',
        '# stub train/eval entrypoint\n',
    )
    write_text(
        configs_dir / 'pdbert_realvul.jsonnet',
        "local data_base_path = '/tmp/pdbert-data/';\n{}\n",
    )
    write_text(
        configs_dir / 'pdbert_vpbench.jsonnet',
        "local data_base_path = '/tmp/pdbert-data/';\n{}\n",
    )
    write_text(experiment_dir / 'analyze_prediction.py', '# stub analyze script\n')
    return root


def _write_stage07_csv(path: Path, *, include_test_rows: bool = True) -> None:
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
    rows = [
        {
            'file_name': '1',
            'unique_id': '1',
            'target': '1',
            'vulnerable_line_numbers': '1',
            'project': 'Juliet',
            'source_signature_path': 'sig-a.json',
            'commit_hash': '',
            'dataset_type': 'train_val',
            'processed_func': 'int bad(void) {\n    return 1;\n}\n',
        },
        {
            'file_name': '2',
            'unique_id': '2',
            'target': '0',
            'vulnerable_line_numbers': '',
            'project': 'Juliet',
            'source_signature_path': 'sig-b.json',
            'commit_hash': '',
            'dataset_type': 'test',
            'processed_func': 'int good(void) {\n    return 0;\n}\n',
        },
    ]
    if not include_test_rows:
        rows = rows[:1]

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_vuln_patch_csv(path: Path) -> None:
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
    rows = [
        {
            'file_name': '10',
            'unique_id': '10',
            'target': '1',
            'vulnerable_line_numbers': '1',
            'project': 'Juliet',
            'source_signature_path': 'sig-vuln.json',
            'commit_hash': '',
            'dataset_type': 'test',
            'processed_func': 'int bad_variant(void) {\n    return 1;\n}\n',
        },
        {
            'file_name': '11',
            'unique_id': '11',
            'target': '0',
            'vulnerable_line_numbers': '',
            'project': 'Juliet',
            'source_signature_path': 'sig-patch.json',
            'commit_hash': '',
            'dataset_type': 'test',
            'processed_func': 'int good_variant(void) {\n    return 0;\n}\n',
        },
    ]

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def test_run_pdbert_uses_latest_run_in_dry_run_mode(tmp_path, capsys):
    module = load_module_from_path('test_run_pdbert_dry_run', REPO_ROOT / 'tools/run_pdbert.py')

    pipeline_root = tmp_path / 'pipeline-runs'
    older_csv = pipeline_root / 'run-older' / '07_dataset_export' / 'Real_Vul_data.csv'
    newer_csv = pipeline_root / 'run-newer' / '07_dataset_export' / 'Real_Vul_data.csv'
    _write_stage07_csv(older_csv)
    _write_stage07_csv(newer_csv)
    _write_vuln_patch_csv(newer_csv.parent / 'vuln_patch' / 'Real_Vul_data.csv')
    os.utime(older_csv.parent.parent, (1, 1))
    os.utime(newer_csv.parent.parent, (2, 2))
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')

    result = run_module_main(
        module,
        [
            '--pipeline-root',
            str(pipeline_root),
            '--vpbench-root',
            str(vpbench_root),
            '--dry-run',
        ],
    )

    assert result == 0
    captured = capsys.readouterr()
    assert 'run-newer' in captured.out
    assert '[analyze/setup]' in captured.out
    assert '[primary/prepare]' in captured.out
    assert '[primary/train]' in captured.out
    assert '[primary/test]' in captured.out
    assert '[primary/analyze]' in captured.out
    assert '[vuln_patch/prepare]' in captured.out
    assert '[vuln_patch/test]' in captured.out
    assert '[vuln_patch/analyze]' in captured.out


def test_run_pdbert_stages_csv_configs_and_runs_primary_pipeline(tmp_path, monkeypatch):
    module = load_module_from_path('test_run_pdbert_execute', REPO_ROOT / 'tools/run_pdbert.py')

    run_dir = tmp_path / 'pipeline-runs' / 'run-demo'
    source_csv = run_dir / '07_dataset_export' / 'Real_Vul_data.csv'
    _write_stage07_csv(source_csv)
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')

    config = module.normalize_config(
        module.PDBERTRunConfig(
            run_dir=run_dir,
            pipeline_root=tmp_path / 'pipeline-runs',
            vpbench_root=vpbench_root,
            container_name='pdbert',
            overwrite=False,
            dry_run=False,
        )
    )
    primary_paths = module.build_pdbert_paths(
        config, run_dir, target_name=module.PRIMARY_TARGET_NAME
    )

    commands: list[tuple[list[str], Path]] = []
    copied_scripts: list[str] = []

    def fake_run_logged_command(command, log_path):
        commands.append((list(command), log_path))
        write_text(log_path, '$ ' + ' '.join(command) + '\n')
        if log_path == primary_paths.host_prepare_log:
            write_text(primary_paths.host_train_json, '{}\n')
            write_text(primary_paths.host_validate_json, '{}\n')
            write_text(primary_paths.host_test_json, '{}\n')
        elif log_path == primary_paths.host_train_log:
            write_text(primary_paths.host_model_config_json, '{}\n')
            write_text(primary_paths.host_model_archive, 'model\n')
        elif log_path == primary_paths.host_analyze_log:
            write_text(primary_paths.host_eval_result_csv, 'metric,value\nf1,1.0\n')
            write_text(primary_paths.host_analysis_json, '{}\n')

    monkeypatch.setattr(module, 'check_container_running', lambda _container_name: None)
    monkeypatch.setattr(module, 'run_logged_command', fake_run_logged_command)
    monkeypatch.setattr(
        module,
        'copy_analyze_script_to_container',
        lambda paths, container_name: copied_scripts.append(
            f'{paths.display_name}:{container_name}'
        ),
    )

    result = run_module_main(
        module,
        [
            '--run-dir',
            str(run_dir),
            '--vpbench-root',
            str(vpbench_root),
        ],
    )

    assert result == 0
    assert [log_path for _, log_path in commands] == [
        primary_paths.host_prepare_log,
        primary_paths.host_train_log,
        primary_paths.host_test_log,
        primary_paths.host_analyze_log,
    ]
    assert '--train-only' in commands[1][0][-1]
    assert '--test-only' in commands[2][0][-1]
    assert copied_scripts == ['run-demo:pdbert']
    assert primary_paths.host_dataset_csv.read_text(encoding='utf-8') == source_csv.read_text(
        encoding='utf-8'
    )
    assert primary_paths.host_runtime_train_config.exists()
    assert primary_paths.host_runtime_test_config.exists()
    assert str(
        primary_paths.container_dataset_dir
    ) + '/' in primary_paths.host_runtime_train_config.read_text(encoding='utf-8')
    assert str(
        primary_paths.container_dataset_dir
    ) + '/' in primary_paths.host_runtime_test_config.read_text(encoding='utf-8')
    assert primary_paths.host_eval_result_csv.exists()
    assert primary_paths.host_analysis_json.exists()
