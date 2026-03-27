from __future__ import annotations

import csv
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
        configs_dir / 'pdbert_vpbench.jsonnet',
        "local data_base_path = '/tmp/pdbert-data/';\n{}\n",
    )
    write_text(experiment_dir / 'analyze_prediction.py', '# stub analyze script\n')
    return root


def _make_model_dir(root: Path) -> Path:
    write_text(root / 'config.json', '{}\n')
    write_text(root / 'model.tar.gz', 'model\n')
    return root


def _write_test_only_csv(path: Path) -> None:
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
            'vulnerable_line_numbers': '2',
            'project': 'DemoProject',
            'source_signature_path': 'sig-a.json',
            'commit_hash': '',
            'dataset_type': 'test',
            'processed_func': 'int bad(void) {\n    return 1;\n}\n',
        }
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_row_manifest(path: Path) -> None:
    write_text(
        path,
        '{"row_id": 1, "trace_id": "trace-a", "matched_source_lines": [{"file_path": "src/demo.c", "line_number": 5}]}\n',
    )


def test_run_pdbert_eval_only_dry_run_prints_prepare_test_analyze(tmp_path, capsys):
    module = load_module_from_path(
        'test_run_pdbert_eval_only_dry_run',
        REPO_ROOT / 'tools/run_pdbert_eval_only.py',
    )

    dataset_csv = tmp_path / 'dataset' / 'Real_Vul_data.csv'
    _write_test_only_csv(dataset_csv)
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')
    model_dir = _make_model_dir(tmp_path / 'model')

    result = run_module_main(
        module,
        [
            '--dataset-csv',
            str(dataset_csv),
            '--model-dir',
            str(model_dir),
            '--vpbench-root',
            str(vpbench_root),
            '--dry-run',
        ],
    )

    assert result == 0
    captured = capsys.readouterr()
    assert '[eval_only/prepare]' in captured.out
    assert '[eval_only/test]' in captured.out
    assert '[eval_only/analyze]' in captured.out
    assert '[eval_only/train]' not in captured.out


def test_run_pdbert_eval_only_executes_prepare_test_analyze_and_joins_predictions(
    tmp_path,
    monkeypatch,
):
    module = load_module_from_path(
        'test_run_pdbert_eval_only_execute',
        REPO_ROOT / 'tools/run_pdbert_eval_only.py',
    )

    dataset_csv = tmp_path / 'dataset' / 'Real_Vul_data.csv'
    row_manifest = tmp_path / 'dataset' / 'trace_row_manifest.jsonl'
    _write_test_only_csv(dataset_csv)
    _write_row_manifest(row_manifest)
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')
    model_dir = _make_model_dir(tmp_path / 'model')

    config = module.normalize_config(
        module.PDBERTEvalOnlyConfig(
            dataset_csv=dataset_csv,
            row_manifest=row_manifest,
            model_dir=model_dir,
            vpbench_root=vpbench_root,
            container_name='pdbert',
            eval_name='demo-eval',
            overwrite=False,
            dry_run=False,
        )
    )
    paths = module.build_eval_only_paths(config)

    commands: list[tuple[list[str], Path]] = []
    copied_scripts: list[str] = []

    def fake_run_logged_command(command, log_path):
        commands.append((list(command), log_path))
        write_text(log_path, '$ ' + ' '.join(command) + '\n')
        if log_path == paths.host_prepare_log:
            write_text(paths.host_dataset_dir / 'test.json', '{}\n')
        elif log_path == paths.host_analyze_log:
            write_text(paths.host_eval_result_csv, 'unique_id,score\n1,0.99\n')
            write_text(paths.host_analysis_json, '{}\n')
            write_text(paths.host_feature_npz, 'stub npz\n')

    monkeypatch.setattr(module._run_pdbert, 'check_container_running', lambda _container_name: None)
    monkeypatch.setattr(module._run_pdbert, 'run_logged_command', fake_run_logged_command)
    monkeypatch.setattr(
        module._run_pdbert,
        'copy_analyze_script_to_container',
        lambda paths, container_name: copied_scripts.append(
            f'{paths.display_name}:{container_name}'
        ),
    )

    result = run_module_main(
        module,
        [
            '--dataset-csv',
            str(dataset_csv),
            '--row-manifest',
            str(row_manifest),
            '--model-dir',
            str(model_dir),
            '--vpbench-root',
            str(vpbench_root),
            '--eval-name',
            'demo-eval',
        ],
    )

    assert result == 0
    assert [log_path for _, log_path in commands] == [
        paths.host_prepare_log,
        paths.host_test_log,
        paths.host_analyze_log,
    ]
    assert '--test-only' in commands[1][0][-1]
    assert copied_scripts == ['demo-eval:pdbert']
    assert paths.host_dataset_csv.read_text(encoding='utf-8') == dataset_csv.read_text(
        encoding='utf-8'
    )
    assert paths.host_runtime_test_config.exists()
    assert str(paths.container_dataset_dir) + '/' in paths.host_runtime_test_config.read_text(
        encoding='utf-8'
    )
    joined_rows = list(
        csv.DictReader(paths.host_joined_predictions_csv.open('r', encoding='utf-8', newline=''))
    )
    assert joined_rows == [
        {
            'row_id': '1',
            'dataset_file_name': '1',
            'dataset_unique_id': '1',
            'dataset_target': '1',
            'dataset_vulnerable_line_numbers': '2',
            'dataset_project': 'DemoProject',
            'dataset_source_signature_path': 'sig-a.json',
            'dataset_commit_hash': '',
            'dataset_dataset_type': 'test',
            'dataset_processed_func': 'int bad(void) {\n    return 1;\n}\n',
            'manifest_trace_id': 'trace-a',
            'manifest_matched_source_lines': '[{"file_path": "src/demo.c", "line_number": 5}]',
            'eval_unique_id': '1',
            'eval_score': '0.99',
        }
    ]
