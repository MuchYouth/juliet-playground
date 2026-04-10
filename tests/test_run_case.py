from __future__ import annotations

from pathlib import Path

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main, write_text


def _make_case_layout(tmp_path: Path) -> Path:
    case_dir = tmp_path / 'cases' / 'demo-project__CVE-2099-0001'
    vulnerable_dir = case_dir / 'vulnerable'
    repo_dir = vulnerable_dir / 'repo'
    repo_dir.mkdir(parents=True, exist_ok=True)
    write_text(
        repo_dir / '.git' / 'config',
        '[remote "origin"]\n\turl = https://github.com/example/demo-project.git\n',
    )

    base_run_dir = vulnerable_dir / 'runs' / 'base-run'
    write_text(
        base_run_dir / 'build_targets.csv',
        'testcase_key,workdir,build_command\ndemo,../../repo,"make clean && make -j1"\n',
    )
    write_text(
        base_run_dir / 'manual_line_truth.csv',
        'testcase_key,file_path,line_number,label,note\n'
        'demo,src/demo.c,1187,vuln,confirmed vulnerable line\n',
    )

    run_dir = vulnerable_dir / 'runs' / 'run-001'
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / 'build_targets.csv').symlink_to('../base-run/build_targets.csv')
    (run_dir / 'manual_line_truth.csv').symlink_to('../base-run/manual_line_truth.csv')
    write_text(run_dir / 'pulse-taint-config.json', '{}\n')
    return case_dir


def test_run_case_executes_external_pipeline_and_updates_outputs_symlink(
    monkeypatch, tmp_path, capsys
):
    module = load_module_from_path('test_run_case', REPO_ROOT / 'tools/run_case.py')
    case_dir = _make_case_layout(tmp_path)
    artifact_root = tmp_path / 'artifacts' / 'external-runs'
    expected_output_root = artifact_root / case_dir.name / 'vulnerable'
    expected_run_dir = expected_output_root / 'run-001'

    calls: list[dict[str, object]] = []

    def fake_run_external_trace_pipeline(args):
        calls.append(
            {
                'source_root': args.source_root,
                'build_targets': args.build_targets,
                'manual_line_truth': args.manual_line_truth,
                'pulse_taint_config': args.pulse_taint_config,
                'output_root': args.output_root,
                'run_id': args.run_id,
                'project_name': args.project_name,
                'overwrite': args.overwrite,
            }
        )
        (args.output_root / args.run_id).mkdir(parents=True, exist_ok=True)
        return 0

    monkeypatch.setattr(
        module._run_external_trace_pipeline,
        'run_external_trace_pipeline',
        fake_run_external_trace_pipeline,
    )

    result = run_module_main(
        module,
        [
            '--case',
            str(case_dir),
            '--track',
            'vulnerable',
            '--run',
            'run-001',
            '--artifact-root',
            str(artifact_root),
        ],
    )

    assert result == 0
    assert calls == [
        {
            'source_root': case_dir / 'vulnerable' / 'repo',
            'build_targets': case_dir / 'vulnerable' / 'runs' / 'run-001' / 'build_targets.csv',
            'manual_line_truth': case_dir
            / 'vulnerable'
            / 'runs'
            / 'run-001'
            / 'manual_line_truth.csv',
            'pulse_taint_config': case_dir
            / 'vulnerable'
            / 'runs'
            / 'run-001'
            / 'pulse-taint-config.json',
            'output_root': expected_output_root,
            'run_id': 'run-001',
            'project_name': 'demo-project',
            'overwrite': False,
        }
    ]

    outputs_link = case_dir / 'vulnerable' / 'runs' / 'run-001' / 'outputs'
    assert outputs_link.is_symlink()
    assert outputs_link.resolve() == expected_run_dir.resolve()

    captured = capsys.readouterr()
    assert 'Case run completed: demo-project__CVE-2099-0001/vulnerable/run-001' in captured.out
