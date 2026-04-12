from __future__ import annotations

from pathlib import Path

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main, write_text


def _make_case_layout(
    tmp_path: Path,
    *,
    create_run_dir: bool = True,
    include_base_pulse_taint_config: bool = False,
) -> Path:
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
    if include_base_pulse_taint_config:
        write_text(base_run_dir / 'pulse-taint-config.json', '{"base": true}\n')

    if create_run_dir:
        run_dir = vulnerable_dir / 'runs' / 'run-001'
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / 'build_targets.csv').symlink_to('../base-run/build_targets.csv')
        (run_dir / 'manual_line_truth.csv').symlink_to('../base-run/manual_line_truth.csv')
        write_text(run_dir / 'pulse-taint-config.json', '{}\n')
    return case_dir


def test_run_case_executes_external_pipeline_and_writes_outputs_under_case_run(
    monkeypatch, tmp_path, capsys
):
    module = load_module_from_path('test_run_case', REPO_ROOT / 'tools/run_case.py')
    case_dir = _make_case_layout(tmp_path)
    expected_outputs_dir = case_dir / 'vulnerable' / 'runs' / 'run-001' / 'outputs'

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
            'output_root': case_dir / 'vulnerable' / 'runs' / 'run-001',
            'run_id': 'outputs',
            'project_name': 'demo-project',
            'overwrite': False,
        }
    ]

    assert expected_outputs_dir.exists()
    assert expected_outputs_dir.is_dir()
    assert not expected_outputs_dir.is_symlink()

    captured = capsys.readouterr()
    assert 'Case run completed: demo-project__CVE-2099-0001/vulnerable/run-001' in captured.out


def test_run_case_bootstraps_missing_run_dir_from_base_run(monkeypatch, tmp_path):
    module = load_module_from_path('test_run_case_bootstrap', REPO_ROOT / 'tools/run_case.py')
    case_dir = _make_case_layout(
        tmp_path,
        create_run_dir=False,
        include_base_pulse_taint_config=True,
    )

    calls: list[dict[str, object]] = []

    def fake_run_external_trace_pipeline(args):
        calls.append(
            {
                'build_targets': args.build_targets,
                'manual_line_truth': args.manual_line_truth,
                'pulse_taint_config': args.pulse_taint_config,
                'output_root': args.output_root,
                'run_id': args.run_id,
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
        ],
    )

    assert result == 0
    run_dir = case_dir / 'vulnerable' / 'runs' / 'run-001'
    build_targets = run_dir / 'build_targets.csv'
    manual_line_truth = run_dir / 'manual_line_truth.csv'
    pulse_taint_config = run_dir / 'pulse-taint-config.json'

    assert build_targets.exists()
    assert not build_targets.is_symlink()
    assert build_targets.read_text(encoding='utf-8') == (
        case_dir / 'vulnerable' / 'runs' / 'base-run' / 'build_targets.csv'
    ).read_text(encoding='utf-8')

    assert manual_line_truth.exists()
    assert not manual_line_truth.is_symlink()
    assert manual_line_truth.read_text(encoding='utf-8') == (
        case_dir / 'vulnerable' / 'runs' / 'base-run' / 'manual_line_truth.csv'
    ).read_text(encoding='utf-8')

    assert pulse_taint_config.exists()
    assert not pulse_taint_config.is_symlink()
    assert pulse_taint_config.read_text(encoding='utf-8') == '{"base": true}\n'

    assert calls == [
        {
            'build_targets': build_targets,
            'manual_line_truth': manual_line_truth,
            'pulse_taint_config': pulse_taint_config,
            'output_root': run_dir,
            'run_id': 'outputs',
        }
    ]
    assert (run_dir / 'outputs').exists()
    assert not (run_dir / 'outputs').is_symlink()


def test_run_case_uses_override_inputs_without_materializing_them(monkeypatch, tmp_path):
    module = load_module_from_path('test_run_case_overrides', REPO_ROOT / 'tools/run_case.py')
    case_dir = _make_case_layout(
        tmp_path,
        create_run_dir=False,
        include_base_pulse_taint_config=True,
    )
    override_build_targets = tmp_path / 'inputs' / 'custom-build-targets.csv'
    override_pulse_taint_config = tmp_path / 'inputs' / 'custom-pulse-taint-config.json'
    write_text(
        override_build_targets,
        'testcase_key,workdir,build_command\ndemo,/tmp,"make custom"\n',
    )
    write_text(override_pulse_taint_config, '{"override": true}\n')

    calls: list[dict[str, object]] = []

    def fake_run_external_trace_pipeline(args):
        calls.append(
            {
                'build_targets': args.build_targets,
                'manual_line_truth': args.manual_line_truth,
                'pulse_taint_config': args.pulse_taint_config,
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
            '--build-targets',
            str(override_build_targets),
            '--pulse-taint-config',
            str(override_pulse_taint_config),
        ],
    )

    assert result == 0
    run_dir = case_dir / 'vulnerable' / 'runs' / 'run-001'

    assert not (run_dir / 'build_targets.csv').exists()
    assert not (run_dir / 'pulse-taint-config.json').exists()
    assert (run_dir / 'manual_line_truth.csv').exists()
    assert not (run_dir / 'manual_line_truth.csv').is_symlink()

    assert calls == [
        {
            'build_targets': override_build_targets.resolve(),
            'manual_line_truth': run_dir / 'manual_line_truth.csv',
            'pulse_taint_config': override_pulse_taint_config.resolve(),
        }
    ]
    assert (run_dir / 'outputs').exists()
    assert not (run_dir / 'outputs').is_symlink()


def test_run_case_keeps_partial_outputs_directory_on_failure(monkeypatch, tmp_path):
    module = load_module_from_path('test_run_case_failure_outputs', REPO_ROOT / 'tools/run_case.py')
    case_dir = _make_case_layout(
        tmp_path,
        create_run_dir=False,
        include_base_pulse_taint_config=True,
    )

    def fake_run_external_trace_pipeline(args):
        outputs_dir = args.output_root / args.run_id
        outputs_dir.mkdir(parents=True, exist_ok=True)
        write_text(outputs_dir / 'partial.txt', 'partial\n')
        raise RuntimeError('boom')

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
        ],
    )

    outputs_dir = case_dir / 'vulnerable' / 'runs' / 'run-001' / 'outputs'
    assert result == 1
    assert outputs_dir.exists()
    assert outputs_dir.is_dir()
    assert not outputs_dir.is_symlink()
    assert (outputs_dir / 'partial.txt').read_text(encoding='utf-8') == 'partial\n'
