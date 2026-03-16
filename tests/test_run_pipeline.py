from __future__ import annotations

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main


def test_full_subcommand_delegates(monkeypatch):
    module = load_module_from_path('test_run_pipeline_full', REPO_ROOT / 'tools/run_pipeline.py')

    captured: dict[str, object] = {}

    def fake_main(**kwargs):
        captured.update(kwargs)
        return 7

    monkeypatch.setattr(module._pipeline, 'main', fake_main)

    result = run_module_main(
        module,
        [
            'full',
            '121',
            '--pair-split-seed',
            '999',
            '--dedup-mode',
            'none',
        ],
    )

    assert result == 7
    assert captured['cwes'] == [121]
    assert captured['pair_split_seed'] == 999
    assert captured['dedup_mode'] == 'none'


def test_stage02b_subcommand_delegates(monkeypatch, tmp_path):
    module = load_module_from_path(
        'test_run_pipeline_stage02b', REPO_ROOT / 'tools/run_pipeline.py'
    )

    captured: dict[str, object] = {}

    def fake_run_stage02b_flow(**kwargs):
        captured.update(kwargs)
        return {'output_dir': str(kwargs['output_dir'])}

    monkeypatch.setattr(module._stage02b_flow, 'run_stage02b_flow', fake_run_stage02b_flow)

    output_dir = tmp_path / '02b_flow'
    result = run_module_main(
        module,
        [
            'stage02b',
            '--input-xml',
            str(tmp_path / 'input.xml'),
            '--source-root',
            str(tmp_path / 'src'),
            '--output-dir',
            str(output_dir),
        ],
    )

    assert result == 0
    assert captured['input_xml'] == tmp_path / 'input.xml'
    assert captured['source_root'] == tmp_path / 'src'
    assert captured['output_dir'] == output_dir


def test_stage03_subcommand_delegates(monkeypatch, tmp_path):
    module = load_module_from_path('test_run_pipeline_stage03', REPO_ROOT / 'tools/run_pipeline.py')

    captured: dict[str, object] = {}

    def fake_run_infer_and_signature(**kwargs):
        captured.update(kwargs)
        return {'infer_run_dir': str(tmp_path / 'infer-run')}

    monkeypatch.setattr(
        module._stage03_infer, 'run_infer_and_signature', fake_run_infer_and_signature
    )

    result = run_module_main(
        module,
        [
            'stage03',
            '--files',
            'demo.c',
            '--summary-json',
            str(tmp_path / 'summary.json'),
        ],
    )

    assert result == 0
    assert captured['files'] == ['demo.c']
    assert captured['summary_json'] == tmp_path / 'summary.json'


def test_stage07_subcommand_delegates(monkeypatch, tmp_path):
    module = load_module_from_path('test_run_pipeline_stage07', REPO_ROOT / 'tools/run_pipeline.py')

    captured: dict[str, object] = {}

    class FakeResult:
        def to_payload(self):
            return {'summary_json': str(tmp_path / 'summary.json')}

    def fake_export_primary_dataset(params):
        captured['params'] = params
        return FakeResult()

    monkeypatch.setattr(
        module._stage07_dataset_export, 'export_primary_dataset', fake_export_primary_dataset
    )

    result = run_module_main(
        module,
        [
            'stage07',
            '--pairs-jsonl',
            str(tmp_path / 'pairs.jsonl'),
            '--paired-signatures-dir',
            str(tmp_path / 'paired'),
            '--slice-dir',
            str(tmp_path / 'slice'),
            '--output-dir',
            str(tmp_path / 'out'),
            '--split-seed',
            '4321',
            '--train-ratio',
            '0.75',
        ],
    )

    assert result == 0
    params = captured['params']
    assert params.pairs_jsonl == tmp_path / 'pairs.jsonl'
    assert params.output_dir == tmp_path / 'out'
    assert params.split_seed == 4321
    assert params.train_ratio == 0.75


def test_stage07b_subcommand_delegates(monkeypatch, tmp_path):
    module = load_module_from_path(
        'test_run_pipeline_stage07b', REPO_ROOT / 'tools/run_pipeline.py'
    )

    captured: dict[str, object] = {}

    class FakeResult:
        def to_payload(self):
            return {'summary_json': str(tmp_path / 'summary.json')}

    def fake_export_patched_dataset(params):
        captured['params'] = params
        return FakeResult()

    monkeypatch.setattr(
        module._stage07b_patched_export, 'export_patched_dataset', fake_export_patched_dataset
    )

    result = run_module_main(
        module,
        [
            'stage07b',
            '--run-dir',
            str(tmp_path / 'run'),
            '--pair-dir',
            str(tmp_path / 'pair'),
            '--dataset-export-dir',
            str(tmp_path / 'dataset'),
            '--signature-output-dir',
            str(tmp_path / 'signatures'),
            '--slice-output-dir',
            str(tmp_path / 'slices'),
            '--output-pairs-jsonl',
            str(tmp_path / 'pairs.jsonl'),
            '--selection-summary-json',
            str(tmp_path / 'selection.json'),
            '--dedup-mode',
            'none',
        ],
    )

    assert result == 0
    params = captured['params']
    assert params.run_dir == tmp_path / 'run'
    assert params.dataset_export_dir == tmp_path / 'dataset'
    assert params.dedup_mode == 'none'


def test_rerun_step07_subcommand_delegates(monkeypatch, tmp_path):
    module = load_module_from_path('test_run_pipeline_rerun', REPO_ROOT / 'tools/run_pipeline.py')

    captured: dict[str, object] = {}

    def fake_run_rerun_step07(**kwargs):
        captured.update(kwargs)
        return {'output_dir': str(tmp_path / 'rerun-out')}

    monkeypatch.setattr(module._rerun_step07, 'run_rerun_step07', fake_run_rerun_step07)

    result = run_module_main(
        module,
        [
            'rerun-step07',
            '--run-dir',
            str(tmp_path / 'run'),
            '--dedup-mode',
            'none',
            '--only-07',
        ],
    )

    assert result == 0
    assert captured['run_dir'] == tmp_path / 'run'
    assert captured['dedup_mode'] == 'none'
    assert captured['only_07'] is True
