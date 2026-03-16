from __future__ import annotations

from pathlib import Path


def test_run_epic001_pipeline_wrapper_delegates(load_tools_module, monkeypatch):
    module = load_tools_module('test_wrapper_run_epic001', 'run-epic001-pipeline.py')

    captured: dict[str, object] = {}

    def fake_main(**kwargs):
        captured.update(kwargs)
        return 7

    monkeypatch.setattr(module._pipeline_run, 'main', fake_main)

    result = module.main(
        cwes=[121],
        all_cwes=False,
        files=[],
        manifest=Path('/tmp/manifest.xml'),
        source_root=Path('/tmp/source'),
        pipeline_root=Path('/tmp/pipeline'),
        run_id='run-demo',
        committed_taint_config=Path('/tmp/config.json'),
        pair_split_seed=999,
        pair_train_ratio=0.7,
        dedup_mode='none',
    )

    assert result == 7
    assert captured['cwes'] == [121]
    assert captured['pair_split_seed'] == 999
    assert captured['dedup_mode'] == 'none'


def test_run_infer_wrapper_delegates(load_tools_module, monkeypatch):
    module = load_tools_module('test_wrapper_run_infer', 'run-infer-all-juliet.py')

    captured: dict[str, object] = {}

    def fake_main(**kwargs):
        captured.update(kwargs)
        return 3

    monkeypatch.setattr(module._infer_runner, 'main', fake_main)

    result = module.main(
        cwes=[78],
        global_result=True,
        all_cwes=False,
        files=['demo.c'],
        pulse_taint_config=Path('/tmp/config.json'),
        infer_results_root=Path('/tmp/infer'),
        signatures_root=Path('/tmp/signatures'),
        summary_json=Path('/tmp/summary.json'),
    )

    assert result == 3
    assert captured['global_result'] is True
    assert captured['files'] == ['demo.c']


def test_export_train_wrapper_delegates(load_tools_module, monkeypatch):
    module = load_tools_module('test_wrapper_export_train', 'export_train_patched_counterparts.py')

    monkeypatch.setattr(module._patched_counterparts, 'main', lambda: 11)

    assert module.main() == 11


def test_generate_signature_wrapper_delegates(load_tools_module, monkeypatch):
    module = load_tools_module('test_wrapper_generate_signature', 'generate-signature.py')

    monkeypatch.setattr(module._signature_stage, 'main', lambda **_kwargs: 13)

    assert module.main() == 13


def test_rerun_step07_wrapper_delegates(load_tools_module, monkeypatch):
    module = load_tools_module('test_wrapper_rerun_step07', 'rerun-step07.py')

    monkeypatch.setattr(module._rerun_step07, 'main', lambda: 5)

    assert module.main() == 5
