from __future__ import annotations

import pytest

from tests.helpers import REPO_ROOT, load_module_from_path, write_text


def test_build_full_run_paths_recreates_expected_layout(tmp_path):
    module = load_module_from_path(
        'test_pipeline_paths_layout',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-demo'
    source_root = tmp_path / 'juliet' / 'C'
    paths = module._build_full_run_paths(run_dir=run_dir, source_root=source_root)

    assert paths.run_dir == run_dir.resolve()
    assert (
        paths.manifest_with_comments_xml
        == run_dir.resolve() / '01_manifest' / 'manifest_with_comments.xml'
    )
    assert (
        paths.trace_strict_jsonl
        == run_dir.resolve() / '04_trace_flow' / 'trace_flow_match_strict.jsonl'
    )
    assert paths.dataset.summary_json == run_dir.resolve() / '07_dataset_export' / 'summary.json'
    assert paths.patched_dataset.summary_json == (
        run_dir.resolve() / '07_dataset_export' / 'train_patched_counterparts_summary.json'
    )
    assert paths.source_testcases_root == source_root.resolve() / 'testcases'


def test_run_step01_manifest_comment_scan_uses_stage_api(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_pipeline_step01_helper',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    paths = module._build_full_run_paths(
        run_dir=tmp_path / 'run',
        source_root=tmp_path / 'juliet' / 'C',
    )
    captured: dict[str, object] = {}

    def fake_scan_manifest_comments(**kwargs):
        captured.update(kwargs)
        write_text(kwargs['output_xml'], '<root />\n')
        return {'output_xml': str(kwargs['output_xml']), 'scanned_files': 1}

    monkeypatch.setattr(
        module._stage01_manifest, 'scan_manifest_comments', fake_scan_manifest_comments
    )
    monkeypatch.setattr(module, 'run_internal_step', lambda step_key, logs_dir, fn: fn())

    result = module.run_step01_manifest_comment_scan(
        paths=paths,
        manifest=tmp_path / 'manifest.xml',
        source_root=tmp_path / 'juliet' / 'C',
    )

    assert captured['output_xml'] == paths.manifest_with_comments_xml
    assert result['output_xml'] == str(paths.manifest_with_comments_xml)


def test_run_step02a_code_field_inventory_uses_stage_api(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_pipeline_step02a_helper',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    paths = module._build_full_run_paths(
        run_dir=tmp_path / 'run',
        source_root=tmp_path / 'juliet' / 'C',
    )
    captured: dict[str, object] = {}

    def fake_extract_unique_code_fields(**kwargs):
        captured.update(kwargs)
        write_text(kwargs['pulse_taint_config_output'], '{}\n')
        return {'pulse_taint_config_output': str(kwargs['pulse_taint_config_output'])}

    monkeypatch.setattr(
        module._stage02a_taint,
        'extract_unique_code_fields',
        fake_extract_unique_code_fields,
    )
    monkeypatch.setattr(module, 'run_internal_step', lambda step_key, logs_dir, fn: fn())

    result = module.run_step02a_code_field_inventory(
        paths=paths,
        source_root=tmp_path / 'juliet' / 'C',
    )

    assert captured['input_xml'] == paths.manifest_with_comments_xml
    assert captured['output_dir'] == paths.taint_dir
    assert result['pulse_taint_config_output'] == str(paths.generated_taint_config)


def test_run_step02b_flow_build_returns_all_step_results(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_pipeline_step02b_helpers',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    paths = module._build_full_run_paths(
        run_dir=tmp_path / 'run',
        source_root=tmp_path / 'juliet' / 'C',
    )
    called: list[str] = []

    def fake_extract_function_inventory(**kwargs):
        called.append('02b_function_inventory_extract')
        write_text(kwargs['output_csv'], 'function_name,count\nfoo,1\n')
        write_text(kwargs['output_summary'], '{}\n')
        return {'step_key': '02b_function_inventory_extract'}

    def fake_categorize_function_names(**kwargs):
        called.append('02b_function_inventory_categorize')
        write_text(kwargs['output_jsonl'], '{}\n')
        write_text(kwargs['output_nested_json'], '{}\n')
        write_text(kwargs['output_summary'], '{}\n')
        return {'step_key': '02b_function_inventory_categorize'}

    def fake_add_flow_tags_to_testcase(**kwargs):
        called.append('02b_testcase_flow_partition')
        write_text(kwargs['output_xml'], '<root />\n')
        write_text(kwargs['summary_json'], '{}\n')
        return {'step_key': '02b_testcase_flow_partition'}

    monkeypatch.setattr(
        module._stage02b_flow,
        'extract_function_inventory',
        fake_extract_function_inventory,
    )
    monkeypatch.setattr(
        module._stage02b_flow,
        'categorize_function_names',
        fake_categorize_function_names,
    )
    monkeypatch.setattr(
        module._stage02b_flow,
        'add_flow_tags_to_testcase',
        fake_add_flow_tags_to_testcase,
    )
    monkeypatch.setattr(module, 'run_internal_step', lambda step_key, logs_dir, fn: fn())

    result = module.run_step02b_flow_build(paths=paths)

    assert list(result) == [
        '02b_function_inventory_extract',
        '02b_function_inventory_categorize',
        '02b_testcase_flow_partition',
    ]
    assert called == [
        '02b_function_inventory_extract',
        '02b_function_inventory_categorize',
        '02b_testcase_flow_partition',
    ]


def test_run_step07_dataset_export_uses_primary_dataset_api(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_pipeline_step07_helper',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    paths = module._build_full_run_paths(
        run_dir=tmp_path / 'run',
        source_root=tmp_path / 'juliet' / 'C',
    )
    captured: dict[str, object] = {}

    def fake_export_primary_dataset(params):
        captured['params'] = params
        paths.dataset.normalized_slices_dir.mkdir(parents=True, exist_ok=True)
        for output_path in [
            paths.dataset.csv_path,
            paths.dataset.dedup_dropped_csv,
            paths.dataset.token_counts_csv,
            paths.dataset.token_distribution_png,
            paths.dataset.split_manifest_json,
            paths.dataset.summary_json,
        ]:
            write_text(output_path, 'ok\n')
        return {'dataset': paths.dataset.to_payload()}

    monkeypatch.setattr(module, 'export_primary_dataset', fake_export_primary_dataset)
    monkeypatch.setattr(module, 'run_internal_step', lambda step_key, logs_dir, fn: fn())

    result = module.run_step07_dataset_export(
        paths=paths,
        pair_split_seed=1234,
        pair_train_ratio=0.8,
        dedup_mode='row',
    )

    params = captured['params']
    assert params.pairs_jsonl == paths.pair.pairs_jsonl
    assert params.output_dir == paths.dataset.output_dir
    assert params.split_seed == 1234
    assert params.train_ratio == 0.8
    assert params.dedup_mode == 'row'
    assert result['dataset']['summary_json'] == str(paths.dataset.summary_json)


def test_run_step03_infer_and_signature_uses_stage_api(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_pipeline_step03_helper',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    paths = module._build_full_run_paths(
        run_dir=tmp_path / 'run',
        source_root=tmp_path / 'juliet' / 'C',
    )
    captured: dict[str, object] = {}

    def fake_run_infer_and_signature(**kwargs):
        captured.update(kwargs)
        write_text(
            paths.infer_summary_json,
            '{"signature_non_empty_dir": "%s"}\n' % (paths.signatures_root / 'sig' / 'non_empty'),
        )
        (paths.signatures_root / 'sig' / 'non_empty').mkdir(parents=True, exist_ok=True)
        return {'signature_output_dir': str(paths.signatures_root / 'sig')}

    monkeypatch.setattr(
        module._stage03_infer,
        'run_infer_and_signature',
        fake_run_infer_and_signature,
    )
    monkeypatch.setattr(module, 'run_internal_step', lambda step_key, logs_dir, fn: fn())

    result, infer_summary, signature_non_empty_dir = module.run_step03_infer_and_signature(
        paths=paths,
        selected_taint_config=tmp_path / 'config.json',
        files=['demo.c'],
        all_cwes=False,
        cwes=None,
    )

    assert captured['infer_results_root'] == paths.infer_results_root
    assert captured['signatures_root'] == paths.signatures_root
    assert captured['summary_json'] == paths.infer_summary_json
    assert result['signature_output_dir'] == str(paths.signatures_root / 'sig')
    assert infer_summary['signature_non_empty_dir'] == str(
        paths.signatures_root / 'sig' / 'non_empty'
    )
    assert signature_non_empty_dir == paths.signatures_root / 'sig' / 'non_empty'


def test_run_step07b_train_patched_counterparts_uses_stage_api(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_pipeline_step07b_helper',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    paths = module._build_full_run_paths(
        run_dir=tmp_path / 'run',
        source_root=tmp_path / 'juliet' / 'C',
    )
    captured: dict[str, object] = {}

    def fake_export_patched_dataset(params):
        captured['params'] = params
        paths.patched_pair.signatures_dir.mkdir(parents=True, exist_ok=True)
        paths.patched_slices.slice_dir.mkdir(parents=True, exist_ok=True)
        for output_path in [
            paths.patched_pair.pairs_jsonl,
            paths.patched_pair.selection_summary_json,
            paths.patched_slices.summary_json,
            paths.patched_dataset.csv_path,
            paths.patched_dataset.dedup_dropped_csv,
            paths.patched_dataset.token_counts_csv,
            paths.patched_dataset.token_distribution_png,
            paths.patched_dataset.split_manifest_json,
            paths.patched_dataset.summary_json,
        ]:
            write_text(output_path, 'ok\n')
        paths.patched_dataset.normalized_slices_dir.mkdir(parents=True, exist_ok=True)
        return {
            'pairing': paths.patched_pair.to_payload(),
            'slices': paths.patched_slices.to_payload(),
            'dataset': paths.patched_dataset.to_payload(),
        }

    monkeypatch.setattr(module, 'export_patched_dataset', fake_export_patched_dataset)
    monkeypatch.setattr(module, 'run_internal_step', lambda step_key, logs_dir, fn: fn())

    result = module.run_step07b_train_patched_counterparts(paths=paths, dedup_mode='none')

    params = captured['params']
    assert params.run_dir == paths.run_dir
    assert params.dataset_export_dir == paths.dataset.output_dir
    assert params.signature_output_dir == paths.patched_pair.signatures_dir
    assert params.slice_output_dir == paths.patched_slices.output_dir
    assert params.dedup_mode == 'none'
    assert result['dataset']['summary_json'] == str(paths.patched_dataset.summary_json)


def test_run_checked_internal_step_validates_required_outputs(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_pipeline_checked_step_helper',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    output_path = tmp_path / 'out.txt'

    monkeypatch.setattr(
        module,
        'run_internal_step',
        lambda step_key, logs_dir, fn: fn(),
    )
    write_text(output_path, 'ok\n')

    result = module._run_checked_internal_step(
        step_key='demo',
        logs_dir=tmp_path / 'logs',
        fn=lambda: {'status': 'ok'},
        required_outputs=[(output_path, 'missing output')],
    )
    assert result == {'status': 'ok'}
    output_path.unlink()

    with pytest.raises(RuntimeError, match='missing output'):
        module._run_checked_internal_step(
            step_key='demo',
            logs_dir=tmp_path / 'logs',
            fn=lambda: {'status': 'ok'},
            required_outputs=[(output_path, 'missing output')],
        )
