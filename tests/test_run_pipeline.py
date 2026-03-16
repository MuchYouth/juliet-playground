from __future__ import annotations

import pytest

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main, write_text


def test_full_subcommand_runs_internal_orchestration_in_minimal_mode(monkeypatch, tmp_path):
    module = load_module_from_path('test_run_pipeline_full', REPO_ROOT / 'tools/run_pipeline.py')

    manifest = tmp_path / 'manifest.xml'
    source_root = tmp_path / 'juliet' / 'C'
    committed_taint_config = tmp_path / 'pulse-taint-config.json'
    pipeline_root = tmp_path / 'pipeline-runs'
    source_root.mkdir(parents=True)
    write_text(manifest, '<manifest />\n')
    write_text(committed_taint_config, '{}\n')

    called: list[str] = []

    def fake_scan_manifest_comments(**kwargs):
        called.append('01_manifest_comment_scan')
        print('stage01 ok')
        write_text(kwargs['output_xml'], '<root />\n')
        return {'output_xml': str(kwargs['output_xml'])}

    def fake_extract_unique_code_fields(**kwargs):
        called.append('02a_code_field_inventory')
        print('stage02a ok')
        write_text(kwargs['pulse_taint_config_output'], '{}\n')
        return {'pulse_taint_config_output': str(kwargs['pulse_taint_config_output'])}

    def fake_run_stage02b_flow(**kwargs):
        called.append('02b_testcase_flow_build')
        assert kwargs['minimal_outputs'] is True
        print('stage02b ok')
        write_text(kwargs['output_dir'] / 'manifest_with_testcase_flows.xml', '<root />\n')
        return {
            'manifest_with_testcase_flows_xml': str(
                kwargs['output_dir'] / 'manifest_with_testcase_flows.xml'
            )
        }

    def fake_run_infer_and_signature(**kwargs):
        called.append('03_infer_and_signature')
        print('stage03 ok')
        assert kwargs['summary_json'] is None
        assert kwargs['minimal_outputs'] is True
        signature_non_empty_dir = (
            kwargs['signatures_root'] / 'infer-demo' / 'signature-demo' / 'non_empty'
        )
        signature_non_empty_dir.mkdir(parents=True, exist_ok=True)
        return {
            'signature_output_dir': str(signature_non_empty_dir.parent),
            'signature_non_empty_dir': str(signature_non_empty_dir),
        }

    def fake_filter_traces_by_flow(**kwargs):
        called.append('04_trace_flow_filter')
        print('stage04 ok')
        assert kwargs['minimal_outputs'] is True
        write_text(kwargs['output_dir'] / 'trace_flow_match_strict.jsonl', '{}\n')
        return {'trace_jsonl': str(kwargs['output_dir'] / 'trace_flow_match_strict.jsonl')}

    def fake_build_paired_trace_dataset(**kwargs):
        called.append('05_pair_trace_dataset')
        print('stage05 ok')
        assert kwargs['minimal_outputs'] is True
        write_text(kwargs['output_dir'] / 'pairs.jsonl', '{}\n')
        write_text(kwargs['output_dir'] / 'leftover_counterparts.jsonl', '{}\n')
        (kwargs['output_dir'] / 'paired_signatures').mkdir(parents=True, exist_ok=True)
        return {'pairs_jsonl': str(kwargs['output_dir'] / 'pairs.jsonl')}

    def fake_generate_slices(**kwargs):
        called.append('06_generate_slices')
        print('stage06 ok')
        assert kwargs['minimal_outputs'] is True
        (kwargs['output_dir'] / 'slice').mkdir(parents=True, exist_ok=True)
        return {'slice_dir': str(kwargs['output_dir'] / 'slice')}

    def fake_export_primary_dataset(params):
        called.append('07_dataset_export')
        print('stage07 ok')
        assert params.minimal_outputs is True
        (params.output_dir / 'normalized_slices').mkdir(parents=True, exist_ok=True)
        for output_path in [
            params.output_dir / 'Real_Vul_data.csv',
            params.output_dir / 'split_manifest.json',
        ]:
            write_text(output_path, 'ok\n')
        return {
            'dataset': {
                'output_dir': str(params.output_dir),
                'csv_path': str(params.output_dir / 'Real_Vul_data.csv'),
                'normalized_slices_dir': str(params.output_dir / 'normalized_slices'),
                'split_manifest_json': str(params.output_dir / 'split_manifest.json'),
            }
        }

    monkeypatch.setattr(
        module._stage01_manifest, 'scan_manifest_comments', fake_scan_manifest_comments
    )
    monkeypatch.setattr(
        module._stage02a_taint,
        'extract_unique_code_fields',
        fake_extract_unique_code_fields,
    )
    monkeypatch.setattr(module._stage02b_flow, 'run_stage02b_flow', fake_run_stage02b_flow)
    monkeypatch.setattr(
        module._stage03_infer,
        'run_infer_and_signature',
        fake_run_infer_and_signature,
    )
    monkeypatch.setattr(
        module._stage04_trace_flow,
        'filter_traces_by_flow',
        fake_filter_traces_by_flow,
    )
    monkeypatch.setattr(
        module._stage05_pair_trace,
        'build_paired_trace_dataset',
        fake_build_paired_trace_dataset,
    )
    monkeypatch.setattr(module._stage06_slices, 'generate_slices', fake_generate_slices)
    monkeypatch.setattr(module, 'export_primary_dataset', fake_export_primary_dataset)

    result = run_module_main(
        module,
        [
            'full',
            '121',
            '--manifest',
            str(manifest),
            '--source-root',
            str(source_root),
            '--pipeline-root',
            str(pipeline_root),
            '--run-id',
            'run-test',
            '--committed-taint-config',
            str(committed_taint_config),
        ],
    )

    assert result == 0
    assert called == [
        '01_manifest_comment_scan',
        '02a_code_field_inventory',
        '02b_testcase_flow_build',
        '03_infer_and_signature',
        '04_trace_flow_filter',
        '05_pair_trace_dataset',
        '06_generate_slices',
        '07_dataset_export',
    ]

    run_dir = pipeline_root / 'run-test'
    assert not (run_dir / 'run_summary.json').exists()
    assert not (run_dir / 'logs').exists()
    assert (run_dir / '05_pair_trace_ds' / 'leftover_counterparts.jsonl').exists()
    assert (run_dir / '07_dataset_export' / 'split_manifest.json').exists()
    assert not (run_dir / '07_dataset_export' / 'summary.json').exists()
    assert not (run_dir / '07_dataset_export' / 'train_patched_counterparts_summary.json').exists()
    assert not (run_dir / '04_trace_flow' / 'summary.json').exists()
    assert not (run_dir / '06_slices' / 'summary.json').exists()


def test_full_subcommand_returns_failure_on_step_error(monkeypatch, tmp_path):
    module = load_module_from_path(
        'test_run_pipeline_full_failure',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    manifest = tmp_path / 'manifest.xml'
    source_root = tmp_path / 'juliet' / 'C'
    committed_taint_config = tmp_path / 'pulse-taint-config.json'
    pipeline_root = tmp_path / 'pipeline-runs'
    source_root.mkdir(parents=True)
    write_text(manifest, '<manifest />\n')
    write_text(committed_taint_config, '{}\n')

    monkeypatch.setattr(
        module,
        'run_step01_manifest_comment_scan',
        lambda **kwargs: {'step': '01'},
    )
    monkeypatch.setattr(
        module,
        'run_step02a_code_field_inventory',
        lambda **kwargs: {'step': '02a'},
    )
    monkeypatch.setattr(
        module,
        'run_step02b_flow_build',
        lambda **kwargs: {'step': '02b'},
    )
    monkeypatch.setattr(
        module,
        'run_step03_infer_and_signature',
        lambda **kwargs: ({'step': '03'}, {'step': '03'}, tmp_path / 'non-empty'),
    )

    def fail_step04(**kwargs):
        raise RuntimeError('trace flow failed')

    monkeypatch.setattr(module, 'run_step04_trace_flow', fail_step04)

    result = run_module_main(
        module,
        [
            'full',
            '121',
            '--manifest',
            str(manifest),
            '--source-root',
            str(source_root),
            '--pipeline-root',
            str(pipeline_root),
            '--run-id',
            'run-fail',
            '--committed-taint-config',
            str(committed_taint_config),
        ],
    )

    assert result == 1
    assert not (pipeline_root / 'run-fail' / 'run_summary.json').exists()


def test_removed_subcommands_are_rejected():
    module = load_module_from_path(
        'test_run_pipeline_removed_subcommands',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    for command in [
        'stage01',
        'stage02a',
        'stage02b',
        'stage03',
        'stage03-signature',
        'stage04',
        'stage05',
        'stage06',
        'stage07',
        'stage07b',
    ]:
        with pytest.raises(SystemExit):
            run_module_main(module, [command])
