from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main, write_text


def test_full_subcommand_runs_internal_orchestration_and_writes_summary(monkeypatch, tmp_path):
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

    def fake_extract_function_inventory(**kwargs):
        called.append('02b_function_inventory_extract')
        print('stage02b extract ok')
        write_text(kwargs['output_csv'], 'function_name,count\nfoo,1\n')
        write_text(kwargs['output_summary'], '{}\n')
        return {'step_key': '02b_function_inventory_extract'}

    def fake_categorize_function_names(**kwargs):
        called.append('02b_function_inventory_categorize')
        print('stage02b categorize ok')
        write_text(kwargs['output_jsonl'], '{}\n')
        write_text(kwargs['output_nested_json'], '{}\n')
        write_text(kwargs['output_summary'], '{}\n')
        return {'step_key': '02b_function_inventory_categorize'}

    def fake_add_flow_tags_to_testcase(**kwargs):
        called.append('02b_testcase_flow_partition')
        print('stage02b partition ok')
        write_text(kwargs['output_xml'], '<root />\n')
        write_text(kwargs['summary_json'], '{}\n')
        return {'step_key': '02b_testcase_flow_partition'}

    def fake_run_infer_and_signature(**kwargs):
        called.append('03_infer_and_signature')
        print('stage03 ok')
        signature_non_empty_dir = (
            kwargs['signatures_root'] / 'infer-demo' / 'signature-demo' / 'non_empty'
        )
        signature_non_empty_dir.mkdir(parents=True, exist_ok=True)
        write_text(
            kwargs['summary_json'],
            json.dumps({'signature_non_empty_dir': str(signature_non_empty_dir)}) + '\n',
        )
        return {'signature_output_dir': str(signature_non_empty_dir.parent)}

    def fake_filter_traces_by_flow(**kwargs):
        called.append('04_trace_flow_filter')
        print('stage04 ok')
        write_text(kwargs['output_dir'] / 'trace_flow_match_strict.jsonl', '{}\n')
        return {'trace_jsonl': str(kwargs['output_dir'] / 'trace_flow_match_strict.jsonl')}

    def fake_build_paired_trace_dataset(**kwargs):
        called.append('05_pair_trace_dataset')
        print('stage05 ok')
        write_text(kwargs['output_dir'] / 'pairs.jsonl', '{}\n')
        write_text(kwargs['output_dir'] / 'summary.json', '{}\n')
        (kwargs['output_dir'] / 'paired_signatures').mkdir(parents=True, exist_ok=True)
        return {'pairs_jsonl': str(kwargs['output_dir'] / 'pairs.jsonl')}

    def fake_generate_slices(**kwargs):
        called.append('06_generate_slices')
        print('stage06 ok')
        (kwargs['output_dir'] / 'slice').mkdir(parents=True, exist_ok=True)
        write_text(kwargs['output_dir'] / 'summary.json', '{}\n')
        return {'summary_json': str(kwargs['output_dir'] / 'summary.json')}

    def fake_export_primary_dataset(params):
        called.append('07_dataset_export')
        print('stage07 ok')
        (params.output_dir / 'normalized_slices').mkdir(parents=True, exist_ok=True)
        for output_path in [
            params.output_dir / 'Real_Vul_data.csv',
            params.output_dir / 'Real_Vul_data_dedup_dropped.csv',
            params.output_dir / 'normalized_token_counts.csv',
            params.output_dir / 'slice_token_distribution.png',
            params.output_dir / 'split_manifest.json',
            params.output_dir / 'summary.json',
        ]:
            write_text(output_path, 'ok\n')
        return {
            'dataset': {
                'output_dir': str(params.output_dir),
                'csv_path': str(params.output_dir / 'Real_Vul_data.csv'),
                'dedup_dropped_csv': str(params.output_dir / 'Real_Vul_data_dedup_dropped.csv'),
                'normalized_slices_dir': str(params.output_dir / 'normalized_slices'),
                'token_counts_csv': str(params.output_dir / 'normalized_token_counts.csv'),
                'token_distribution_png': str(params.output_dir / 'slice_token_distribution.png'),
                'split_manifest_json': str(params.output_dir / 'split_manifest.json'),
                'summary_json': str(params.output_dir / 'summary.json'),
            }
        }

    def fake_export_patched_dataset(params):
        called.append('07b_train_patched_counterparts_export')
        print('stage07b ok')
        patched_paths = module._build_full_run_paths(
            run_dir=params.run_dir,
            source_root=source_root,
        )
        patched_paths.patched_pair.signatures_dir.mkdir(parents=True, exist_ok=True)
        (patched_paths.patched_slices.output_dir / 'slice').mkdir(parents=True, exist_ok=True)
        for output_path in [
            patched_paths.patched_pair.pairs_jsonl,
            patched_paths.patched_pair.selection_summary_json,
            patched_paths.patched_slices.summary_json,
            patched_paths.patched_dataset.csv_path,
            patched_paths.patched_dataset.dedup_dropped_csv,
            patched_paths.patched_dataset.token_counts_csv,
            patched_paths.patched_dataset.token_distribution_png,
            patched_paths.patched_dataset.split_manifest_json,
            patched_paths.patched_dataset.summary_json,
        ]:
            write_text(output_path, 'ok\n')
        patched_paths.patched_dataset.normalized_slices_dir.mkdir(
            parents=True,
            exist_ok=True,
        )
        return {
            'pairing': {
                'output_dir': str(patched_paths.pair.output_dir),
                'pairs_jsonl': str(patched_paths.patched_pair.pairs_jsonl),
                'signatures_dir': str(patched_paths.patched_pair.signatures_dir),
                'selection_summary_json': str(patched_paths.patched_pair.selection_summary_json),
            },
            'slices': {
                'output_dir': str(patched_paths.patched_slices.output_dir),
                'slice_dir': str(patched_paths.patched_slices.slice_dir),
                'summary_json': str(patched_paths.patched_slices.summary_json),
            },
            'dataset': {
                'output_dir': str(patched_paths.patched_dataset.output_dir),
                'csv_path': str(patched_paths.patched_dataset.csv_path),
                'dedup_dropped_csv': str(patched_paths.patched_dataset.dedup_dropped_csv),
                'normalized_slices_dir': str(patched_paths.patched_dataset.normalized_slices_dir),
                'token_counts_csv': str(patched_paths.patched_dataset.token_counts_csv),
                'token_distribution_png': str(patched_paths.patched_dataset.token_distribution_png),
                'split_manifest_json': str(patched_paths.patched_dataset.split_manifest_json),
                'summary_json': str(patched_paths.patched_dataset.summary_json),
            },
        }

    monkeypatch.setattr(
        module._stage01_manifest, 'scan_manifest_comments', fake_scan_manifest_comments
    )
    monkeypatch.setattr(
        module._stage02a_taint,
        'extract_unique_code_fields',
        fake_extract_unique_code_fields,
    )
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
    monkeypatch.setattr(module, 'export_patched_dataset', fake_export_patched_dataset)

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
        '02b_function_inventory_extract',
        '02b_function_inventory_categorize',
        '02b_testcase_flow_partition',
        '03_infer_and_signature',
        '04_trace_flow_filter',
        '05_pair_trace_dataset',
        '06_generate_slices',
        '07_dataset_export',
        '07b_train_patched_counterparts_export',
    ]

    run_dir = pipeline_root / 'run-test'
    summary = json.loads((run_dir / 'run_summary.json').read_text(encoding='utf-8'))
    assert summary['status'] == 'success'
    assert summary['run']['run_id'] == 'run-test'
    assert summary['inputs']['cwes'] == [121]
    assert summary['config']['selected_reason'] == 'generated'
    assert summary['steps']['03_infer_and_signature']['returncode'] == 0
    assert Path(summary['outputs']['stage04']['trace_flow_match_strict_jsonl']).name == (
        'trace_flow_match_strict.jsonl'
    )
    assert (run_dir / 'logs' / '01_manifest_comment_scan.stdout.log').exists()
    assert (run_dir / 'logs' / '07b_train_patched_counterparts_export.stderr.log').exists()


def test_full_subcommand_writes_failed_summary_on_step_error(monkeypatch, tmp_path):
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
        lambda **kwargs: {'02b_function_inventory_extract': {'step': '02b'}},
    )
    monkeypatch.setattr(
        module,
        'run_step03_infer_and_signature',
        lambda **kwargs: ({'step': '03'}, {}, tmp_path / 'non-empty'),
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
    summary = json.loads(
        (pipeline_root / 'run-fail' / 'run_summary.json').read_text(encoding='utf-8')
    )
    assert summary['status'] == 'failed'
    assert summary['error_message'] == 'trace flow failed'
    assert summary['config']['selected_reason'] == 'fallback_committed'
    assert '05_pair_trace_dataset' not in summary['steps']


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
