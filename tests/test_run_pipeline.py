from __future__ import annotations

import json
from pathlib import Path

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
        params.signature_output_dir.mkdir(parents=True, exist_ok=True)
        (params.slice_output_dir / 'slice').mkdir(parents=True, exist_ok=True)
        for output_path in [
            params.output_pairs_jsonl,
            params.selection_summary_json,
            params.slice_output_dir / 'summary.json',
            params.dataset_export_dir / 'train_patched_counterparts.csv',
            params.dataset_export_dir / 'train_patched_counterparts_dedup_dropped.csv',
            params.dataset_export_dir / 'train_patched_counterparts_token_counts.csv',
            params.dataset_export_dir / 'train_patched_counterparts_token_distribution.png',
            params.dataset_export_dir / 'train_patched_counterparts_split_manifest.json',
            params.dataset_export_dir / 'train_patched_counterparts_summary.json',
        ]:
            write_text(output_path, 'ok\n')
        (params.dataset_export_dir / 'train_patched_counterparts_slices').mkdir(
            parents=True,
            exist_ok=True,
        )
        return {
            'pairing': {
                'output_dir': str(params.pair_dir),
                'pairs_jsonl': str(params.output_pairs_jsonl),
                'signatures_dir': str(params.signature_output_dir),
                'selection_summary_json': str(params.selection_summary_json),
            },
            'slices': {
                'output_dir': str(params.slice_output_dir),
                'slice_dir': str(params.slice_output_dir / 'slice'),
                'summary_json': str(params.slice_output_dir / 'summary.json'),
            },
            'dataset': {
                'output_dir': str(params.dataset_export_dir),
                'csv_path': str(params.dataset_export_dir / 'train_patched_counterparts.csv'),
                'dedup_dropped_csv': str(
                    params.dataset_export_dir / 'train_patched_counterparts_dedup_dropped.csv'
                ),
                'normalized_slices_dir': str(
                    params.dataset_export_dir / 'train_patched_counterparts_slices'
                ),
                'token_counts_csv': str(
                    params.dataset_export_dir / 'train_patched_counterparts_token_counts.csv'
                ),
                'token_distribution_png': str(
                    params.dataset_export_dir / 'train_patched_counterparts_token_distribution.png'
                ),
                'split_manifest_json': str(
                    params.dataset_export_dir / 'train_patched_counterparts_split_manifest.json'
                ),
                'summary_json': str(
                    params.dataset_export_dir / 'train_patched_counterparts_summary.json'
                ),
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
    assert summary['config']['taint_config']['selected_reason'] == 'generated'
    assert summary['steps']['03_infer_and_signature']['returncode'] == 0
    assert Path(summary['outputs']['stage05']['pairs_jsonl']).name == 'pairs.jsonl'
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
    assert summary['config']['taint_config']['selected_reason'] == 'fallback_committed'
    assert '05_pair_trace_dataset' not in summary['steps']


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


def test_stage03_signature_subcommand_delegates(monkeypatch, tmp_path):
    module = load_module_from_path(
        'test_run_pipeline_stage03_signature',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    captured: dict[str, object] = {}

    def fake_run_signature_generation(**kwargs):
        captured.update(kwargs)
        return {'output_dir': str(tmp_path / 'signatures' / 'infer-demo' / 'signature-demo')}

    monkeypatch.setattr(
        module._stage03_signature,
        'run_signature_generation',
        fake_run_signature_generation,
    )

    result = run_module_main(
        module,
        [
            'stage03-signature',
            '--input-dir',
            str(tmp_path / 'infer-run'),
            '--output-root',
            str(tmp_path / 'signatures'),
        ],
    )

    assert result == 0
    assert captured['input_dir'] == tmp_path / 'infer-run'
    assert captured['output_root'] == tmp_path / 'signatures'


def test_stage05_subcommand_uses_wrapper_style_path_resolution(monkeypatch, tmp_path):
    module = load_module_from_path('test_run_pipeline_stage05', REPO_ROOT / 'tools/run_pipeline.py')

    captured: dict[str, object] = {}

    monkeypatch.setattr(
        module._stage05_pair_trace,
        'resolve_paths',
        lambda *, trace_jsonl, output_dir, pipeline_root, run_dir: (
            tmp_path / 'trace.jsonl',
            tmp_path / '05_pair_trace_ds',
            tmp_path / 'run',
        ),
    )

    def fake_build_paired_trace_dataset(**kwargs):
        captured.update(kwargs)
        return {'pairs_jsonl': str(tmp_path / '05_pair_trace_ds' / 'pairs.jsonl')}

    monkeypatch.setattr(
        module._stage05_pair_trace,
        'build_paired_trace_dataset',
        fake_build_paired_trace_dataset,
    )

    result = run_module_main(module, ['stage05'])

    assert result == 0
    assert captured['trace_jsonl'] == tmp_path / 'trace.jsonl'
    assert captured['output_dir'] == tmp_path / '05_pair_trace_ds'
    assert captured['run_dir'] == tmp_path / 'run'


def test_stage06_subcommand_uses_wrapper_style_path_resolution(monkeypatch, tmp_path):
    module = load_module_from_path('test_run_pipeline_stage06', REPO_ROOT / 'tools/run_pipeline.py')

    captured: dict[str, object] = {}

    monkeypatch.setattr(
        module._stage06_slices,
        'resolve_paths',
        lambda *, signature_db_dir, output_dir, pipeline_root, run_dir: (
            tmp_path / 'paired_signatures',
            tmp_path / '06_slices',
            tmp_path / '06_slices' / 'slice',
            tmp_path / 'run',
        ),
    )

    def fake_generate_slices(**kwargs):
        captured.update(kwargs)
        return {'summary_json': str(tmp_path / '06_slices' / 'summary.json')}

    monkeypatch.setattr(module._stage06_slices, 'generate_slices', fake_generate_slices)

    result = run_module_main(module, ['stage06'])

    assert result == 0
    assert captured['signature_db_dir'] == tmp_path / 'paired_signatures'
    assert captured['output_dir'] == tmp_path / '06_slices'
    assert captured['run_dir'] == tmp_path / 'run'


def test_stage07_subcommand_delegates(monkeypatch, tmp_path):
    module = load_module_from_path('test_run_pipeline_stage07', REPO_ROOT / 'tools/run_pipeline.py')

    captured: dict[str, object] = {}

    def fake_export_primary_dataset(params):
        captured['params'] = params
        return {'dataset': {'summary_json': str(tmp_path / 'summary.json')}}

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

    def fake_export_patched_dataset(params):
        captured['params'] = params
        return {'dataset': {'summary_json': str(tmp_path / 'summary.json')}}

    monkeypatch.setattr(
        module._stage07b_patched_export, 'export_patched_dataset', fake_export_patched_dataset
    )
    monkeypatch.setattr(
        module._stage07b_patched_export,
        'resolve_paths',
        lambda **kwargs: module._stage07b_patched_export.ResolvedPatchedExportPaths(
            run_dir=tmp_path / 'run',
            pair_dir=tmp_path / 'pair',
            dataset_export_dir=tmp_path / 'dataset',
            signature_output_dir=tmp_path / 'signatures',
            slice_output_dir=tmp_path / 'slices',
        ),
    )
    monkeypatch.setattr(
        module._stage07b_patched_export,
        'validate_args',
        lambda *args, **kwargs: None,
    )

    result = run_module_main(
        module,
        [
            'stage07b',
            '--dedup-mode',
            'none',
        ],
    )

    assert result == 0
    params = captured['params']
    assert params.run_dir == tmp_path / 'run'
    assert params.dataset_export_dir == tmp_path / 'dataset'
    assert params.output_pairs_jsonl == tmp_path / 'pair' / 'train_patched_counterparts_pairs.jsonl'
    assert params.selection_summary_json == (
        tmp_path / 'pair' / 'train_patched_counterparts_selection_summary.json'
    )
    assert params.dedup_mode == 'none'
