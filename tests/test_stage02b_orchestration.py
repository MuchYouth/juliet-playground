from __future__ import annotations

from tests.helpers import REPO_ROOT, load_module_from_path, write_text


def test_build_stage02b_output_paths_matches_pipeline_layout(tmp_path):
    stage02b_module = load_module_from_path(
        'test_stage02b_output_paths_module',
        REPO_ROOT / 'tools/stage/stage02b_flow.py',
    )
    pipeline_module = load_module_from_path(
        'test_stage02b_output_paths_pipeline_module',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-demo'
    source_root = tmp_path / 'juliet' / 'C'
    pipeline_paths = pipeline_module._build_full_run_paths(run_dir=run_dir, source_root=source_root)
    stage02b_paths = stage02b_module.build_stage02b_output_paths(pipeline_paths['flow_dir'])

    assert pipeline_paths['stage02b']['function_names_unique_csv'] == stage02b_paths['function_names_unique_csv']
    assert pipeline_paths['stage02b']['function_names_categorized_jsonl'] == stage02b_paths['function_names_categorized_jsonl']
    assert pipeline_paths['stage02b']['grouped_family_role_json'] == stage02b_paths['grouped_family_role_json']
    assert pipeline_paths['stage02b']['manifest_with_testcase_flows_xml'] == stage02b_paths['manifest_with_testcase_flows_xml']
    assert pipeline_paths['stage02b']['summary_json'] == stage02b_paths['summary_json']


def test_run_stage02b_flow_uses_shared_output_paths(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_stage02b_run_stage_flow_module',
        REPO_ROOT / 'tools/stage/stage02b_flow.py',
    )

    output_dir = tmp_path / '02b_flow'
    expected_paths = module.build_stage02b_output_paths(output_dir)
    captured: dict[str, object] = {}

    def fake_extract_function_inventory(**kwargs):
        captured['extract'] = kwargs
        write_text(kwargs['output_csv'], 'function_name,count\nfoo,1\n')
        return {'total_comment_tags_seen': 1}

    def fake_categorize_function_names(**kwargs):
        captured['categorize'] = kwargs
        write_text(kwargs['output_jsonl'], '{}\n')
        write_text(kwargs['output_nested_json'], '{}')
        return {'total_unique_function_names': 1, 'total_weighted_count': 1}

    def fake_add_flow_tags_to_testcase(**kwargs):
        captured['partition'] = kwargs
        write_text(kwargs['output_xml'], '<root />\n')
        return {'testcases': 1}

    monkeypatch.setattr(module, 'extract_function_inventory', fake_extract_function_inventory)
    monkeypatch.setattr(module, 'categorize_function_names', fake_categorize_function_names)
    monkeypatch.setattr(module, 'add_flow_tags_to_testcase', fake_add_flow_tags_to_testcase)

    result = module.run_stage02b_flow(
        input_xml=tmp_path / 'manifest.xml',
        source_root=tmp_path / 'source',
        output_dir=output_dir,
    )

    assert captured['extract']['output_csv'] == expected_paths['function_names_unique_csv']
    assert captured['categorize']['output_jsonl'] == expected_paths['function_names_categorized_jsonl']
    assert captured['partition']['output_xml'] == expected_paths['manifest_with_testcase_flows_xml']
    assert result['artifacts']['function_names_unique_csv'] == str(expected_paths['function_names_unique_csv'])
