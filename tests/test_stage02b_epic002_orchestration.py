from __future__ import annotations

import xml.etree.ElementTree as ET

from tests.golden.helpers import prepare_workspace
from tests.helpers import REPO_ROOT, load_module_from_path, write_text


def test_build_stage02b_epic002_output_paths_matches_pipeline_layout(tmp_path):
    stage_module = load_module_from_path(
        'test_stage02b_epic002_output_paths_module',
        REPO_ROOT / 'tools/stage/stage02b_epic002.py',
    )
    pipeline_module = load_module_from_path(
        'test_stage02b_epic002_output_paths_pipeline_module',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-demo'
    source_root = tmp_path / 'juliet' / 'C'
    pipeline_paths = pipeline_module._build_full_run_paths(run_dir=run_dir, source_root=source_root)
    stage_paths = stage_module.build_stage02b_epic002_output_paths(run_dir / '02b_flow' / 'epic002')

    assert pipeline_paths['stage02b_epic002'] == stage_paths
    assert set(stage_paths) == {
        'output_dir',
        'source_sink_classified_xml',
        'source_sink_exceptions_xml',
        'summary_json',
    }


def test_run_stage02b_epic002_uses_shared_output_paths(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_stage02b_epic002_run_stage_module',
        REPO_ROOT / 'tools/stage/stage02b_epic002.py',
    )

    output_dir = tmp_path / '02b_flow' / 'epic002'
    expected_paths = module.build_stage02b_epic002_output_paths(output_dir)
    captured: dict[str, object] = {}

    def fake_write_classification_outputs(**kwargs):
        captured.update(kwargs)
        write_text(kwargs['output_xml'], '<root />\n')
        write_text(kwargs['exceptions_xml'], '<root />\n')
        return {
            'counts': {'classified_flows_total': 1, 'exception_flows_total': 0},
            'flow_type_counts': {'b2b': 1},
            'ordering_method_counts': {'same_function_line_order': 1},
            'exception_comment_count_distribution': {},
            'exception_reason_counts': {},
            'entry_entry_pair_count': 0,
            'entry_entry_pair_with_scope_count': 0,
            'entry_entry_pair_with_destructor_count': 0,
            'triplet_without_scope_count': 0,
            'triplet_without_destructor_count': 0,
        }

    monkeypatch.setattr(
        module,
        'write_classification_outputs',
        fake_write_classification_outputs,
    )

    result = module.run_stage02b_epic002(
        input_xml=tmp_path / 'manifest_with_testcase_flows.xml',
        output_dir=output_dir,
    )

    assert captured['manifest_xml'] == tmp_path / 'manifest_with_testcase_flows.xml'
    assert captured['output_xml'] == expected_paths['source_sink_classified_xml']
    assert captured['exceptions_xml'] == expected_paths['source_sink_exceptions_xml']
    assert captured['summary_json'] is None
    assert result['artifacts']['source_sink_classified_xml'] == str(
        expected_paths['source_sink_classified_xml']
    )
    assert result['artifacts']['source_sink_exceptions_xml'] == str(
        expected_paths['source_sink_exceptions_xml']
    )
    assert result['artifacts']['summary_json'] == str(expected_paths['summary_json'])
    assert result['stats']['classified_flows_total'] == 1


def test_run_stage02b_epic002_generates_role_annotated_xml(tmp_path):
    module = load_module_from_path(
        'test_stage02b_epic002_run_stage_real',
        REPO_ROOT / 'tools/stage/stage02b_epic002.py',
    )
    baseline_root, work_root = prepare_workspace(tmp_path)
    output_dir = work_root / 'expected' / '02b_flow' / 'epic002'

    result = module.run_stage02b_epic002(
        input_xml=baseline_root / 'expected/02c_flow/manifest_with_testcase_flows.xml',
        output_dir=output_dir,
    )

    classified_xml = output_dir / 'source_sink_classified.xml'
    exceptions_xml = output_dir / 'source_sink_exceptions.xml'
    summary_json = output_dir / 'summary.json'

    assert classified_xml.exists()
    assert exceptions_xml.exists()
    assert summary_json.exists()
    assert result['stats']['classified_flows_total'] > 0

    root = ET.parse(classified_xml).getroot()
    roles = {
        child.attrib.get('role')
        for testcase in root.findall('testcase')
        for flow in testcase.findall('flow')
        for child in flow
        if child.tag in {'flaw', 'fix'} and 'role' in child.attrib
    }
    assert roles == {'source', 'sink'}
