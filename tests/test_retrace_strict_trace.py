from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main, write_text


def test_retrace_cli_defaults_to_pruning_single_child_flows(monkeypatch):
    module = load_module_from_path(
        'test_retrace_strict_trace_default_single_child_prune_flag',
        REPO_ROOT / 'tools/retrace_strict_trace.py',
    )
    captured: dict[str, object] = {}

    def fake_run_retrace_strict_trace(**kwargs):
        captured.update(kwargs)
        return {'artifacts': {}, 'stats': {}}

    monkeypatch.setattr(module, 'run_retrace_strict_trace', fake_run_retrace_strict_trace)

    result = run_module_main(module, ['run-demo'])

    assert result == 0
    assert captured['prune_single_child_flows'] is True


def test_retrace_cli_removed_keep_single_child_flows_option_is_rejected():
    module = load_module_from_path(
        'test_retrace_strict_trace_removed_keep_single_child_flag',
        REPO_ROOT / 'tools/retrace_strict_trace.py',
    )
    with pytest.raises(SystemExit):
        run_module_main(module, ['run-demo', '--keep-single-child-flows'])


def test_retrace_cli_passes_source_root(monkeypatch, tmp_path):
    module = load_module_from_path(
        'test_retrace_strict_trace_source_root_flag',
        REPO_ROOT / 'tools/retrace_strict_trace.py',
    )
    captured: dict[str, object] = {}

    def fake_run_retrace_strict_trace(**kwargs):
        captured.update(kwargs)
        return {'artifacts': {}, 'stats': {}}

    monkeypatch.setattr(module, 'run_retrace_strict_trace', fake_run_retrace_strict_trace)

    source_root = tmp_path / 'juliet' / 'C'
    result = run_module_main(module, ['run-demo', '--source-root', str(source_root)])

    assert result == 0
    assert captured['source_root'] == source_root


def test_retrace_uses_stage02a_enriched_xml_when_source_root_is_provided(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_retrace_strict_trace_uses_stage02a_enriched_xml',
        REPO_ROOT / 'tools/retrace_strict_trace.py',
    )

    source_run_dir = tmp_path / 'pipeline-runs' / 'run-demo'
    write_text(source_run_dir / '01_manifest' / 'manifest_with_comments.xml', '<root />\n')
    signature_non_empty_dir = (
        source_run_dir / '03_signatures' / 'infer-demo' / 'sig-demo' / 'non_empty'
    )
    signature_non_empty_dir.mkdir(parents=True, exist_ok=True)
    write_text(
        source_run_dir / '03_infer_summary.json',
        (
            '{\n'
            '  "artifacts": {\n'
            f'    "signature_non_empty_dir": "{signature_non_empty_dir}"\n'
            '  }\n'
            '}\n'
        ),
    )
    source_root = tmp_path / 'juliet' / 'C'
    source_root.mkdir(parents=True)
    captured: dict[str, Path] = {}

    def fake_run_stage02b_flow(**kwargs):
        write_text(kwargs['output_dir'] / 'manifest_with_testcase_flows.xml', '<root />\n')
        write_text(kwargs['output_dir'] / 'summary.json', '{}\n')
        return {'artifacts': {}, 'stats': {'testcases': 1}}

    def fake_run_stage02b_epic002(**kwargs):
        write_text(kwargs['output_dir'] / 'source_sink_classified.xml', '<root />\n')
        write_text(kwargs['output_dir'] / 'source_sink_exceptions.xml', '<root />\n')
        write_text(kwargs['output_dir'] / 'summary.json', '{}\n')
        return {'artifacts': {}, 'stats': {'classified_flows_total': 1}}

    def fake_extract_unique_code_fields(**kwargs):
        captured['stage02a_input_xml'] = kwargs['input_xml']
        write_text(kwargs['pulse_taint_config_output'], '{}\n')
        write_text(kwargs['output_dir'] / 'summary.json', '{}\n')
        write_text(kwargs['output_dir'] / 'source_sink_classified_with_code.xml', '<root />\n')
        return {'artifacts': {}, 'stats': {'code_backfill_attempted': 1}}

    def fake_filter_traces_by_flow(**kwargs):
        captured['stage04_flow_xml'] = kwargs['flow_xml']
        write_text(kwargs['output_dir'] / 'trace_flow_match_strict.jsonl', '{}\n')
        write_text(kwargs['output_dir'] / 'summary.json', '{}\n')
        return {'artifacts': {}, 'stats': {'traces_strict_match': 1}}

    monkeypatch.setattr(module._stage02b_flow, 'run_stage02b_flow', fake_run_stage02b_flow)
    monkeypatch.setattr(module._stage02b_epic002, 'run_stage02b_epic002', fake_run_stage02b_epic002)
    monkeypatch.setattr(
        module._stage02a_taint, 'extract_unique_code_fields', fake_extract_unique_code_fields
    )
    monkeypatch.setattr(
        module._stage04_trace_flow, 'filter_traces_by_flow', fake_filter_traces_by_flow
    )

    output = module.run_retrace_strict_trace(
        source_run=str(source_run_dir),
        pipeline_root=tmp_path / 'pipeline-runs',
        output_name='retrace-demo',
        source_root=source_root,
    )

    retrace_dir = source_run_dir.parent / 'retrace-demo'
    assert captured['stage02a_input_xml'] == (
        retrace_dir / '02b_flow' / 'epic002' / 'source_sink_classified.xml'
    )
    assert captured['stage04_flow_xml'] == (
        retrace_dir / '02a_taint' / 'source_sink_classified_with_code.xml'
    )
    assert output['artifacts']['source_sink_classified_with_code_xml'] == str(
        retrace_dir / '02a_taint' / 'source_sink_classified_with_code.xml'
    )
