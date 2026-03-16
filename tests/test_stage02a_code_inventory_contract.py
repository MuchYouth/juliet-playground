from __future__ import annotations

import json

from tests.golden.helpers import (
    REPO_ROOT,
    load_module_from_path,
    prepare_workspace,
    run_module_main,
)


def test_stage02a_code_inventory_contract(tmp_path):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_stage02a_code_inventory_contract',
        REPO_ROOT
        / 'experiments/epic001a_code_field_inventory/scripts/extract_unique_code_fields.py',
    )

    output_dir = work_root / 'expected/02a_taint'
    pulse_config_path = output_dir / 'pulse-taint-config.json'
    assert (
        run_module_main(
            module,
            [
                '--input-xml',
                str(baseline_root / 'expected/01_manifest/manifest_with_comments.xml'),
                '--source-root',
                str(REPO_ROOT / 'juliet-test-suite-v1.3/C'),
                '--output-dir',
                str(output_dir),
                '--pulse-taint-config-output',
                str(pulse_config_path),
            ],
        )
        == 0
    )

    candidate_map_path = output_dir / 'source_sink_candidate_map.json'
    summary_path = output_dir / 'summary.json'

    assert pulse_config_path.exists()
    assert candidate_map_path.exists()
    assert summary_path.exists()

    pulse_config = json.loads(pulse_config_path.read_text(encoding='utf-8'))
    assert set(pulse_config) == {'pulse-taint-sources', 'pulse-taint-sinks'}
    assert isinstance(pulse_config['pulse-taint-sources'], list)
    assert isinstance(pulse_config['pulse-taint-sinks'], list)
    assert pulse_config['pulse-taint-sources']
    assert pulse_config['pulse-taint-sinks']

    source_procedures = set()
    for row in pulse_config['pulse-taint-sources']:
        assert set(row) == {'procedure', 'taint_target'}
        assert row['procedure'].strip()
        assert row['taint_target'] in {'ReturnValue', 'AllArguments'}
        source_procedures.add(row['procedure'])

    sink_procedures = set()
    for row in pulse_config['pulse-taint-sinks']:
        assert set(row) == {'procedure', 'taint_target'}
        assert row['procedure'].strip()
        assert row['taint_target'] == 'AllArguments'
        sink_procedures.add(row['procedure'])

    assert source_procedures == sink_procedures

    candidate_map = json.loads(candidate_map_path.read_text(encoding='utf-8'))
    assert isinstance(candidate_map, dict)
    assert candidate_map
    for key, calls in candidate_map.items():
        assert isinstance(key, str)
        assert isinstance(calls, list)
        for call in calls:
            assert isinstance(call, dict)
            assert isinstance(call.get('name'), str)
            assert call['name'].strip()
            assert isinstance(call.get('argc'), int)
            assert call['argc'] >= 0
            if 'original_name' in call:
                assert isinstance(call['original_name'], str)
                assert call['original_name'].strip()

    summary = json.loads(summary_path.read_text(encoding='utf-8'))
    assert summary['candidate_map_keys'] == len(candidate_map)
    assert summary['unique_function_names'] == len(source_procedures)
    assert summary['keys_with_calls'] <= summary['candidate_map_keys']
