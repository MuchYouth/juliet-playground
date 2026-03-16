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
    source_procedures = {row['procedure'] for row in pulse_config['pulse-taint-sources']}
    sink_procedures = {row['procedure'] for row in pulse_config['pulse-taint-sinks']}
    assert source_procedures == sink_procedures

    candidate_map = json.loads(candidate_map_path.read_text(encoding='utf-8'))
    assert isinstance(candidate_map, dict)
    assert candidate_map

    summary = json.loads(summary_path.read_text(encoding='utf-8'))
    assert set(summary) == {'artifacts', 'stats'}
    assert summary['artifacts']['pulse_taint_config'] == str(pulse_config_path)
    assert summary['stats']['candidate_map_keys'] == len(candidate_map)
    assert summary['stats']['unique_function_names'] == len(source_procedures)
    assert summary['stats']['keys_with_calls'] <= summary['stats']['candidate_map_keys']
