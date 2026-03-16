from __future__ import annotations

import json
import shutil
from pathlib import Path

from tests.golden.helpers import (
    REPO_ROOT,
    deterministic_tokenizer_context,
    load_module_from_path,
    prepare_workspace,
)


def test_stage07b_patched_export_contract(tmp_path, monkeypatch):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_stage07b_patched_export_contract',
        REPO_ROOT / 'tools/stage/stage07b_patched_export.py',
    )

    monkeypatch.chdir(baseline_root)

    output_pair_dir = work_root / 'expected/05_pair_trace_ds'
    output_pair_dir.mkdir(parents=True, exist_ok=True)
    (output_pair_dir / 'pairs.jsonl').write_text(
        (baseline_root / 'expected/05_pair_trace_ds/pairs.jsonl').read_text(encoding='utf-8'),
        encoding='utf-8',
    )
    (output_pair_dir / 'leftover_counterparts.jsonl').write_text(
        (baseline_root / 'expected/05_pair_trace_ds/leftover_counterparts.jsonl').read_text(encoding='utf-8'),
        encoding='utf-8',
    )
    shutil.copytree(
        baseline_root / 'expected/05_pair_trace_ds/paired_signatures',
        output_pair_dir / 'paired_signatures',
    )
    dataset_export_dir = work_root / 'expected/07_dataset_export'
    dataset_export_dir.mkdir(parents=True, exist_ok=True)
    (dataset_export_dir / 'split_manifest.json').write_text(
        (baseline_root / 'expected/07b_dataset_export/split_manifest.json').read_text(encoding='utf-8'),
        encoding='utf-8',
    )

    with deterministic_tokenizer_context():
        result = module.export_patched_dataset(
            run_dir=work_root / 'expected',
            dedup_mode='row',
        )

    required_paths = [
        Path(result['artifacts']['pairing_pairs_jsonl']),
        Path(result['artifacts']['pairing_signatures_dir']),
        Path(result['artifacts']['slice_dir']),
        Path(result['artifacts']['csv_path']),
        Path(result['artifacts']['normalized_slices_dir']),
        Path(result['artifacts']['split_manifest_json']),
        Path(result['artifacts']['summary_json']),
    ]
    for path in required_paths:
        assert path.exists()

    pairs = [
        json.loads(line)
        for line in Path(result['artifacts']['pairing_pairs_jsonl']).read_text(encoding='utf-8').splitlines()
        if line.strip()
    ]
    assert pairs
    for pair in pairs:
        assert {'pair_id', 'testcase_key', 'source_primary_pair_id', 'counterpart_flow_type', 'b2b_path', 'counterpart_path'} <= set(pair)
        assert Path(pair['b2b_path']).exists()
        assert Path(pair['counterpart_path']).exists()

    summary = json.loads(Path(result['artifacts']['summary_json']).read_text(encoding='utf-8'))
    assert set(summary) == {'artifacts', 'stats'}
    assert {'selection', 'counts', 'dedup', 'filtered_pair_reasons'} <= set(summary['stats'])

    split_manifest = json.loads(Path(result['artifacts']['split_manifest_json']).read_text(encoding='utf-8'))
    assert {'pair_ids', 'counts'} <= set(split_manifest)
