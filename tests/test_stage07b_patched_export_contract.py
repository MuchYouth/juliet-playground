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
        (baseline_root / 'expected/05_pair_trace_ds/leftover_counterparts.jsonl').read_text(
            encoding='utf-8'
        ),
        encoding='utf-8',
    )
    shutil.copytree(
        baseline_root / 'expected/05_pair_trace_ds/paired_signatures',
        output_pair_dir / 'paired_signatures',
    )
    dataset_export_dir = work_root / 'expected/07_dataset_export'
    dataset_export_dir.mkdir(parents=True, exist_ok=True)
    (dataset_export_dir / 'split_manifest.json').write_text(
        (baseline_root / 'expected/07b_dataset_export/split_manifest.json').read_text(
            encoding='utf-8'
        ),
        encoding='utf-8',
    )

    with deterministic_tokenizer_context():
        result = module.export_patched_dataset(
            module.PatchedDatasetExportParams(
                run_dir=work_root / 'expected',
                dedup_mode='row',
            )
        )

    required_paths = [
        result.pairing.pairs_jsonl,
        result.pairing.selection_summary_json,
        result.pairing.signatures_dir,
        result.slices.slice_dir,
        result.slices.summary_json,
        result.dataset.csv_path,
        result.dataset.dedup_dropped_csv,
        result.dataset.normalized_slices_dir,
        result.dataset.token_counts_csv,
        result.dataset.token_distribution_png,
        result.dataset.split_manifest_json,
        result.dataset.summary_json,
    ]
    for path in required_paths:
        assert path.exists()

    pairs = [
        json.loads(line)
        for line in result.pairing.pairs_jsonl.read_text(encoding='utf-8').splitlines()
        if line.strip()
    ]
    assert pairs
    for pair in pairs:
        assert {
            'pair_id',
            'testcase_key',
            'source_primary_pair_id',
            'b2b_flow_type',
            'counterpart_flow_type',
            'output_files',
        } <= set(pair)
        assert pair['pair_id']
        assert pair['source_primary_pair_id']
        assert pair['b2b_flow_type'] == 'b2b'
        assert pair['counterpart_flow_type']
        assert pair['counterpart_flow_type'] != 'b2b'

        for path_str in pair['output_files'].values():
            exported = json.loads(Path(path_str).read_text(encoding='utf-8'))
            assert 'pairing_meta' in exported
            assert exported['pairing_meta']['pair_id'] == pair['pair_id']

    selection_summary = json.loads(
        result.pairing.selection_summary_json.read_text(encoding='utf-8')
    )
    assert {'dataset_basename', 'counts', 'selected_testcases', 'train_val_pair_ids_total'} <= set(
        selection_summary
    )

    split_manifest = json.loads(result.dataset.split_manifest_json.read_text(encoding='utf-8'))
    assert {'pair_ids', 'counts'} <= set(split_manifest)
