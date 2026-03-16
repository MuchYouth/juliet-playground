from __future__ import annotations

import csv
import json

from tests.golden.helpers import (
    REPO_ROOT,
    deterministic_tokenizer_context,
    load_module_from_path,
    prepare_workspace,
)


def test_stage07_dataset_export_contract(tmp_path, monkeypatch):
    baseline_root, work_root = prepare_workspace(tmp_path)
    pipeline_module = load_module_from_path(
        'test_stage07_dataset_export_contract',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    monkeypatch.chdir(baseline_root)
    output_dir = work_root / 'expected/07_dataset_export'
    with deterministic_tokenizer_context():
        pipeline_module.export_dataset_from_pipeline(
            pairs_jsonl=baseline_root / 'expected/05_pair_trace_ds/pairs.jsonl',
            paired_signatures_dir=baseline_root / 'expected/05_pair_trace_ds/paired_signatures',
            slice_dir=baseline_root / 'expected/06_slices/slice',
            output_dir=output_dir,
            split_seed=1234,
            train_ratio=0.8,
            dedup_mode='row',
        )

    normalized_slices_dir = output_dir / 'normalized_slices'
    real_vul_data_csv = output_dir / 'Real_Vul_data.csv'
    split_manifest_path = output_dir / 'split_manifest.json'
    summary_path = output_dir / 'summary.json'

    for path in [normalized_slices_dir, real_vul_data_csv, split_manifest_path, summary_path]:
        assert path.exists()

    with real_vul_data_csv.open('r', encoding='utf-8', newline='') as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = list(reader)
    assert header == [
        'file_name',
        'unique_id',
        'target',
        'vulnerable_line_numbers',
        'project',
        'source_signature_path',
        'commit_hash',
        'dataset_type',
        'processed_func',
    ]
    assert rows

    normalized_slice_files = sorted(path for path in normalized_slices_dir.iterdir() if path.is_file())
    assert len(normalized_slice_files) == len(rows)

    split_manifest = json.loads(split_manifest_path.read_text(encoding='utf-8'))
    assert {'counts', 'pair_ids'} <= set(split_manifest)
    assert {'train_val', 'test'} <= set(split_manifest['pair_ids'])

    summary = json.loads(summary_path.read_text(encoding='utf-8'))
    assert set(summary) == {'artifacts', 'stats'}
    assert {'dedup', 'filtered_pair_reasons', 'counts'} <= set(summary['stats'])
    assert summary['stats']['counts']['train_val_pairs'] == len(split_manifest['pair_ids']['train_val'])
    assert summary['stats']['counts']['test_pairs'] == len(split_manifest['pair_ids']['test'])
