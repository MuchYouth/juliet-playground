from __future__ import annotations

import json
from pathlib import Path

from tests.golden.helpers import (
    REPO_ROOT,
    deterministic_tokenizer_context,
    load_module_from_path,
    prepare_workspace,
    run_module_main,
)


def test_stage07b_patched_export_contract(tmp_path, monkeypatch):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_stage07b_patched_export_contract',
        REPO_ROOT / 'tools/export_train_patched_counterparts.py',
    )

    monkeypatch.chdir(baseline_root)

    pair_dir = baseline_root / 'expected/05_pair_trace_ds'
    output_pair_dir = work_root / 'expected/05_pair_trace_ds'
    dataset_export_dir = work_root / 'expected/07b_dataset_export'
    slice_output_dir = work_root / 'expected/06_slices/train_patched_counterparts'
    signature_output_dir = output_pair_dir / 'train_patched_counterparts_signatures'
    output_pairs_jsonl = output_pair_dir / 'train_patched_counterparts_pairs.jsonl'
    selection_summary_json = output_pair_dir / 'train_patched_counterparts_selection_summary.json'

    dataset_export_dir.mkdir(parents=True, exist_ok=True)
    (dataset_export_dir / 'split_manifest.json').write_text(
        (baseline_root / 'expected/07b_dataset_export/split_manifest.json').read_text(
            encoding='utf-8'
        ),
        encoding='utf-8',
    )

    with deterministic_tokenizer_context():
        assert (
            run_module_main(
                module,
                [
                    '--pair-dir',
                    str(pair_dir),
                    '--dataset-export-dir',
                    str(dataset_export_dir),
                    '--signature-output-dir',
                    str(signature_output_dir),
                    '--slice-output-dir',
                    str(slice_output_dir),
                    '--output-pairs-jsonl',
                    str(output_pairs_jsonl),
                    '--selection-summary-json',
                    str(selection_summary_json),
                    '--dedup-mode',
                    'row',
                    '--overwrite',
                ],
                cwd=baseline_root,
            )
            == 0
        )

    required_paths = [
        output_pairs_jsonl,
        selection_summary_json,
        signature_output_dir,
        slice_output_dir / 'slice',
        slice_output_dir / 'summary.json',
        dataset_export_dir / 'train_patched_counterparts.csv',
        dataset_export_dir / 'train_patched_counterparts_dedup_dropped.csv',
        dataset_export_dir / 'train_patched_counterparts_slices',
        dataset_export_dir / 'train_patched_counterparts_token_counts.csv',
        dataset_export_dir / 'train_patched_counterparts_token_distribution.png',
        dataset_export_dir / 'train_patched_counterparts_split_manifest.json',
        dataset_export_dir / 'train_patched_counterparts_summary.json',
    ]
    for path in required_paths:
        assert path.exists()

    pairs = [
        json.loads(line)
        for line in output_pairs_jsonl.read_text(encoding='utf-8').splitlines()
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

    selection_summary = json.loads(selection_summary_json.read_text(encoding='utf-8'))
    assert {
        'source_split_manifest_json',
        'output_pairs_jsonl',
        'counts',
        'selected_testcases',
    } <= set(selection_summary)

    split_manifest = json.loads(
        (dataset_export_dir / 'train_patched_counterparts_split_manifest.json').read_text(
            encoding='utf-8'
        )
    )
    assert {'pair_ids', 'counts'} <= set(split_manifest)
