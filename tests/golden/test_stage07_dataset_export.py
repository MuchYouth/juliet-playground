from __future__ import annotations

from tests.golden.helpers import (
    REPO_ROOT,
    assert_directory_matches,
    deterministic_tokenizer_context,
    load_module_from_path,
    prepare_workspace,
)


def test_stage07_dataset_export_matches_golden(tmp_path, monkeypatch):
    baseline_root, work_root = prepare_workspace(tmp_path)
    pipeline_module = load_module_from_path(
        'test_golden_stage07_dataset_export',
        REPO_ROOT / 'tools/run-epic001-pipeline.py',
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

    assert_directory_matches(
        expected_dir=baseline_root / 'expected/07_dataset_export',
        actual_dir=output_dir,
        root_aliases=[(baseline_root, ''), (work_root, ''), (REPO_ROOT, '')],
    )
