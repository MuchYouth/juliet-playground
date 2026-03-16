from __future__ import annotations

import shutil

from tests.golden.helpers import (
    REPO_ROOT,
    assert_directory_matches,
    assert_directory_text_multiset_matches,
    deterministic_tokenizer_context,
    load_module_from_path,
    normalized_file_text,
    prepare_workspace,
)


def test_stage07b_patched_export_matches_golden(tmp_path, monkeypatch):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_golden_stage07b_patched_export',
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
    split_manifest = normalized_file_text(
        baseline_root / 'expected/07b_dataset_export/split_manifest.json',
        [(baseline_root, ''), (work_root, ''), (REPO_ROOT, '')],
    )
    (dataset_export_dir / 'split_manifest.json').write_text(split_manifest, encoding='utf-8')

    with deterministic_tokenizer_context():
        result = module.export_patched_dataset(
            module.PatchedDatasetExportParams(
                run_dir=work_root / 'expected',
                dedup_mode='row',
            )
        )

    root_aliases = [(baseline_root, ''), (work_root, ''), (REPO_ROOT, '')]
    assert normalized_file_text(
        baseline_root / 'expected/05_pair_trace_ds/train_patched_counterparts_pairs.jsonl',
        root_aliases,
    ) == normalized_file_text(result.pairing.pairs_jsonl, root_aliases)
    assert normalized_file_text(
        baseline_root
        / 'expected/05_pair_trace_ds/train_patched_counterparts_selection_summary.json',
        root_aliases,
    ) == normalized_file_text(result.pairing.selection_summary_json, root_aliases)

    assert_directory_matches(
        expected_dir=baseline_root
        / 'expected/05_pair_trace_ds/train_patched_counterparts_signatures',
        actual_dir=result.pairing.signatures_dir,
        root_aliases=root_aliases,
    )
    assert_directory_matches(
        expected_dir=baseline_root / 'expected/06_slices/train_patched_counterparts',
        actual_dir=result.slices.output_dir,
        root_aliases=root_aliases,
    )

    for name in [
        'train_patched_counterparts.csv',
        'train_patched_counterparts_dedup_dropped.csv',
        'train_patched_counterparts_token_counts.csv',
        'train_patched_counterparts_split_manifest.json',
        'train_patched_counterparts_summary.json',
    ]:
        assert normalized_file_text(
            baseline_root / 'expected/07b_dataset_export' / name,
            root_aliases,
        ) == normalized_file_text(result.dataset.output_dir / name, root_aliases)

    assert_directory_text_multiset_matches(
        expected_dir=baseline_root
        / 'expected/07b_dataset_export/train_patched_counterparts_slices',
        actual_dir=result.dataset.output_dir / 'train_patched_counterparts_slices',
        root_aliases=root_aliases,
        suffixes={'.c', '.cpp'},
    )
    assert (
        result.dataset.output_dir / 'train_patched_counterparts_token_distribution.png'
    ).exists()
