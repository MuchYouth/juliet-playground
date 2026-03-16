from __future__ import annotations

from tests.helpers import REPO_ROOT, load_module_from_path


def test_build_dataset_export_paths_covers_primary_and_patched(tmp_path):
    module = load_module_from_path(
        'test_shared_artifact_layout_dataset',
        REPO_ROOT / 'tools/shared/artifact_layout.py',
    )

    output_dir = tmp_path / '07_dataset_export'
    primary = module.build_dataset_export_paths(output_dir)
    patched = module.build_dataset_export_paths(
        output_dir,
        module.TRAIN_PATCHED_COUNTERPARTS_BASENAME,
    )

    assert primary['csv_path'] == output_dir / 'Real_Vul_data.csv'
    assert primary['split_manifest_json'] == output_dir / 'split_manifest.json'
    assert primary['summary_json'] == output_dir / 'summary.json'
    assert patched['csv_path'] == output_dir / 'train_patched_counterparts.csv'
    assert patched['normalized_slices_dir'] == output_dir / 'train_patched_counterparts_slices'
    assert patched['summary_json'] == output_dir / 'train_patched_counterparts_summary.json'


def test_pair_trace_and_slice_path_builders_match_expected_layout(tmp_path):
    module = load_module_from_path(
        'test_shared_artifact_layout_pairing',
        REPO_ROOT / 'tools/shared/artifact_layout.py',
    )

    pair_dir = tmp_path / 'run' / '05_pair_trace_ds'
    slice_stage_dir = tmp_path / 'run' / '06_slices' / 'train_patched_counterparts'
    pair_paths = module.build_pair_trace_paths(pair_dir)
    patched_pair_paths = module.build_patched_pairing_paths(pair_dir)
    slice_paths = module.build_slice_stage_paths(slice_stage_dir)

    assert pair_paths['pairs_jsonl'] == pair_dir / 'pairs.jsonl'
    assert pair_paths['leftover_counterparts_jsonl'] == pair_dir / 'leftover_counterparts.jsonl'
    assert pair_paths['paired_signatures_dir'] == pair_dir / 'paired_signatures'
    assert patched_pair_paths['pairs_jsonl'] == (pair_dir / 'train_patched_counterparts_pairs.jsonl')
    assert patched_pair_paths['signatures_dir'] == (
        pair_dir / 'train_patched_counterparts_signatures'
    )
    assert slice_paths['slice_dir'] == slice_stage_dir / 'slice'
    assert slice_paths['summary_json'] == slice_stage_dir / 'summary.json'
