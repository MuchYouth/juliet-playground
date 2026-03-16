from __future__ import annotations

from tests.helpers import REPO_ROOT, load_module_from_path, write_jsonl


def test_primary_dataset_export_uses_shared_step07_core(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_step07_shared_primary',
        REPO_ROOT / 'tools/stage/stage07_dataset_export.py',
    )

    pairs_jsonl = tmp_path / 'pairs.jsonl'
    write_jsonl(
        pairs_jsonl,
        [
            {'pair_id': 'pair-a', 'testcase_key': 'CASE_A'},
            {'pair_id': 'pair-b', 'testcase_key': 'CASE_B'},
        ],
    )
    paired_signatures_dir = tmp_path / 'paired'
    slice_dir = tmp_path / 'slice'
    paired_signatures_dir.mkdir()
    slice_dir.mkdir()

    captured: dict[str, object] = {}

    def fake_run_configured(request):
        captured['request'] = request
        return {
            'artifacts': {k: str(v) for k, v in request.export_paths.items()},
            'stats': {},
        }

    monkeypatch.setattr(module, 'run_configured_step07_export', fake_run_configured)

    result = module.export_dataset_from_pipeline(
        pairs_jsonl=pairs_jsonl,
        paired_signatures_dir=paired_signatures_dir,
        slice_dir=slice_dir,
        output_dir=tmp_path / 'out',
        split_seed=1234,
        train_ratio=0.8,
        dedup_mode='row',
    )

    assert result['artifacts']['csv_path'].endswith('Real_Vul_data.csv')
    request = captured['request']
    split_assignments = request.split_assignments_fn(['pair-a', 'pair-b'])
    assert split_assignments.keys() == {'pair-a', 'pair-b'}
    assert set(split_assignments.values()) == {'train_val', 'test'}
    assert request.dataset_basename is None
    assert request.paired_signatures_dir == paired_signatures_dir
    assert request.slice_dir == slice_dir


def test_patched_counterparts_uses_shared_step07_core(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_step07_shared_patched',
        REPO_ROOT / 'tools/stage/stage07b_patched_export.py',
    )

    paired_signatures_dir = tmp_path / 'paired'
    slice_dir = tmp_path / 'slice'
    paired_signatures_dir.mkdir()
    slice_dir.mkdir()
    pairs = [
        {'pair_id': 'pair-a', 'testcase_key': 'CASE_A'},
        {'pair_id': 'pair-b', 'testcase_key': 'CASE_B'},
    ]

    captured: dict[str, object] = {}

    def fake_run_configured(request):
        captured['request'] = request
        return {
            'artifacts': {k: str(v) for k, v in request.export_paths.items()},
            'stats': {'counts': {'pairs_total': 2}},
        }

    monkeypatch.setattr(module, 'run_configured_step07_export', fake_run_configured)

    dataset_paths = module.build_dataset_export_paths(tmp_path / 'out', module.DATASET_BASENAME)
    result = module.export_dataset(
        pairs=pairs,
        paired_signatures_dir=paired_signatures_dir,
        slice_dir=slice_dir,
        dataset_paths=dataset_paths,
        dedup_mode='none',
    )

    assert result['artifacts']['csv_path'].endswith('train_patched_counterparts.csv')
    request = captured['request']
    assert request.split_assignments_fn(['pair-a', 'pair-b']) == {
        'pair-a': 'train_val',
        'pair-b': 'train_val',
    }
    assert request.dataset_basename == 'train_patched_counterparts'
