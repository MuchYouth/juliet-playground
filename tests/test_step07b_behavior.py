from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers import REPO_ROOT, load_module_from_path, write_json, write_jsonl


def test_build_stage07b_paths_uses_standard_layout(tmp_path):
    module = load_module_from_path(
        'test_step07b_behavior_paths',
        REPO_ROOT / 'tools/stage/stage07b_patched_export.py',
    )

    run_dir = tmp_path / 'run'
    paths = module.build_stage07b_paths(run_dir)

    assert paths['run_dir'] == run_dir.resolve()
    assert paths['pair_dir'] == run_dir.resolve() / '05_pair_trace_ds'
    assert paths['dataset_export_dir'] == run_dir.resolve() / '07_dataset_export'
    assert paths['pairing']['signatures_dir'] == (
        run_dir.resolve() / '05_pair_trace_ds' / 'train_patched_counterparts_signatures'
    )
    assert paths['slices']['output_dir'] == run_dir.resolve() / '06_slices' / 'train_patched_counterparts'
    assert paths['dataset']['summary_json'] == (
        run_dir.resolve() / '07_dataset_export' / 'train_patched_counterparts_summary.json'
    )


def test_build_train_patched_counterparts_tracks_selection_and_skip_reasons(tmp_path):
    module = load_module_from_path(
        'test_step07b_behavior_selection',
        REPO_ROOT / 'tools/stage/stage07b_patched_export.py',
    )

    run_dir = tmp_path / 'run'
    pair_dir = run_dir / '05_pair_trace_ds'
    dataset_export_dir = run_dir / '07_dataset_export'

    b2b_1 = pair_dir / 'paired_signatures' / 'CASE1' / 'b2b.json'
    b2b_2 = pair_dir / 'paired_signatures' / 'CASE2' / 'b2b.json'
    b2b_3 = pair_dir / 'paired_signatures' / 'CASE3' / 'b2b.json'
    counterpart_1 = pair_dir / 'leftovers' / 'case1_g2b.json'
    counterpart_3 = pair_dir / 'leftovers' / 'case3_unknown.json'

    for path in [b2b_1, b2b_2, b2b_3, counterpart_1, counterpart_3]:
        write_json(path, {'bug_trace': [], 'key': path.stem, 'hash': f'hash-{path.stem}'})

    write_jsonl(
        pair_dir / 'pairs.jsonl',
        [
            {'pair_id': 'primary-1', 'testcase_key': 'CASE1', 'b2b_path': str(b2b_1)},
            {'pair_id': 'primary-2', 'testcase_key': 'CASE2', 'b2b_path': str(b2b_2)},
            {'pair_id': 'primary-3', 'testcase_key': 'CASE3', 'b2b_path': str(b2b_3)},
        ],
    )
    write_jsonl(
        pair_dir / 'leftover_counterparts.jsonl',
        [
            {
                'testcase_key': 'CASE1',
                'trace_file': str(counterpart_1),
                'best_flow_type': 'g2b',
                'bug_trace_length': 8,
            },
            {
                'testcase_key': 'CASE3',
                'trace_file': str(counterpart_3),
                'best_flow_type': '',
                'bug_trace_length': 5,
            },
        ],
    )
    write_json(
        dataset_export_dir / 'split_manifest.json',
        {'pair_ids': {'train_val': ['primary-1', 'primary-2', 'primary-3'], 'test': []}},
    )

    result = module.build_train_patched_counterparts(run_dir=run_dir)

    assert len(result['pairs']) == 1
    selected = result['pairs'][0]
    assert selected['testcase_key'] == 'CASE1'
    assert selected['source_primary_pair_id'] == 'primary-1'
    assert selected['counterpart_flow_type'] == 'g2b'
    assert Path(selected['b2b_path']).exists()
    assert Path(selected['counterpart_path']).exists()
    assert result['stats'] == {
        'counts': {
            'primary_train_val_pairs_total': 3,
            'selected_pairs': 1,
            'selected_counterpart_flow_g2b': 1,
            'primary_train_val_pairs_without_leftover': 1,
            'skipped_missing_counterpart_flow_type': 1,
        },
        'train_val_pair_ids_total': 3,
        'selected_testcases': 1,
    }


def test_build_train_patched_counterparts_requires_train_val_pairs(tmp_path):
    module = load_module_from_path(
        'test_step07b_behavior_requires_train',
        REPO_ROOT / 'tools/stage/stage07b_patched_export.py',
    )

    run_dir = tmp_path / 'run'
    pair_dir = run_dir / '05_pair_trace_ds'
    dataset_export_dir = run_dir / '07_dataset_export'
    write_jsonl(pair_dir / 'pairs.jsonl', [])
    write_jsonl(pair_dir / 'leftover_counterparts.jsonl', [])
    write_json(
        dataset_export_dir / 'split_manifest.json', {'pair_ids': {'train_val': [], 'test': []}}
    )

    with pytest.raises(ValueError, match='No train_val pair_ids found'):
        module.build_train_patched_counterparts(run_dir=run_dir)


def test_build_train_patched_counterparts_pair_id_is_stable_across_run_roots(tmp_path):
    module = load_module_from_path(
        'test_step07b_behavior_pair_id_stability',
        REPO_ROOT / 'tools/stage/stage07b_patched_export.py',
    )

    def build_selection(root: Path) -> str:
        run_dir = root / 'run'
        pair_dir = run_dir / '05_pair_trace_ds'
        dataset_export_dir = run_dir / '07_dataset_export'

        b2b_path = pair_dir / 'paired_signatures' / 'CASE1' / 'b2b.json'
        counterpart_path = pair_dir / 'leftovers' / 'case1_g2b.json'
        for path, payload in (
            (b2b_path, {'bug_trace': [], 'key': 'CASE1|bad|TAINT_ERROR', 'hash': 'hash-b2b'}),
            (counterpart_path, {'bug_trace': [], 'key': 'CASE1|goodG2B|TAINT_ERROR', 'hash': 'hash-g2b'}),
        ):
            write_json(path, payload)

        write_jsonl(
            pair_dir / 'pairs.jsonl',
            [{'pair_id': 'primary-1', 'testcase_key': 'CASE1', 'b2b_path': str(b2b_path)}],
        )
        write_jsonl(
            pair_dir / 'leftover_counterparts.jsonl',
            [
                {
                    'testcase_key': 'CASE1',
                    'trace_file': str(counterpart_path),
                    'best_flow_type': 'g2b',
                    'bug_trace_length': 8,
                }
            ],
        )
        write_json(
            dataset_export_dir / 'split_manifest.json',
            {'pair_ids': {'train_val': ['primary-1'], 'test': []}},
        )

        result = module.build_train_patched_counterparts(run_dir=run_dir)
        return result['pairs'][0]['pair_id']

    assert build_selection(tmp_path / 'root_a') == build_selection(tmp_path / 'root_b')


def test_leftover_sort_key_ignores_run_prefix():
    module = load_module_from_path(
        'test_step07b_behavior_leftover_sort_key_stability',
        REPO_ROOT / 'tools/stage/stage07b_patched_export.py',
    )

    left = {
        'trace_file': '/tmp/run-a/leftovers/CASE1/7.json',
        'best_flow_type': 'g2b',
        'bug_trace_length': 8,
    }
    right = {
        'trace_file': '/tmp/run-b/leftovers/CASE1/7.json',
        'best_flow_type': 'g2b',
        'bug_trace_length': 8,
    }

    assert module.leftover_sort_key(left) == module.leftover_sort_key(right)


def test_export_patched_dataset_runs_selection_slice_and_export(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_step07b_behavior_export_api',
        REPO_ROOT / 'tools/stage/stage07b_patched_export.py',
    )

    run_dir = tmp_path / 'run'
    (run_dir / '05_pair_trace_ds').mkdir(parents=True)
    (run_dir / '07_dataset_export').mkdir(parents=True)

    captured: dict[str, object] = {}

    def fake_build_train_patched_counterparts(*, run_dir):
        captured['build_args'] = {'run_dir': run_dir}
        paths = module.build_stage07b_paths(run_dir)
        return {
            'pairs': [{'pair_id': 'p1', 'testcase_key': 'CASE1'}],
            'artifacts': {
                'pairs_jsonl': str(paths['pairing']['pairs_jsonl']),
                'signatures_dir': str(paths['pairing']['signatures_dir']),
            },
            'stats': {'counts': {'selected_pairs': 1}, 'train_val_pair_ids_total': 1, 'selected_testcases': 1},
        }

    def fake_generate_slices(**kwargs):
        captured['slice_args'] = kwargs
        out = kwargs['output_dir']
        (out / 'slice').mkdir(parents=True, exist_ok=True)
        (out / 'summary.json').write_text('{}\n', encoding='utf-8')
        return {'artifacts': {'slice_dir': str(out / 'slice')}, 'stats': {}}

    def fake_export_dataset(**kwargs):
        captured['export_args'] = kwargs
        dataset_paths = kwargs['dataset_paths']
        dataset_paths['normalized_slices_dir'].mkdir(parents=True, exist_ok=True)
        for key in ('csv_path', 'split_manifest_json', 'summary_json'):
            dataset_paths[key].parent.mkdir(parents=True, exist_ok=True)
            dataset_paths[key].write_text('{}\n', encoding='utf-8')
        return {'artifacts': {k: str(v) for k, v in dataset_paths.items()}, 'stats': {'counts': {}}}

    def fake_merge(summary_path, selection_stats):
        captured['merge_args'] = {'summary_path': summary_path, 'selection_stats': selection_stats}
        return {'artifacts': {}, 'stats': {'selection': selection_stats}}

    monkeypatch.setattr(module, 'build_train_patched_counterparts', fake_build_train_patched_counterparts)
    monkeypatch.setattr(module, 'generate_slices', fake_generate_slices)
    monkeypatch.setattr(module, 'export_dataset', fake_export_dataset)
    monkeypatch.setattr(module, '_merge_patched_summary', fake_merge)

    result = module.export_patched_dataset(run_dir=run_dir, dedup_mode='none')

    assert captured['export_args']['dedup_mode'] == 'none'
    assert captured['build_args']['run_dir'] == run_dir
    assert captured['slice_args']['signature_db_dir'] == (
        run_dir / '05_pair_trace_ds' / 'train_patched_counterparts_signatures'
    )
    assert captured['slice_args']['output_dir'] == (
        run_dir / '06_slices' / 'train_patched_counterparts'
    )
    assert result['artifacts']['summary_json'] == str(
        run_dir / '07_dataset_export' / 'train_patched_counterparts_summary.json'
    )
