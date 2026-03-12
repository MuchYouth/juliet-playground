from __future__ import annotations


def test_compute_pair_split_is_deterministic_and_keeps_both_sides(load_tools_module):
    module = load_tools_module('test_run_epic001_pipeline_module', 'run-epic001-pipeline.py')

    pair_ids = ['pair-3', 'pair-1', 'pair-2', 'pair-4', 'pair-5']
    split_first = module.compute_pair_split(pair_ids, train_ratio=0.8, seed=1234)
    split_second = module.compute_pair_split(pair_ids, train_ratio=0.8, seed=1234)

    assert split_first == split_second
    assert set(split_first) == set(pair_ids)
    assert sorted(split_first.values()) == [
        'test',
        'train_val',
        'train_val',
        'train_val',
        'train_val',
    ]
