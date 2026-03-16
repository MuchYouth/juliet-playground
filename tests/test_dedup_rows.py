from __future__ import annotations

from collections import Counter


def test_dedupe_pairs_by_normalized_rows_drops_duplicate_pair_and_keeps_audit(
    load_tools_module,
):
    module = load_tools_module('test_run_pipeline_dedup_module', 'run_pipeline.py')

    surviving_pairs = {
        'pair-keep': [
            {
                'pair_id': 'pair-keep',
                'testcase_key': 'CASE001',
                'role': 'b2b',
                'role_name': 'b2b',
                'target': 1,
                'source_signature_path': 'sig/keep-b2b.json',
                'normalized_code': 'int bad = 1;',
            },
            {
                'pair_id': 'pair-keep',
                'testcase_key': 'CASE001',
                'role': 'counterpart',
                'role_name': 'g2b',
                'target': 0,
                'source_signature_path': 'sig/keep-g2b.json',
                'normalized_code': 'int good = 0;',
            },
        ],
        'pair-drop': [
            {
                'pair_id': 'pair-drop',
                'testcase_key': 'CASE002',
                'role': 'b2b',
                'role_name': 'b2b',
                'target': 1,
                'source_signature_path': 'sig/drop-b2b.json',
                'normalized_code': 'int bad = 1;',
            },
            {
                'pair_id': 'pair-drop',
                'testcase_key': 'CASE002',
                'role': 'counterpart',
                'role_name': 'g2b',
                'target': 0,
                'source_signature_path': 'sig/drop-g2b.json',
                'normalized_code': 'int good = 0;',
            },
        ],
    }

    filtered_pair_reasons = Counter()
    deduped_pairs, dedup_summary, dedup_audit_rows = module.dedupe_pairs_by_normalized_rows(
        surviving_pairs=surviving_pairs,
        filtered_pair_reasons=filtered_pair_reasons,
        dedup_mode='row',
    )

    assert list(deduped_pairs) == ['pair-keep']
    assert dedup_summary['pairs_before'] == 2
    assert dedup_summary['pairs_after'] == 1
    assert dedup_summary['pairs_dropped_duplicate'] == 1
    assert filtered_pair_reasons['dedup_duplicate_normalized_slice'] == 1

    assert len(dedup_audit_rows) == 2
    assert {row['pair_id'] for row in dedup_audit_rows} == {'pair-drop'}
    assert {row['matched_kept_pair_id'] for row in dedup_audit_rows} == {'pair-keep'}
    assert {row['dedup_reason'] for row in dedup_audit_rows} == {'duplicate_pair'}
