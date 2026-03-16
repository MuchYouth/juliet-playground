from __future__ import annotations

import json
from pathlib import Path

from tests.golden.helpers import (
    REPO_ROOT,
    load_module_from_path,
    prepare_workspace,
    run_module_main,
)


def test_stage05_pair_trace_contract(tmp_path, monkeypatch):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_stage05_pair_trace_contract',
        REPO_ROOT / 'tools/build-paired-trace-signatures.py',
    )

    monkeypatch.chdir(baseline_root)
    output_dir = work_root / 'expected/05_pair_trace_ds'
    assert (
        run_module_main(
            module,
            [
                '--trace-jsonl',
                str(baseline_root / 'expected/04_trace_flow/trace_flow_match_strict.jsonl'),
                '--output-dir',
                str(output_dir),
            ],
            cwd=baseline_root,
        )
        == 0
    )

    pairs_path = output_dir / 'pairs.jsonl'
    leftovers_path = output_dir / 'leftover_counterparts.jsonl'
    paired_signatures_dir = output_dir / 'paired_signatures'
    summary_path = output_dir / 'summary.json'
    for path in [pairs_path, leftovers_path, paired_signatures_dir, summary_path]:
        assert path.exists()

    pairs = [
        json.loads(line) for line in pairs_path.read_text(encoding='utf-8').splitlines() if line
    ]
    assert pairs
    for pair in pairs:
        assert {
            'pair_id',
            'testcase_key',
            'b2b_flow_type',
            'counterpart_flow_type',
            'output_files',
        } <= set(pair)
        assert pair['pair_id']
        assert pair['b2b_flow_type'] == 'b2b'
        assert pair['counterpart_flow_type']
        assert pair['counterpart_flow_type'] != 'b2b'

        b2b_path = Path(pair['output_files']['b2b'])
        counterpart_path = Path(pair['output_files'][pair['counterpart_flow_type']])
        assert b2b_path.exists()
        assert counterpart_path.exists()

        for role_path in [b2b_path, counterpart_path]:
            exported = json.loads(role_path.read_text(encoding='utf-8'))
            assert 'pairing_meta' in exported
            assert exported['pairing_meta']['pair_id'] == pair['pair_id']

    summary = json.loads(summary_path.read_text(encoding='utf-8'))
    assert {'records_total', 'summary_counts', 'paired_testcases', 'leftover_counterparts'} <= set(
        summary
    )
