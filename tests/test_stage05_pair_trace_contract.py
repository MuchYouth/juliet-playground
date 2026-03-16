from __future__ import annotations

import json
from pathlib import Path

from tests.golden.helpers import (
    REPO_ROOT,
    load_module_from_path,
    prepare_workspace,
)


def test_stage05_pair_trace_contract(tmp_path, monkeypatch):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_stage05_pair_trace_contract',
        REPO_ROOT / 'tools/stage/stage05_pair_trace.py',
    )

    monkeypatch.chdir(baseline_root)
    output_dir = work_root / 'expected/05_pair_trace_ds'
    module.build_paired_trace_dataset(
        trace_jsonl=baseline_root / 'expected/04_trace_flow/trace_flow_match_strict.jsonl',
        output_dir=output_dir,
    )

    pairs_path = output_dir / 'pairs.jsonl'
    leftovers_path = output_dir / 'leftover_counterparts.jsonl'
    paired_signatures_dir = output_dir / 'paired_signatures'
    summary_path = output_dir / 'summary.json'
    for path in [pairs_path, leftovers_path, paired_signatures_dir, summary_path]:
        assert path.exists()

    pairs = [json.loads(line) for line in pairs_path.read_text(encoding='utf-8').splitlines() if line]
    assert pairs
    for pair in pairs:
        assert {'pair_id', 'testcase_key', 'counterpart_flow_type', 'b2b_path', 'counterpart_path'} <= set(pair)
        assert pair['pair_id']
        assert pair['counterpart_flow_type'] != 'b2b'
        assert Path(pair['b2b_path']).exists()
        assert Path(pair['counterpart_path']).exists()

    summary = json.loads(summary_path.read_text(encoding='utf-8'))
    assert set(summary) == {'artifacts', 'stats'}
    assert {'records_total', 'paired_testcases', 'leftover_counterparts'} <= set(summary['stats'])
