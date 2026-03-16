from __future__ import annotations

from tests.golden.helpers import (
    REPO_ROOT,
    assert_directory_matches,
    assert_unordered_jsonl_matches,
    load_module_from_path,
    normalized_file_text,
    prepare_workspace,
)


def test_stage05_pair_trace_matches_golden(tmp_path, monkeypatch):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_golden_stage05_pair_trace',
        REPO_ROOT / 'tools/stage/stage05_pair_trace.py',
    )

    monkeypatch.chdir(baseline_root)
    output_dir = work_root / 'expected/05_pair_trace_ds'
    module.build_paired_trace_dataset(
        trace_jsonl=baseline_root / 'expected/04_trace_flow/trace_flow_match_strict.jsonl',
        output_dir=output_dir,
        run_dir=work_root / 'expected',
    )

    root_aliases = [(baseline_root, ''), (work_root, ''), (REPO_ROOT, '')]
    for name in ['pairs.jsonl', 'summary.json']:
        assert normalized_file_text(
            baseline_root / 'expected/05_pair_trace_ds' / name,
            root_aliases,
        ) == normalized_file_text(output_dir / name, root_aliases)

    assert_unordered_jsonl_matches(
        expected_path=baseline_root / 'expected/05_pair_trace_ds/leftover_counterparts.jsonl',
        actual_path=output_dir / 'leftover_counterparts.jsonl',
        root_aliases=root_aliases,
    )

    assert_directory_matches(
        expected_dir=baseline_root / 'expected/05_pair_trace_ds/paired_signatures',
        actual_dir=output_dir / 'paired_signatures',
        root_aliases=root_aliases,
    )
