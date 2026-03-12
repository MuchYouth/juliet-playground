from __future__ import annotations

from tests.golden.helpers import (
    REPO_ROOT,
    assert_directory_matches,
    load_module_from_path,
    prepare_workspace,
    run_module_main,
)


def test_stage04_trace_flow_matches_golden(tmp_path):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_golden_stage04_trace_flow',
        REPO_ROOT / 'experiments/epic001d_trace_flow_filter/scripts/filter_traces_by_flow.py',
    )

    output_dir = work_root / 'expected/04_trace_flow'
    assert (
        run_module_main(
            module,
            [
                '--flow-xml',
                str(baseline_root / 'expected/02c_flow/manifest_with_testcase_flows.xml'),
                '--signatures-dir',
                str(baseline_root / 'expected/03_signatures_non_empty'),
                '--output-dir',
                str(output_dir),
            ],
        )
        == 0
    )

    assert_directory_matches(
        expected_dir=baseline_root / 'expected/04_trace_flow',
        actual_dir=output_dir,
        root_aliases=[(baseline_root, ''), (work_root, ''), (REPO_ROOT, '')],
    )
