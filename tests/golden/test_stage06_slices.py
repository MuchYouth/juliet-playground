from __future__ import annotations

from tests.golden.helpers import (
    REPO_ROOT,
    assert_directory_matches,
    load_module_from_path,
    normalized_file_text,
    prepare_workspace,
    run_module_main,
)


def test_stage06_slices_matches_golden(tmp_path):
    baseline_root, work_root = prepare_workspace(tmp_path)
    root_aliases = [(baseline_root, ''), (work_root, ''), (REPO_ROOT, '')]
    module = load_module_from_path(
        'test_golden_stage06_slices',
        REPO_ROOT / 'tools/generate_slices.py',
    )

    output_dir = work_root / 'expected/06_slices'
    assert (
        run_module_main(
            module,
            [
                '--signature-db-dir',
                str(baseline_root / 'expected/05_pair_trace_ds/paired_signatures'),
                '--output-dir',
                str(output_dir),
            ],
        )
        == 0
    )

    assert_directory_matches(
        expected_dir=baseline_root / 'expected/06_slices/slice',
        actual_dir=output_dir / 'slice',
        root_aliases=root_aliases,
    )
    assert normalized_file_text(
        baseline_root / 'expected/06_slices/summary.json',
        root_aliases,
    ) == normalized_file_text(
        output_dir / 'summary.json',
        root_aliases,
    )
