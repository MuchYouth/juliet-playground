from __future__ import annotations

from tests.golden.helpers import (
    REPO_ROOT,
    assert_directory_matches,
    load_module_from_path,
    prepare_workspace,
    run_module_main,
)


def test_stage02a_code_inventory_matches_golden(tmp_path):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_golden_stage02a_code_inventory',
        REPO_ROOT
        / 'experiments/epic001a_code_field_inventory/scripts/extract_unique_code_fields.py',
    )

    output_dir = work_root / 'expected/02a_taint'
    assert (
        run_module_main(
            module,
            [
                '--input-xml',
                str(baseline_root / 'expected/01_manifest/manifest_with_comments.xml'),
                '--source-root',
                str(REPO_ROOT / 'juliet-test-suite-v1.3/C'),
                '--output-dir',
                str(output_dir),
                '--pulse-taint-config-output',
                str(output_dir / 'pulse-taint-config.json'),
            ],
        )
        == 0
    )

    assert_directory_matches(
        expected_dir=baseline_root / 'expected/02a_taint',
        actual_dir=output_dir,
        root_aliases=[(baseline_root, ''), (work_root, ''), (REPO_ROOT, '')],
    )
