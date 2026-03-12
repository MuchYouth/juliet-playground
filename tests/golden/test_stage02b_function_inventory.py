from __future__ import annotations

from tests.golden.helpers import (
    REPO_ROOT,
    assert_directory_matches,
    load_module_from_path,
    prepare_workspace,
    run_module_main,
)


def test_stage02b_function_inventory_matches_golden(tmp_path):
    baseline_root, work_root = prepare_workspace(tmp_path)
    output_dir = work_root / 'expected/02b_inventory'

    extract_module = load_module_from_path(
        'test_golden_stage02b_extract_inventory',
        REPO_ROOT / 'experiments/epic001b_function_inventory/scripts/extract_function_inventory.py',
    )
    assert (
        run_module_main(
            extract_module,
            [
                '--input-xml',
                str(baseline_root / 'expected/01_manifest/manifest_with_comments.xml'),
                '--output-csv',
                str(output_dir / 'function_names_unique.csv'),
                '--output-summary',
                str(output_dir / 'function_inventory_summary.json'),
            ],
        )
        == 0
    )

    categorize_module = load_module_from_path(
        'test_golden_stage02b_categorize_inventory',
        REPO_ROOT / 'experiments/epic001b_function_inventory/scripts/categorize_function_names.py',
    )
    assert (
        run_module_main(
            categorize_module,
            [
                '--input-csv',
                str(output_dir / 'function_names_unique.csv'),
                '--manifest-xml',
                str(baseline_root / 'expected/01_manifest/manifest_with_comments.xml'),
                '--source-root',
                str(REPO_ROOT / 'juliet-test-suite-v1.3/C/testcases'),
                '--output-jsonl',
                str(output_dir / 'function_names_categorized.jsonl'),
                '--output-nested-json',
                str(output_dir / 'grouped_family_role.json'),
                '--output-summary',
                str(output_dir / 'category_summary.json'),
            ],
        )
        == 0
    )

    assert_directory_matches(
        expected_dir=baseline_root / 'expected/02b_inventory',
        actual_dir=output_dir,
        root_aliases=[(baseline_root, ''), (work_root, ''), (REPO_ROOT, '')],
    )
