from __future__ import annotations

import csv
import json
from pathlib import Path

from tests.golden.helpers import (
    REPO_ROOT,
    load_module_from_path,
    prepare_workspace,
    run_module_main,
)

FLOW_FAMILIES = {
    'g2b_family',
    'b2g_family',
    'g2g_family',
    'b2b_family',
    'helper_family',
    'class_family',
    'misc_family',
}
OPERATION_ROLES = {'source', 'sink', 'source_sink'}
ROLE_VARIANTS_BY_ROLE = {
    'source': {'source'},
    'sink': {'direct_sink', 'va_sink', 'action_sink'},
    'source_sink': {
        'source_func_only',
        'sink_func_only',
        'both_func_included',
        'both_func_excluded',
    },
}


def _run_extract(output_dir: Path, baseline_root: Path) -> None:
    module = load_module_from_path(
        'test_stage02b_extract_contract',
        REPO_ROOT / 'experiments/epic001b_function_inventory/scripts/extract_function_inventory.py',
    )
    assert (
        run_module_main(
            module,
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


def test_stage02b_function_inventory_extract_contract(tmp_path):
    baseline_root, work_root = prepare_workspace(tmp_path)
    output_dir = work_root / 'expected/02b_inventory'

    _run_extract(output_dir, baseline_root)

    csv_path = output_dir / 'function_names_unique.csv'
    summary_path = output_dir / 'function_inventory_summary.json'
    assert csv_path.exists()
    assert summary_path.exists()

    rows = list(csv.DictReader(csv_path.open('r', encoding='utf-8', newline='')))
    assert rows
    assert csv_path.read_text(encoding='utf-8').strip()

    summary = json.loads(summary_path.read_text(encoding='utf-8'))
    assert isinstance(summary, dict)


def test_stage02b_function_inventory_categorize_contract(tmp_path):
    baseline_root, work_root = prepare_workspace(tmp_path)
    output_dir = work_root / 'expected/02b_inventory'
    _run_extract(output_dir, baseline_root)

    module = load_module_from_path(
        'test_stage02b_categorize_contract',
        REPO_ROOT / 'experiments/epic001b_function_inventory/scripts/categorize_function_names.py',
    )
    assert (
        run_module_main(
            module,
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

    input_rows = list(
        csv.DictReader((output_dir / 'function_names_unique.csv').open('r', encoding='utf-8'))
    )
    jsonl_path = output_dir / 'function_names_categorized.jsonl'
    assert jsonl_path.exists()

    records = [
        json.loads(line)
        for line in jsonl_path.read_text(encoding='utf-8').splitlines()
        if line.strip()
    ]
    assert len(records) == len(input_rows)

    for record in records:
        assert set(record) == {
            'function_name',
            'count',
            'simple_name',
            'flow_family',
            'operation_role',
            'role_variant',
        }
        assert isinstance(record['function_name'], str)
        assert record['function_name'].strip()
        assert isinstance(record['count'], int)
        assert record['count'] > 0
        assert isinstance(record['simple_name'], str)
        assert record['flow_family'] in FLOW_FAMILIES
        assert record['operation_role'] in OPERATION_ROLES
        assert record['role_variant'] in ROLE_VARIANTS_BY_ROLE[record['operation_role']]
