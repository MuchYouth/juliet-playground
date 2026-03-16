from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from tests.golden.helpers import (
    REPO_ROOT,
    load_module_from_path,
    prepare_workspace,
    run_module_main,
)


def test_stage02c_flow_partition_contract(tmp_path):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_stage02c_flow_partition_contract',
        REPO_ROOT
        / 'experiments/epic001c_testcase_flow_partition/scripts/add_flow_tags_to_testcase.py',
    )

    output_dir = work_root / 'expected/02c_flow'
    output_xml = output_dir / 'manifest_with_testcase_flows.xml'
    summary_path = output_dir / 'summary.json'
    assert (
        run_module_main(
            module,
            [
                '--input-xml',
                str(baseline_root / 'expected/01_manifest/manifest_with_comments.xml'),
                '--function-categories-jsonl',
                str(baseline_root / 'expected/02b_inventory/function_names_categorized.jsonl'),
                '--output-xml',
                str(output_xml),
                '--summary-json',
                str(summary_path),
            ],
        )
        == 0
    )

    assert output_xml.exists()
    assert summary_path.exists()

    root = ET.parse(output_xml).getroot()
    flow_count = 0
    for testcase in root.findall('testcase'):
        for flow in testcase.findall('flow'):
            flow_count += 1
            assert flow.attrib.get('type', '').strip()
            for item in list(flow):
                assert item.tag in {'comment_flaw', 'comment_fix', 'flaw'}
                assert item.attrib.get('file', '').strip()
                assert int(item.attrib.get('line', '0') or 0) > 0
                if item.tag in {'comment_flaw', 'comment_fix'}:
                    assert item.attrib.get('function', '').strip()
                else:
                    assert item.attrib.get('inferred_function', '').strip()

    assert flow_count > 0

    summary = json.loads(summary_path.read_text(encoding='utf-8'))
    assert summary['testcases'] == len(root.findall('testcase'))
    assert isinstance(summary['flow_tag_item_counts'], dict)
    assert isinstance(summary['tag_counts_in_flows'], dict)
    assert 'unresolved_comment_records' in summary
    assert 'unresolved_flaw_records' in summary
