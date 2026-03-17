from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from tests.helpers import REPO_ROOT, load_module_from_path, write_text


def test_add_flow_tags_normalizes_tags_unifies_function_and_dedups_manifest_flaw(tmp_path):
    module = load_module_from_path(
        'test_stage02b_flow_partition_normalization',
        REPO_ROOT / 'tools/stage/stage02b_flow.py',
    )

    input_xml = tmp_path / 'manifest_with_comments.xml'
    output_xml = tmp_path / 'manifest_with_testcase_flows.xml'
    summary_json = tmp_path / 'summary.json'
    write_text(
        input_xml,
        """<?xml version='1.0' encoding='utf-8'?>
<container>
  <testcase>
    <file path="sample.c">
      <flaw line="10" name="CWE-X: synthetic flaw" />
      <comment_flaw line="10" function="bad" code="bad_stmt();" />
      <comment_fix line="20" function="goodG2B" code="fixed_stmt();" />
      <comment_flaw line="20" function="goodG2B" code="same_line_flaw_stmt();" />
    </file>
  </testcase>
</container>
""",
    )

    module.add_flow_tags_to_testcase(
        input_xml=input_xml,
        output_xml=output_xml,
        summary_json=summary_json,
    )

    root = ET.parse(output_xml).getroot()
    testcase = root.find('testcase')
    assert testcase is not None
    flows = {flow.attrib['type']: list(flow) for flow in testcase.findall('flow')}

    b2b_items = flows['b2b']
    assert len(b2b_items) == 1
    b2b_item = b2b_items[0]
    assert b2b_item.tag == 'flaw'
    assert b2b_item.attrib['origin'] == 'manifest_flaw'
    assert b2b_item.attrib['function'] == 'bad'
    assert b2b_item.attrib['name'] == 'CWE-X: synthetic flaw'
    assert 'inferred_function' not in b2b_item.attrib

    g2b_items = {
        (item.tag, item.attrib['origin'], item.attrib['function']) for item in flows['g2b']
    }
    assert g2b_items == {
        ('fix', 'comment_fix', 'goodG2B'),
        ('flaw', 'comment_flaw', 'goodG2B'),
    }

    summary = json.loads(summary_json.read_text(encoding='utf-8'))
    assert summary['tag_counts_in_flows'] == {'flaw': 2, 'fix': 1}
    assert summary['dedup_removed_comment_flaw_records'] == 1
