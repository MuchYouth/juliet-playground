from __future__ import annotations

import xml.etree.ElementTree as ET

from tests.golden.helpers import (
    REPO_ROOT,
    load_module_from_path,
    prepare_workspace,
    run_module_main,
)


def test_stage01_manifest_scan_contract(tmp_path):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_stage01_manifest_scan_contract',
        REPO_ROOT / 'experiments/epic001_manifest_comment_scan/scripts/scan_manifest_comments.py',
    )

    input_xml = baseline_root / 'seed/manifest_subset.xml'
    output_xml = work_root / 'expected/01_manifest/manifest_with_comments.xml'
    output_xml.parent.mkdir(parents=True, exist_ok=True)

    assert (
        run_module_main(
            module,
            [
                '--manifest',
                str(input_xml),
                '--source-root',
                str(REPO_ROOT / 'juliet-test-suite-v1.3/C'),
                '--output-xml',
                str(output_xml),
            ],
        )
        == 0
    )

    assert output_xml.exists()

    input_root = ET.parse(input_xml).getroot()
    output_root = ET.parse(output_xml).getroot()

    assert len(input_root.findall('testcase')) == len(output_root.findall('testcase'))

    input_files = [file_elem.attrib.get('path', '') for file_elem in input_root.iter('file')]
    output_files = [file_elem.attrib.get('path', '') for file_elem in output_root.iter('file')]
    assert output_files == input_files

    input_flaws = [
        (file_elem.attrib.get('path', ''), child.attrib.get('line', ''))
        for file_elem in input_root.iter('file')
        for child in list(file_elem)
        if child.tag == 'flaw'
    ]
    output_flaws = [
        (file_elem.attrib.get('path', ''), child.attrib.get('line', ''))
        for file_elem in output_root.iter('file')
        for child in list(file_elem)
        if child.tag == 'flaw'
    ]
    assert output_flaws == input_flaws

    comment_tag_count = 0
    for file_elem in output_root.iter('file'):
        for child in list(file_elem):
            if not child.tag.startswith('comment_'):
                continue
            comment_tag_count += 1
            assert child.tag in {'comment_flaw', 'comment_fix'}
            assert set(child.attrib) == {'line', 'code', 'function'}
            assert int(child.attrib['line']) > 0
            assert child.attrib['code'].strip()
            assert child.attrib['function'].strip()

    assert comment_tag_count > 0
