from __future__ import annotations

import textwrap
from pathlib import Path

from shared.juliet_manifest import build_manifest_source_index


def _write(path: Path, content: str = '') -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')


def test_build_manifest_source_index_resolves_manifest_files_from_c_root(tmp_path):
    source_root = tmp_path / 'juliet-test-suite-v1.3' / 'C'
    testcases_root = source_root / 'testcases'
    manifest_xml = tmp_path / 'manifest.xml'

    _write(
        testcases_root
        / 'CWE121_Stack_Based_Buffer_Overflow'
        / 's01'
        / 'CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_21.c'
    )
    _write(
        testcases_root
        / 'CWE121_Stack_Based_Buffer_Overflow'
        / 's08'
        / 'CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cat_43.cpp'
    )
    _write(
        testcases_root
        / 'CWE190_Integer_Overflow'
        / 's01'
        / 'CWE190_Integer_Overflow__char_rand_multiply_68a.c'
    )
    _write(
        testcases_root / 'CWE190_Integer_Overflow' / 's01' / 'unrelated_helper.c',
        'int helper(void) { return 0; }\n',
    )
    manifest_xml.write_text(
        textwrap.dedent(
            """\
            <?xml version="1.0" encoding="utf-8"?>
            <container>
              <testcase>
                <file path="CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_21.c" />
              </testcase>
              <testcase>
                <file path="CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cat_43.cpp" />
              </testcase>
              <testcase>
                <file path="CWE190_Integer_Overflow__char_rand_multiply_68a.c" />
              </testcase>
              <testcase>
                <file path="CWE190_Integer_Overflow__missing_01.c" />
              </testcase>
            </container>
            """
        ),
        encoding='utf-8',
    )

    source_index = build_manifest_source_index(
        manifest_xml=manifest_xml,
        source_root=source_root,
        suffixes={'.c', '.cpp', '.h'},
    )

    assert sorted(source_index) == [
        'CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_21.c',
        'CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cat_43.cpp',
        'CWE190_Integer_Overflow__char_rand_multiply_68a.c',
    ]
    assert source_index['CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_21.c'] == (
        testcases_root
        / 'CWE121_Stack_Based_Buffer_Overflow'
        / 's01'
        / 'CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_21.c'
    )
    assert source_index['CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cat_43.cpp'] == (
        testcases_root
        / 'CWE121_Stack_Based_Buffer_Overflow'
        / 's08'
        / 'CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cat_43.cpp'
    )
    assert source_index['CWE190_Integer_Overflow__char_rand_multiply_68a.c'] == (
        testcases_root
        / 'CWE190_Integer_Overflow'
        / 's01'
        / 'CWE190_Integer_Overflow__char_rand_multiply_68a.c'
    )
    assert 'CWE190_Integer_Overflow__missing_01.c' not in source_index


def test_build_manifest_source_index_accepts_testcases_root(tmp_path):
    testcases_root = tmp_path / 'testcases'
    manifest_xml = tmp_path / 'manifest.xml'

    _write(
        testcases_root
        / 'CWE369_Divide_by_Zero'
        / 's02'
        / 'CWE369_Divide_by_Zero__float_zero_divide_53d.c'
    )
    _write(
        testcases_root
        / 'CWE369_Divide_by_Zero'
        / 's02'
        / 'CWE369_Divide_by_Zero__float_zero_divide_84.h'
    )
    manifest_xml.write_text(
        textwrap.dedent(
            """\
            <?xml version="1.0" encoding="utf-8"?>
            <container>
              <testcase>
                <file path="CWE369_Divide_by_Zero__float_zero_divide_53d.c" />
                <file path="CWE369_Divide_by_Zero__float_zero_divide_84.h" />
              </testcase>
            </container>
            """
        ),
        encoding='utf-8',
    )

    source_index = build_manifest_source_index(
        manifest_xml=manifest_xml,
        source_root=testcases_root,
        suffixes={'.c', '.cpp', '.h'},
    )

    assert sorted(source_index) == [
        'CWE369_Divide_by_Zero__float_zero_divide_53d.c',
        'CWE369_Divide_by_Zero__float_zero_divide_84.h',
    ]
    assert source_index['CWE369_Divide_by_Zero__float_zero_divide_53d.c'] == (
        testcases_root
        / 'CWE369_Divide_by_Zero'
        / 's02'
        / 'CWE369_Divide_by_Zero__float_zero_divide_53d.c'
    )
    assert source_index['CWE369_Divide_by_Zero__float_zero_divide_84.h'] == (
        testcases_root
        / 'CWE369_Divide_by_Zero'
        / 's02'
        / 'CWE369_Divide_by_Zero__float_zero_divide_84.h'
    )
