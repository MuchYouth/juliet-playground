from __future__ import annotations

from shared.juliet_keys import (
    JULIET_GROUP_HEADER_SUFFIXES,
    JULIET_GROUP_INVENTORY_SUFFIXES,
    JULIET_GROUP_SOURCE_SUFFIXES,
    list_juliet_case_group_files,
    parse_juliet_case_identity,
)


def test_parse_juliet_case_identity_accepts_grouped_source_and_header_names():
    identity = parse_juliet_case_identity(
        '/tmp/CWE78_OS_Command_Injection__char_console_execlp_52a.c',
        allowed_suffixes=JULIET_GROUP_SOURCE_SUFFIXES,
    )
    assert identity == ('/tmp', '78', 'OS_Command_Injection', 'char_console_execlp', '52')

    header_identity = parse_juliet_case_identity(
        '/tmp/CWE134_Uncontrolled_Format_String__char_console_printf_83.h',
        allowed_suffixes=JULIET_GROUP_INVENTORY_SUFFIXES,
    )
    assert header_identity == (
        '/tmp',
        '134',
        'Uncontrolled_Format_String',
        'char_console_printf',
        '83',
    )


def test_list_juliet_case_group_files_filters_by_requested_suffixes(tmp_path):
    testcase_dir = tmp_path / 'CWE134_Uncontrolled_Format_String' / 's01'
    testcase_dir.mkdir(parents=True)
    for name in (
        'CWE134_Uncontrolled_Format_String__char_console_printf_83a.cpp',
        'CWE134_Uncontrolled_Format_String__char_console_printf_83_bad.cpp',
        'CWE134_Uncontrolled_Format_String__char_console_printf_83_goodG2B.cpp',
        'CWE134_Uncontrolled_Format_String__char_console_printf_83.h',
    ):
        (testcase_dir / name).write_text('\n', encoding='utf-8')

    source_files = list_juliet_case_group_files(
        testcase_dir / 'CWE134_Uncontrolled_Format_String__char_console_printf_83a.cpp',
        allowed_suffixes=JULIET_GROUP_SOURCE_SUFFIXES,
    )
    header_files = list_juliet_case_group_files(
        testcase_dir / 'CWE134_Uncontrolled_Format_String__char_console_printf_83a.cpp',
        allowed_suffixes=JULIET_GROUP_HEADER_SUFFIXES,
    )

    assert [path.name for path in source_files] == [
        'CWE134_Uncontrolled_Format_String__char_console_printf_83_bad.cpp',
        'CWE134_Uncontrolled_Format_String__char_console_printf_83_goodG2B.cpp',
        'CWE134_Uncontrolled_Format_String__char_console_printf_83a.cpp',
    ]
    assert [path.name for path in header_files] == [
        'CWE134_Uncontrolled_Format_String__char_console_printf_83.h',
    ]
