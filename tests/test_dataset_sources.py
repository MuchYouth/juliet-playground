from __future__ import annotations

from tests.helpers import REPO_ROOT, load_module_from_path, write_text


def test_constructor_alias_for_function_name_handles_ctor_and_dtor_names():
    module = load_module_from_path(
        'test_dataset_sources_constructor_alias',
        REPO_ROOT / 'tools/shared/dataset_sources.py',
    )

    assert module.constructor_alias_for_function_name('Widget::Widget') == 'Widget'
    assert module.constructor_alias_for_function_name('Widget::~Widget') == 'Widget'
    assert module.constructor_alias_for_function_name('ns::Widget::Widget') == 'Widget'
    assert module.constructor_alias_for_function_name('ns::Widget::~Widget') == 'Widget'
    assert module.constructor_alias_for_function_name('Widget::run') is None
    assert module.constructor_alias_for_function_name('run') is None


def test_expand_source_candidates_for_identifier_inventory_includes_group_sources_and_headers(
    tmp_path,
):
    module = load_module_from_path(
        'test_dataset_sources_expand_candidates',
        REPO_ROOT / 'tools/shared/dataset_sources.py',
    )

    testcase_dir = tmp_path / 'CWE134_Uncontrolled_Format_String' / 's01'
    source_path = testcase_dir / 'CWE134_Uncontrolled_Format_String__char_console_printf_83a.cpp'
    write_text(source_path, 'int main(void) { return 0; }\n')
    write_text(
        testcase_dir / 'CWE134_Uncontrolled_Format_String__char_console_printf_83_bad.cpp',
        'int bad(void) { return 1; }\n',
    )
    write_text(
        testcase_dir / 'CWE134_Uncontrolled_Format_String__char_console_printf_83_goodG2B.cpp',
        'int goodG2B(void) { return 0; }\n',
    )
    write_text(
        testcase_dir / 'CWE134_Uncontrolled_Format_String__char_console_printf_83.h',
        'class Widget {};\n',
    )
    write_text(testcase_dir / 'unrelated_helper.cpp', 'int helper(void) { return 0; }\n')

    expanded = module.expand_source_candidates_for_identifier_inventory([source_path])

    assert [path.name for path in expanded] == [
        'CWE134_Uncontrolled_Format_String__char_console_printf_83a.cpp',
        'CWE134_Uncontrolled_Format_String__char_console_printf_83.h',
        'CWE134_Uncontrolled_Format_String__char_console_printf_83_bad.cpp',
        'CWE134_Uncontrolled_Format_String__char_console_printf_83_goodG2B.cpp',
    ]


def test_collect_identifier_inventory_gathers_functions_types_and_variables(tmp_path):
    module = load_module_from_path(
        'test_dataset_sources_collect_inventory',
        REPO_ROOT / 'tools/shared/dataset_sources.py',
    )

    source_path = tmp_path / 'sample.cpp'
    write_text(
        source_path,
        '\n'.join(
            [
                'class Widget {',
                'public:',
                '    Widget(char * dataCopy);',
                '    ~Widget();',
                'private:',
                '    char * data;',
                '};',
                'static const int GLOBAL_CONST_TRUE = 1;',
                'int helper(int inputBuffer) {',
                '    int tempInt = atoi(inputBuffer);',
                '    return tempInt;',
                '}',
                '',
            ]
        ),
    )

    parsers = module.load_tree_sitter_parsers()
    inventory, error = module.collect_identifier_inventory(source_path, parsers)

    assert error is None
    assert {'helper'} <= inventory.function_names
    assert {'Widget'} <= inventory.type_names
    assert {'GLOBAL_CONST_TRUE', 'inputBuffer', 'tempInt', 'dataCopy', 'data'} <= (
        inventory.variable_names
    )
