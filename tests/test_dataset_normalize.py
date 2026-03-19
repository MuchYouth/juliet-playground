from __future__ import annotations

from tests.helpers import REPO_ROOT, load_module_from_path


def test_normalize_slice_function_names_rewrites_stack_constructor_type_name():
    module = load_module_from_path(
        'test_dataset_normalize_stack_ctor',
        REPO_ROOT / 'tools/shared/dataset_normalize.py',
    )

    normalized, placeholder_map, replacements = module.normalize_slice_function_names(
        '    Widget widget(data);\n',
        {'Widget'},
    )

    assert normalized == '    FUNC_1 widget(data);\n'
    assert placeholder_map == {'Widget': 'FUNC_1'}
    assert replacements == 1


def test_normalize_slice_function_names_rewrites_heap_constructor_type_names_consistently():
    module = load_module_from_path(
        'test_dataset_normalize_heap_ctor',
        REPO_ROOT / 'tools/shared/dataset_normalize.py',
    )

    normalized, placeholder_map, replacements = module.normalize_slice_function_names(
        '    Widget * widget = new Widget(data);\n',
        {'Widget'},
    )

    assert normalized == '    FUNC_1 * widget = new FUNC_1(data);\n'
    assert placeholder_map == {'Widget': 'FUNC_1'}
    assert replacements == 2


def test_normalize_slice_function_names_keeps_external_apis_untouched():
    module = load_module_from_path(
        'test_dataset_normalize_external_api',
        REPO_ROOT / 'tools/shared/dataset_normalize.py',
    )

    normalized, placeholder_map, replacements = module.normalize_slice_function_names(
        '    system(data);\n    Widget widget(data);\n',
        {'Widget'},
    )

    assert normalized == '    system(data);\n    FUNC_1 widget(data);\n'
    assert placeholder_map == {'Widget': 'FUNC_1'}
    assert replacements == 1
