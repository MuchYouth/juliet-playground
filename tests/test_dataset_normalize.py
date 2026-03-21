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


def test_normalize_slice_identifiers_rewrites_user_defined_variables_and_types():
    module = load_module_from_path(
        'test_dataset_normalize_identifiers',
        REPO_ROOT / 'tools/shared/dataset_normalize.py',
    )

    normalized, placeholder_maps, replacements = module.normalize_slice_identifiers(
        '\n'.join(
            [
                'if (GLOBAL_CONST_TRUE)',
                '    recvResult = recv(connectSocket, inputBuffer, CHAR_ARRAY_SIZE - 1, 0);',
                'Widget widget(data);',
                'tempInt = helper(inputBuffer);',
                '',
            ]
        ),
        module.IdentifierInventory(
            function_names={'helper'},
            type_names={'Widget'},
            variable_names={
                'GLOBAL_CONST_TRUE',
                'recvResult',
                'connectSocket',
                'inputBuffer',
                'CHAR_ARRAY_SIZE',
                'widget',
                'data',
                'tempInt',
            },
        ),
    )

    assert 'recv(' in normalized
    assert 'FUNC_1' in normalized
    assert 'TYPE_1 VAR_6(VAR_7);' in normalized
    assert 'VAR_1' in normalized
    assert placeholder_maps['function'] == {'helper': 'FUNC_1'}
    assert placeholder_maps['type'] == {'Widget': 'TYPE_1'}
    assert replacements == 11


def test_normalize_slice_identifiers_rewrites_member_and_method_references():
    module = load_module_from_path(
        'test_dataset_normalize_member_method',
        REPO_ROOT / 'tools/shared/dataset_normalize.py',
    )

    normalized, placeholder_maps, replacements = module.normalize_slice_identifiers(
        'obj.method(data);\nreturn obj.field;\n',
        module.IdentifierInventory(
            function_names={'method'},
            variable_names={'obj', 'data', 'field'},
        ),
    )

    assert normalized == 'VAR_1.FUNC_1(VAR_2);\nreturn VAR_1.VAR_3;\n'
    assert placeholder_maps['function'] == {'method': 'FUNC_1'}
    assert placeholder_maps['variable'] == {
        'obj': 'VAR_1',
        'data': 'VAR_2',
        'field': 'VAR_3',
    }
    assert replacements == 5
