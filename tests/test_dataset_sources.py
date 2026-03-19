from __future__ import annotations

from tests.helpers import REPO_ROOT, load_module_from_path


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
