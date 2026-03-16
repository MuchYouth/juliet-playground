from __future__ import annotations

from tests.helpers import REPO_ROOT, load_module_from_path


class DummyNode:
    def __init__(
        self,
        *,
        node_type: str,
        start_byte: int = 0,
        end_byte: int = 0,
        children: list['DummyNode'] | None = None,
        fields: dict[str, 'DummyNode'] | None = None,
    ):
        self.type = node_type
        self.start_byte = start_byte
        self.end_byte = end_byte
        self.children = children or []
        self._fields = fields or {}

    def child_by_field_name(self, name: str):
        return self._fields.get(name)


def test_node_first_line_text_and_function_name_extraction():
    module = load_module_from_path(
        'test_source_parsing_module',
        REPO_ROOT / 'tools/shared/source_parsing.py',
    )

    source_bytes = b'int demo(void)\\n{\\n  return 0;\\n}\\nA::method'
    line_node = DummyNode(node_type='declaration', start_byte=0, end_byte=14)
    method_start = source_bytes.index(b'A::method')
    qualified = DummyNode(
        node_type='qualified_identifier',
        start_byte=method_start,
        end_byte=method_start + len(b'A::method'),
    )
    nested = DummyNode(
        node_type='function_declarator',
        fields={'declarator': qualified},
    )

    assert module.node_first_line_text(line_node, source_bytes) == 'int demo(void)'
    assert module.extract_function_name_from_declarator(nested, source_bytes) == 'A::method'


def test_extract_function_name_from_declarator_falls_back_to_name_field():
    module = load_module_from_path(
        'test_source_parsing_name_field_module',
        REPO_ROOT / 'tools/shared/source_parsing.py',
    )

    source_bytes = b'wrapper target'
    name_node = DummyNode(node_type='identifier', start_byte=8, end_byte=14)
    declarator = DummyNode(node_type='pointer_declarator', fields={'name': name_node})

    assert module.extract_function_name_from_declarator(declarator, source_bytes) == 'target'
