from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from shared.source_parsing import PARSER_LANG_BY_SUFFIX, node_first_line_text


@dataclass
class FileContext:
    source_bytes: bytes
    source_lines: list[str]
    line_nodes: dict[int, list[object]]


@dataclass(frozen=True)
class CallArgument:
    position: int
    text: str

    def to_dict(self) -> dict[str, int | str]:
        return {'position': self.position, 'text': self.text}


@dataclass(frozen=True)
class CallSite:
    raw_function_name: str
    argc: int
    call_text: str
    lhs_text: str
    arguments: list[CallArgument]

    def to_candidate_entry(self) -> dict[str, int | str]:
        return {'name': self.raw_function_name, 'argc': self.argc}

    def to_dict(self) -> dict[str, object]:
        return {
            'raw_function_name': self.raw_function_name,
            'argc': self.argc,
            'call_text': self.call_text,
            'lhs_text': self.lhs_text,
            'arguments': [argument.to_dict() for argument in self.arguments],
        }


def _node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte : node.end_byte].decode('utf-8', errors='ignore').strip()


def _build_line_nodes(root_node) -> dict[int, list[object]]:
    line_nodes: dict[int, list[object]] = {}
    stack = [root_node]
    while stack:
        node = stack.pop()
        if node.is_named:
            line = node.start_point[0] + 1
            line_nodes.setdefault(line, []).append(node)
        stack.extend(reversed(node.children))
    return line_nodes


def choose_line_node(*, ctx: FileContext, line_no: int, target_text: str | None) -> object | None:
    candidates = ctx.line_nodes.get(line_no, [])
    if not candidates:
        return None

    if target_text is not None:
        matched = [
            node
            for node in candidates
            if node_first_line_text(node, ctx.source_bytes) == target_text
        ]
        if matched:
            return min(matched, key=lambda node: node.end_byte - node.start_byte)

    return min(candidates, key=lambda node: node.end_byte - node.start_byte)


def _should_skip_call(raw_function_name: str) -> bool:
    lowered = raw_function_name.lower()
    return (
        'g2b' in lowered
        or 'b2b' in lowered
        or 'bad' in lowered
        or lowered.startswith('global')
        or lowered.startswith('helper')
    )


def _extract_arguments(args_node, source_bytes: bytes) -> list[CallArgument]:
    if args_node is None:
        return []
    return [
        CallArgument(position=index, text=_node_text(argument, source_bytes))
        for index, argument in enumerate(args_node.named_children, start=1)
    ]


def _extract_lhs_text(call_node, source_bytes: bytes) -> str:
    parent = getattr(call_node, 'parent', None)
    while parent is not None:
        if parent.type == 'assignment_expression':
            left_node = parent.child_by_field_name('left')
            if left_node is not None:
                return _node_text(left_node, source_bytes)
        if parent.type == 'init_declarator':
            declarator = parent.child_by_field_name('declarator')
            if declarator is not None:
                return _node_text(declarator, source_bytes)
        parent = getattr(parent, 'parent', None)
    return ''


def _extract_calls_from_node(
    node,
    *,
    source_bytes: bytes,
    target_line: int,
    dedupe_by_signature: bool,
) -> list[CallSite]:
    calls: list[CallSite] = []
    seen: set[tuple[str, int]] = set()
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == 'call_expression' and (current.start_point[0] + 1) == target_line:
            function_node = current.child_by_field_name('function')
            args_node = current.child_by_field_name('arguments')
            raw_function_name = (
                _node_text(function_node, source_bytes) if function_node is not None else ''
            )
            if _should_skip_call(raw_function_name):
                stack.extend(reversed(current.children))
                continue

            arguments = _extract_arguments(args_node, source_bytes)
            argc = len(arguments)
            signature = (raw_function_name, argc)
            if not dedupe_by_signature or signature not in seen:
                if dedupe_by_signature:
                    seen.add(signature)
                calls.append(
                    CallSite(
                        raw_function_name=raw_function_name,
                        argc=argc,
                        call_text=_node_text(current, source_bytes),
                        lhs_text=_extract_lhs_text(current, source_bytes),
                        arguments=arguments,
                    )
                )
        stack.extend(reversed(current.children))
    return calls


def extract_call_sites_for_line(
    *,
    ctx: FileContext,
    line_no: int,
    target_text: str | None = None,
    dedupe_by_signature: bool = True,
) -> list[CallSite]:
    chosen = choose_line_node(ctx=ctx, line_no=line_no, target_text=target_text)
    if chosen is None:
        return []
    return _extract_calls_from_node(
        chosen,
        source_bytes=ctx.source_bytes,
        target_line=line_no,
        dedupe_by_signature=dedupe_by_signature,
    )


def load_file_context(src: Path, parsers: dict[str, object]) -> FileContext:
    content = src.read_text(encoding='utf-8', errors='ignore')
    source_bytes = content.encode('utf-8', errors='ignore')
    source_lines = content.splitlines()
    line_nodes: dict[int, list[object]] = {}

    language_name = PARSER_LANG_BY_SUFFIX.get(src.suffix.lower())
    parser = parsers.get(language_name) if language_name else None
    if parser is not None:
        try:
            tree = parser.parse(source_bytes)
            line_nodes = _build_line_nodes(tree.root_node)
        except Exception:
            line_nodes = {}

    return FileContext(source_bytes=source_bytes, source_lines=source_lines, line_nodes=line_nodes)
