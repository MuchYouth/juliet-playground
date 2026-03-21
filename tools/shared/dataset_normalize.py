from __future__ import annotations

import hashlib

from shared.dataset_sources import IdentifierInventory

FUNCTION_CATEGORY = 'function'
TYPE_CATEGORY = 'type'
VARIABLE_CATEGORY = 'variable'
DEFAULT_PLACEHOLDER_PREFIXES = {
    FUNCTION_CATEGORY: 'FUNC',
    TYPE_CATEGORY: 'TYPE',
    VARIABLE_CATEGORY: 'VAR',
}
LEGACY_PLACEHOLDER_PREFIXES = {
    FUNCTION_CATEGORY: 'FUNC',
    TYPE_CATEGORY: 'FUNC',
    VARIABLE_CATEGORY: 'FUNC',
}


def lex_c_like(code: str) -> list[dict[str, str]]:
    tokens: list[dict[str, str]] = []
    i = 0
    n = len(code)

    while i < n:
        ch = code[i]

        if ch.isspace():
            j = i + 1
            while j < n and code[j].isspace():
                j += 1
            tokens.append({'kind': 'ws', 'text': code[i:j]})
            i = j
            continue

        if code.startswith('//', i):
            j = i + 2
            while j < n and code[j] != '\n':
                j += 1
            tokens.append({'kind': 'comment', 'text': code[i:j]})
            i = j
            continue

        if code.startswith('/*', i):
            j = i + 2
            while j < n - 1 and code[j : j + 2] != '*/':
                j += 1
            j = min(n, j + 2 if j < n - 1 else n)
            tokens.append({'kind': 'comment', 'text': code[i:j]})
            i = j
            continue

        if ch == '"':
            j = i + 1
            while j < n:
                if code[j] == '\\':
                    j += 2
                    continue
                if code[j] == '"':
                    j += 1
                    break
                j += 1
            tokens.append({'kind': 'string', 'text': code[i:j]})
            i = j
            continue

        if ch == "'":
            j = i + 1
            while j < n:
                if code[j] == '\\':
                    j += 2
                    continue
                if code[j] == "'":
                    j += 1
                    break
                j += 1
            tokens.append({'kind': 'char', 'text': code[i:j]})
            i = j
            continue

        if ch.isalpha() or ch == '_':
            j = i + 1
            while j < n and (code[j].isalnum() or code[j] == '_'):
                j += 1
            tokens.append({'kind': 'identifier', 'text': code[i:j]})
            i = j
            continue

        if code.startswith('->', i) or code.startswith('::', i):
            tokens.append({'kind': 'punct', 'text': code[i : i + 2]})
            i += 2
            continue

        tokens.append({'kind': 'punct', 'text': ch})
        i += 1

    return tokens


def previous_meaningful_token(tokens: list[dict[str, str]], index: int) -> dict[str, str] | None:
    for j in range(index - 1, -1, -1):
        token = tokens[j]
        if token['kind'] in {'ws', 'comment'}:
            continue
        return token
    return None


def next_meaningful_token(tokens: list[dict[str, str]], index: int) -> dict[str, str] | None:
    for j in range(index + 1, len(tokens)):
        token = tokens[j]
        if token['kind'] in {'ws', 'comment'}:
            continue
        return token
    return None


def next_meaningful_index(tokens: list[dict[str, str]], index: int) -> int | None:
    for j in range(index + 1, len(tokens)):
        token = tokens[j]
        if token['kind'] in {'ws', 'comment'}:
            continue
        return j
    return None


def matching_closing_paren_index(tokens: list[dict[str, str]], open_index: int) -> int | None:
    depth = 0
    for idx in range(open_index, len(tokens)):
        token = tokens[idx]
        if token['kind'] != 'punct':
            continue
        if token['text'] == '(':
            depth += 1
            continue
        if token['text'] != ')':
            continue
        depth -= 1
        if depth == 0:
            return idx
    return None


def replace_identifier_with_placeholder(
    tokens: list[dict[str, str]],
    index: int,
    *,
    category: str,
    placeholder_maps: dict[str, dict[str, str]],
    placeholder_prefixes: dict[str, str],
) -> int:
    name = tokens[index]['text']
    placeholder_map = placeholder_maps[category]
    placeholder = placeholder_map.get(name)
    if placeholder is None:
        placeholder = f'{placeholder_prefixes[category]}_{len(placeholder_map) + 1}'
        placeholder_map[name] = placeholder
    if tokens[index]['text'] == placeholder:
        return 0
    tokens[index]['text'] = placeholder
    return 1


def is_function_call_context(tokens: list[dict[str, str]], index: int) -> bool:
    next_token = next_meaningful_token(tokens, index)
    return next_token is not None and next_token['text'] == '('


def _is_declaration_type_context(tokens: list[dict[str, str]], index: int) -> bool:
    prev_token = previous_meaningful_token(tokens, index)
    if prev_token is not None and prev_token['text'] in {'.', '->'}:
        return False
    if prev_token is not None and prev_token['text'] in {'class', 'struct', 'union', 'enum'}:
        return True

    next_index = next_meaningful_index(tokens, index)
    if next_index is None:
        return False

    while next_index is not None and tokens[next_index]['text'] in {'*', '&'}:
        next_index = next_meaningful_index(tokens, next_index)
    if next_index is None or tokens[next_index]['kind'] != 'identifier':
        return False

    after_identifier_index = next_meaningful_index(tokens, next_index)
    if after_identifier_index is None:
        return False
    return tokens[after_identifier_index]['text'] in {';', '=', ',', ')', '(', '['}


def is_type_context(
    tokens: list[dict[str, str]],
    index: int,
) -> bool:
    prev_token = previous_meaningful_token(tokens, index)
    if prev_token is not None and prev_token['text'] == 'new':
        return is_function_call_context(tokens, index)
    return _is_declaration_type_context(tokens, index)


def new_placeholder_maps() -> dict[str, dict[str, str]]:
    return {
        FUNCTION_CATEGORY: {},
        TYPE_CATEGORY: {},
        VARIABLE_CATEGORY: {},
    }


def flatten_placeholder_maps(placeholder_maps: dict[str, dict[str, str]]) -> dict[str, str]:
    flattened: dict[str, str] = {}
    for category in (FUNCTION_CATEGORY, TYPE_CATEGORY, VARIABLE_CATEGORY):
        flattened.update(placeholder_maps[category])
    return flattened


def normalize_slice_identifiers(
    code: str,
    identifier_inventory: IdentifierInventory,
    *,
    placeholder_prefixes: dict[str, str] | None = None,
) -> tuple[str, dict[str, dict[str, str]], int]:
    if identifier_inventory.is_empty():
        return code, new_placeholder_maps(), 0

    tokens = lex_c_like(code)
    placeholder_maps = new_placeholder_maps()
    selected_prefixes = dict(DEFAULT_PLACEHOLDER_PREFIXES)
    if placeholder_prefixes is not None:
        selected_prefixes.update(placeholder_prefixes)
    replacements = 0

    for idx, token in enumerate(tokens):
        if token['kind'] != 'identifier':
            continue
        name = token['text']
        if name in identifier_inventory.function_names and is_function_call_context(tokens, idx):
            replacements += replace_identifier_with_placeholder(
                tokens,
                idx,
                category=FUNCTION_CATEGORY,
                placeholder_maps=placeholder_maps,
                placeholder_prefixes=selected_prefixes,
            )
            continue

        if name in identifier_inventory.type_names and is_type_context(tokens, idx):
            replacements += replace_identifier_with_placeholder(
                tokens,
                idx,
                category=TYPE_CATEGORY,
                placeholder_maps=placeholder_maps,
                placeholder_prefixes=selected_prefixes,
            )
            continue

        if name in identifier_inventory.variable_names:
            replacements += replace_identifier_with_placeholder(
                tokens,
                idx,
                category=VARIABLE_CATEGORY,
                placeholder_maps=placeholder_maps,
                placeholder_prefixes=selected_prefixes,
            )

    return ''.join(token['text'] for token in tokens), placeholder_maps, replacements


def normalize_slice_function_names(
    code: str, user_defined_function_names: set[str]
) -> tuple[str, dict[str, str], int]:
    if not user_defined_function_names:
        return code, {}, 0

    normalized_code, placeholder_maps, replacements = normalize_slice_identifiers(
        code,
        IdentifierInventory(
            function_names=set(user_defined_function_names),
            type_names=set(user_defined_function_names),
        ),
        placeholder_prefixes=LEGACY_PLACEHOLDER_PREFIXES,
    )
    return normalized_code, flatten_placeholder_maps(placeholder_maps), replacements


def compact_code_for_hash(code: str) -> str:
    return ''.join(str(code).split())


def normalized_code_md5(code: str) -> str:
    return hashlib.md5(compact_code_for_hash(code).encode('utf-8')).hexdigest()
