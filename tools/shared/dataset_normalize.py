from __future__ import annotations

import hashlib


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
    placeholder_map: dict[str, str],
) -> int:
    name = tokens[index]['text']
    placeholder = placeholder_map.get(name)
    if placeholder is None:
        placeholder = f'FUNC_{len(placeholder_map) + 1}'
        placeholder_map[name] = placeholder
    if tokens[index]['text'] == placeholder:
        return 0
    tokens[index]['text'] = placeholder
    return 1


def is_constructor_type_context(
    tokens: list[dict[str, str]],
    index: int,
) -> bool:
    prev_token = previous_meaningful_token(tokens, index)
    if prev_token is not None and prev_token['text'] in {'.', '->', '::'}:
        return False

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

    after_identifier = tokens[after_identifier_index]
    if after_identifier['text'] == '(':
        close_index = matching_closing_paren_index(tokens, after_identifier_index)
        if close_index is None:
            return False
        terminator_index = next_meaningful_index(tokens, close_index)
        if terminator_index is None:
            return False
        return tokens[terminator_index]['text'] == ';'

    if after_identifier['text'] != '=':
        return False

    new_index = next_meaningful_index(tokens, after_identifier_index)
    if new_index is None or tokens[new_index]['text'] != 'new':
        return False

    allocated_type_index = next_meaningful_index(tokens, new_index)
    if allocated_type_index is None or tokens[allocated_type_index]['kind'] != 'identifier':
        return False
    if tokens[allocated_type_index]['text'] != tokens[index]['text']:
        return False

    open_index = next_meaningful_index(tokens, allocated_type_index)
    if open_index is None or tokens[open_index]['text'] != '(':
        return False

    close_index = matching_closing_paren_index(tokens, open_index)
    if close_index is None:
        return False
    terminator_index = next_meaningful_index(tokens, close_index)
    if terminator_index is None:
        return False
    return tokens[terminator_index]['text'] == ';'


def normalize_slice_function_names(
    code: str, user_defined_function_names: set[str]
) -> tuple[str, dict[str, str], int]:
    if not user_defined_function_names:
        return code, {}, 0

    tokens = lex_c_like(code)
    placeholder_map: dict[str, str] = {}
    replacements = 0

    for idx, token in enumerate(tokens):
        if token['kind'] != 'identifier':
            continue
        name = token['text']
        if name not in user_defined_function_names:
            continue

        prev_token = previous_meaningful_token(tokens, idx)
        next_token = next_meaningful_token(tokens, idx)

        if next_token is not None and next_token['text'] == '(':
            if prev_token is not None and prev_token['text'] in {'.', '->', '::'}:
                continue
            replacements += replace_identifier_with_placeholder(tokens, idx, placeholder_map)
            continue

        if is_constructor_type_context(tokens, idx):
            replacements += replace_identifier_with_placeholder(tokens, idx, placeholder_map)

    return ''.join(token['text'] for token in tokens), placeholder_map, replacements


def compact_code_for_hash(code: str) -> str:
    return ''.join(str(code).split())


def normalized_code_md5(code: str) -> str:
    return hashlib.md5(compact_code_for_hash(code).encode('utf-8')).hexdigest()
