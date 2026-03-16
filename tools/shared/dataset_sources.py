from __future__ import annotations

from pathlib import Path
from typing import Any

from shared.paths import PROJECT_HOME
from shared.source_parsing import extract_function_name_from_declarator
from shared.traces import extract_std_bug_trace

CPP_LIKE_SUFFIXES = {'.cpp', '.cc', '.cxx', '.c++', '.hpp', '.hh', '.hxx'}
PROJECT_HOME_PATH = Path(PROJECT_HOME).resolve()


def normalize_artifact_path(path: Path | str) -> str:
    raw = str(path or '').strip()
    if not raw:
        return ''
    candidate = Path(raw)
    if not candidate.is_absolute():
        return str(candidate)
    resolved = candidate.resolve()
    try:
        return str(resolved.relative_to(PROJECT_HOME_PATH))
    except ValueError:
        return str(resolved)


def load_tree_sitter_parsers() -> dict[str, object]:
    try:
        from tree_sitter import Parser
        from tree_sitter_languages import get_language
    except Exception:
        return {}

    parsers: dict[str, object] = {}
    for language_name in ('c', 'cpp'):
        parser = Parser()
        lang = get_language(language_name)
        if hasattr(parser, 'set_language'):
            parser.set_language(lang)
        else:
            parser.language = lang
        parsers[language_name] = parser
    return parsers


def candidate_languages_for_source(path: Path) -> list[str]:
    suffix = path.suffix.lower()
    if suffix in CPP_LIKE_SUFFIXES:
        return ['cpp', 'c']
    return ['c', 'cpp']


def node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte : node.end_byte].decode('utf-8', errors='ignore')


def extract_defined_function_names(root_node, source_bytes: bytes) -> set[str]:
    names: set[str] = set()
    stack = [root_node]
    while stack:
        node = stack.pop()
        if node.type == 'function_definition':
            declarator = node.child_by_field_name('declarator')
            name = extract_function_name_from_declarator(declarator, source_bytes)
            if name:
                names.add(name)
        stack.extend(reversed(node.children))
    return names


def collect_defined_function_names(
    source_path: Path, parsers: dict[str, object]
) -> tuple[set[str], str | None]:
    try:
        source_bytes = source_path.read_bytes()
    except Exception as exc:
        return set(), f'read_error:{exc}'

    last_error: str | None = None
    for language_name in candidate_languages_for_source(source_path):
        parser = parsers.get(language_name)
        if parser is None:
            continue
        try:
            tree = parser.parse(source_bytes)
            return extract_defined_function_names(tree.root_node, source_bytes), None
        except Exception as exc:
            last_error = f'{language_name}:{exc}'

    if not parsers:
        return set(), 'parser_unavailable'
    return set(), last_error or 'parse_failed'


def dedupe_paths(paths: list[Path]) -> list[Path]:
    deduped: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        deduped.append(path)
        seen.add(key)
    return deduped


def build_source_file_candidates(
    signature_payload: dict[str, Any], primary_file_hint: str | None
) -> list[Path]:
    candidates: list[Path] = []

    bug_trace = extract_std_bug_trace(signature_payload.get('bug_trace', []))
    for node in bug_trace:
        filename = node.get('filename')
        if filename:
            candidates.append(Path(str(filename)))

    top_file_raw = signature_payload.get('file')
    top_file_path: Path | None = None
    if top_file_raw:
        top_file_path = Path(str(top_file_raw))
        candidates.append(top_file_path)

    if primary_file_hint:
        primary_path = Path(primary_file_hint)
        if primary_path.is_absolute():
            candidates.append(primary_path)
        else:
            basename = primary_path.name
            matches = [path for path in candidates if path.name == basename]
            if matches:
                candidates.extend(matches)
            elif top_file_path is not None:
                candidates.append(top_file_path.parent / basename)

    return dedupe_paths(candidates)


def find_slice_path(slice_dir: Path, testcase_key: str, role_name: str) -> Path | None:
    candidates = [
        slice_dir / f'slice_{testcase_key}_{role_name}.c',
        slice_dir / f'slice_{testcase_key}_{role_name}.cpp',
    ]
    existing = [path for path in candidates if path.exists()]
    if len(existing) > 1:
        raise RuntimeError(
            f'Multiple slice candidates found for {testcase_key}/{role_name}: {existing}'
        )
    return existing[0] if existing else None
