from __future__ import annotations

import difflib
import importlib.util
import json
import os
import re
import shutil
import sys
import types
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPO_ROOT / 'tests' / 'golden' / 'fixtures' / 'cwe121_subset'
DEFAULT_SOURCE_RUN = REPO_ROOT / 'artifacts' / 'pipeline-runs' / 'run-2026.03.10-00:49:21'

SELECTED_TESTCASE_KEYS = [
    'CWE121_01-CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncat',
    'CWE121_01-CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_snprintf',
    'CWE121_06-CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncat',
    'CWE121_14-CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_snprintf',
    'CWE121_21-CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets',
    'CWE121_43-CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cat',
]

EXPECTED_PRIMARY_PAIR_IDS = [
    '00cbd53f9833d289',
    '066531ee1975e596',
    '0eacd5b75217911f',
    '15654d4cde74cd87',
    '5d00adb1a8bb3f92',
]

EXPECTED_PATCHED_PAIR_IDS = [
    '96287c035b801e53',
    'c569d11f7550b8ca',
    'c91162a5acaea404',
]

EXPECTED_PATCHED_SOURCE_PRIMARY_PAIR_IDS = [
    '5d00adb1a8bb3f92',
    '0eacd5b75217911f',
    '15654d4cde74cd87',
]

PATCHED_SOURCE_TESTCASE_KEYS = [
    'CWE121_01-CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_snprintf',
    'CWE121_06-CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_ncat',
    'CWE121_14-CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_snprintf',
]

STRICT_ONLY_TESTCASE_KEYS = [
    'CWE121_21-CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets',
]

VOLATILE_KEYS = {'generated_at', 'started_at', 'ended_at', 'duration_sec', 'source_files_total'}
TEXT_SUFFIXES = {'.txt', '.csv', '.c', '.cpp'}
JSON_SUFFIXES = {'.json'}

TESTCASE_KEY_RE = re.compile(r'^(CWE\d+)_([A-Za-z0-9_]+)_(\d+)([a-zA-Z]?)$')
TOKEN_RE = re.compile(
    r"""
    [A-Za-z_][A-Za-z0-9_]*
    |\d+
    |::|->|==|!=|<=|>=|\+\+|--
    |[{}()\[\];,.*+\-/<>=%&|!~?:]
    """,
    re.VERBOSE,
)


def ensure_repo_on_path() -> None:
    for path in (REPO_ROOT, REPO_ROOT / 'tools'):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


def install_typer_stub_if_needed() -> None:
    if 'typer' in sys.modules:
        return

    typer_stub = types.ModuleType('typer')

    def _parameter(default=None, *args, **kwargs):
        return default

    class BadParameter(Exception):
        pass

    class Exit(Exception):
        def __init__(self, code: int = 0):
            super().__init__(code)
            self.code = code

    def run(fn):
        return fn

    typer_stub.Argument = _parameter
    typer_stub.Option = _parameter
    typer_stub.BadParameter = BadParameter
    typer_stub.Exit = Exit
    typer_stub.run = run
    sys.modules['typer'] = typer_stub


def load_module_from_path(module_name: str, module_path: Path):
    ensure_repo_on_path()
    install_typer_stub_if_needed()

    module_path = module_path.resolve()
    search_paths = [module_path.parent, REPO_ROOT / 'tools', REPO_ROOT]
    inserted: list[str] = []
    for path in reversed(search_paths):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)
            inserted.append(path_str)

    try:
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f'Failed to load module spec for: {module_path}')

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        for path_str in inserted:
            if path_str in sys.path:
                sys.path.remove(path_str)


def run_module_main(module, argv: list[str], cwd: Path | None = None) -> int:
    old_argv = sys.argv[:]
    old_cwd = Path.cwd()
    try:
        sys.argv = [str(getattr(module, '__file__', 'script.py')), *argv]
        if cwd is not None:
            os.chdir(cwd)
        result = module.main()
        return int(result or 0)
    finally:
        sys.argv = old_argv
        os.chdir(old_cwd)


class DummyTokenizer:
    def tokenize(self, code: str) -> list[str]:
        return TOKEN_RE.findall(str(code))


def write_stub_plot(_results: list[dict[str, Any]], output_plot: Path | str) -> None:
    Path(output_plot).write_bytes(b'STUB_PNG\n')


@contextmanager
def deterministic_tokenizer_context() -> Iterator[None]:
    ensure_repo_on_path()
    import tokenize_slices

    original_load_tokenizer = tokenize_slices.load_tokenizer
    original_plot_distribution = tokenize_slices.plot_distribution
    tokenize_slices.load_tokenizer = lambda _model_name: DummyTokenizer()
    tokenize_slices.plot_distribution = write_stub_plot
    try:
        yield
    finally:
        tokenize_slices.load_tokenizer = original_load_tokenizer
        tokenize_slices.plot_distribution = original_plot_distribution


def prepare_workspace(tmp_path: Path) -> tuple[Path, Path]:
    baseline_root = tmp_path / 'baseline'
    work_root = tmp_path / 'work'
    shutil.copytree(FIXTURE_ROOT, baseline_root)
    work_root.mkdir(parents=True, exist_ok=True)
    link_repo_source_tree(baseline_root)
    return baseline_root, work_root


def link_repo_source_tree(target_root: Path) -> None:
    link_path = target_root / 'juliet-test-suite-v1.3'
    if link_path.exists():
        return
    link_path.symlink_to(REPO_ROOT / 'juliet-test-suite-v1.3', target_is_directory=True)


def derive_testcase_key_from_file_name(file_name: str) -> str | None:
    stem = Path(file_name).stem
    match = TESTCASE_KEY_RE.match(stem)
    if not match:
        return None
    cwe, body, num, _letter = match.groups()
    return f'{cwe}_{num}-{cwe}_{body}'


def _normalize_path_string(value: str, root_aliases: list[tuple[Path, str]]) -> str:
    text = str(value).replace('\\', '/')
    ordered_aliases = sorted(root_aliases, key=lambda item: len(str(item[0])), reverse=True)
    for root, alias in ordered_aliases:
        root_text = str(root.resolve()).replace('\\', '/').rstrip('/')
        alias_text = alias.strip('/')

        prefix = f'{root_text}/'
        replacement = f'{alias_text}/' if alias_text else ''
        if prefix in text:
            text = text.replace(prefix, replacement)

        if text == root_text:
            text = alias_text
            continue

        if text.startswith(prefix):
            remainder = text[len(prefix) :].lstrip('/')
            text = f'{alias_text}/{remainder}' if alias_text else remainder

    return text


def _normalize_json_value(value: Any, root_aliases: list[tuple[Path, str]]) -> Any:
    if isinstance(value, dict):
        return {
            key: _normalize_json_value(val, root_aliases)
            for key, val in sorted(value.items())
            if key not in VOLATILE_KEYS
        }
    if isinstance(value, list):
        return [_normalize_json_value(item, root_aliases) for item in value]
    if isinstance(value, str):
        return _normalize_path_string(value, root_aliases)
    return value


def _load_normalized_json(path: Path, root_aliases: list[tuple[Path, str]]) -> str:
    payload = json.loads(path.read_text(encoding='utf-8'))
    normalized = _normalize_json_value(payload, root_aliases)
    return json.dumps(normalized, ensure_ascii=False, indent=2, sort_keys=True) + '\n'


def _load_normalized_jsonl(path: Path, root_aliases: list[tuple[Path, str]]) -> str:
    records = []
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        records.append(_normalize_json_value(payload, root_aliases))
    return (
        '\n'.join(json.dumps(record, ensure_ascii=False, sort_keys=True) for record in records)
        + '\n'
    )


def _canonical_xml_repr(element: ET.Element, root_aliases: list[tuple[Path, str]]) -> Any:
    attrs = tuple(
        sorted(
            (
                key,
                _normalize_path_string(value, root_aliases) if isinstance(value, str) else value,
            )
            for key, value in element.attrib.items()
        )
    )
    text = (element.text or '').strip()
    tail = (element.tail or '').strip()
    text = _normalize_path_string(text, root_aliases) if text else ''
    tail = _normalize_path_string(tail, root_aliases) if tail else ''
    return (
        element.tag,
        attrs,
        text,
        tail,
        tuple(_canonical_xml_repr(child, root_aliases) for child in list(element)),
    )


def _load_normalized_xml(path: Path, root_aliases: list[tuple[Path, str]]) -> str:
    root = ET.parse(path).getroot()
    canonical = _canonical_xml_repr(root, root_aliases)
    return json.dumps(canonical, ensure_ascii=False, indent=2) + '\n'


def _load_normalized_text(path: Path, root_aliases: list[tuple[Path, str]]) -> str:
    text = path.read_text(encoding='utf-8', errors='replace').replace('\r\n', '\n')
    return _normalize_path_string(text, root_aliases)


def normalized_file_text(path: Path, root_aliases: list[tuple[Path, str]]) -> str:
    if path.suffix == '.json':
        return _load_normalized_json(path, root_aliases)
    if path.suffix == '.jsonl':
        return _load_normalized_jsonl(path, root_aliases)
    if path.suffix == '.xml':
        return _load_normalized_xml(path, root_aliases)
    return _load_normalized_text(path, root_aliases)


def assert_directory_matches(
    *,
    expected_dir: Path,
    actual_dir: Path,
    root_aliases: list[tuple[Path, str]],
) -> None:
    expected_files = sorted(
        p.relative_to(expected_dir) for p in expected_dir.rglob('*') if p.is_file()
    )
    actual_files = sorted(p.relative_to(actual_dir) for p in actual_dir.rglob('*') if p.is_file())
    assert actual_files == expected_files, (
        f'File set mismatch for {actual_dir}.\nExpected: {expected_files}\nActual:   {actual_files}'
    )

    for relative_path in expected_files:
        expected_path = expected_dir / relative_path
        actual_path = actual_dir / relative_path
        expected_text = normalized_file_text(expected_path, root_aliases)
        actual_text = normalized_file_text(actual_path, root_aliases)
        if expected_text != actual_text:
            diff = ''.join(
                difflib.unified_diff(
                    expected_text.splitlines(keepends=True),
                    actual_text.splitlines(keepends=True),
                    fromfile=str(expected_path),
                    tofile=str(actual_path),
                )
            )
            raise AssertionError(f'Golden mismatch for {relative_path}\n{diff}')


def sanitize_tree_in_place(root: Path, root_aliases: list[tuple[Path, str]]) -> None:
    for path in sorted(p for p in root.rglob('*') if p.is_file()):
        if path.suffix == '.json':
            payload = json.loads(path.read_text(encoding='utf-8'))
            normalized = _normalize_json_value(payload, root_aliases)
            path.write_text(
                json.dumps(normalized, ensure_ascii=False, indent=2, sort_keys=True) + '\n',
                encoding='utf-8',
            )
            continue

        if path.suffix == '.jsonl':
            rows = []
            for line in path.read_text(encoding='utf-8').splitlines():
                if not line.strip():
                    continue
                payload = json.loads(line)
                rows.append(_normalize_json_value(payload, root_aliases))
            path.write_text(
                '\n'.join(json.dumps(row, ensure_ascii=False, sort_keys=True) for row in rows)
                + '\n',
                encoding='utf-8',
            )
            continue

        if path.suffix == '.xml':
            root_elem = ET.parse(path).getroot()

            def _sanitize_xml(node: ET.Element) -> None:
                node.attrib = {
                    key: _normalize_path_string(value, root_aliases)
                    if isinstance(value, str)
                    else value
                    for key, value in node.attrib.items()
                }
                if node.text:
                    node.text = _normalize_path_string(node.text, root_aliases)
                if node.tail:
                    node.tail = _normalize_path_string(node.tail, root_aliases)
                for child in list(node):
                    _sanitize_xml(child)

            _sanitize_xml(root_elem)
            tree = ET.ElementTree(root_elem)
            try:
                ET.indent(tree, space='  ')
            except AttributeError:
                pass
            tree.write(path, encoding='utf-8', xml_declaration=True)
            continue

        if path.suffix in TEXT_SUFFIXES:
            path.write_text(normalized_file_text(path, root_aliases), encoding='utf-8')
