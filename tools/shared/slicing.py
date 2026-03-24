from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

CPP_SUFFIXES = {'.cpp', '.cc', '.cxx', '.c++'}


def rewrite_prefixed_path(
    original_path: str,
    *,
    old_prefix: str | None = None,
    new_prefix: str | None = None,
) -> str:
    if old_prefix and new_prefix and original_path.startswith(old_prefix):
        return original_path.replace(old_prefix, new_prefix, 1)
    return original_path


def read_source_line(filepath: Path, line_number: int) -> str | None:
    try:
        with filepath.open('r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return None
    except Exception:
        return None

    if 1 <= line_number <= len(lines):
        return lines[line_number - 1]
    return None


def classify_suffix(path_like: str | None) -> str | None:
    if not path_like:
        return None
    suffix = Path(path_like).suffix.lower()
    if suffix == '.c':
        return '.c'
    if suffix in CPP_SUFFIXES:
        return '.cpp'
    return None


def guess_output_suffix(
    data: dict[str, Any],
    std_bug_trace: list[dict[str, Any]],
    *,
    extra_candidates: Iterable[str | None] = (),
) -> str:
    candidates: list[str | None] = [data.get('file'), *extra_candidates]
    for node in std_bug_trace:
        candidates.append(node.get('filename'))
    for candidate in candidates:
        suffix = classify_suffix(candidate)
        if suffix:
            return suffix
    return '.c'


def build_slice(
    std_bug_trace: list[dict[str, Any]],
    *,
    old_prefix: str | None = None,
    new_prefix: str | None = None,
) -> tuple[str | None, str | None]:
    slice_lines: list[str] = []
    seen: set[tuple[str, int]] = set()

    for node in std_bug_trace:
        filename = node.get('filename')
        line_number = int(node.get('line_number', 0) or 0)
        if not filename or line_number <= 0:
            return None, 'invalid_trace_node'

        resolved_path = rewrite_prefixed_path(
            str(filename),
            old_prefix=old_prefix,
            new_prefix=new_prefix,
        )
        key = (resolved_path, line_number)
        if key in seen:
            continue
        seen.add(key)

        source_line = read_source_line(Path(resolved_path), line_number)
        if source_line is None:
            return None, 'missing_source_line'
        slice_lines.append(source_line)

    return ''.join(slice_lines), None
