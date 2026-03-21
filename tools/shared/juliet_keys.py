from __future__ import annotations

import re
from pathlib import Path

TESTCASE_KEY_RE = re.compile(r'^(CWE\d+)_([A-Za-z0-9_]+)_(\d+)([a-zA-Z]?)$')
JULIET_CASE_GROUP_STEM_RE = re.compile(
    '^CWE'
    + '(?P<cwe_number>\\d+)'
    + '_'
    + '(?P<cwe_name>.*)'
    + '__'
    + '(?P<functional_variant_name>.*)'
    + '_'
    + '(?P<flow_variant_id>\\d+)'
    + '_?'
    + '(?P<subfile_id>[a-z]{1}|(bad)|(good(\\d)+)|(base)|(goodB2G)|(goodG2B))?$',
    re.IGNORECASE,
)

JULIET_GROUP_SOURCE_SUFFIXES = frozenset({'.c', '.cpp'})
JULIET_GROUP_HEADER_SUFFIXES = frozenset({'.h', '.hpp', '.hh', '.hxx'})
JULIET_GROUP_INVENTORY_SUFFIXES = JULIET_GROUP_SOURCE_SUFFIXES | JULIET_GROUP_HEADER_SUFFIXES

JulietCaseIdentity = tuple[str, str, str, str, str]


def derive_testcase_key_from_file_name(file_name: str) -> str | None:
    stem = Path(file_name).stem
    m = TESTCASE_KEY_RE.match(stem)
    if not m:
        return None
    cwe, body, num, _letter = m.groups()
    return f'{cwe}_{num}-{cwe}_{body}'


def parse_juliet_case_identity(
    file_path: Path | str,
    *,
    allowed_suffixes: frozenset[str] | set[str] | None = None,
) -> JulietCaseIdentity | None:
    candidate = Path(file_path)
    suffix = candidate.suffix.lower()
    if allowed_suffixes is not None and suffix not in allowed_suffixes:
        return None

    match = JULIET_CASE_GROUP_STEM_RE.match(candidate.stem)
    if match is None:
        return None

    return (
        str(candidate.parent),
        match.group('cwe_number'),
        match.group('cwe_name'),
        match.group('functional_variant_name'),
        match.group('flow_variant_id'),
    )


def list_juliet_case_group_files(
    file_path: Path | str,
    *,
    allowed_suffixes: frozenset[str] | set[str] = JULIET_GROUP_SOURCE_SUFFIXES,
) -> list[Path]:
    candidate = Path(file_path)
    identity = parse_juliet_case_identity(candidate)
    if identity is None:
        return []

    directory = Path(identity[0])
    if not directory.is_dir():
        return []

    matches: list[Path] = []
    for entry in sorted(directory.iterdir()):
        if not entry.is_file():
            continue
        entry_identity = parse_juliet_case_identity(entry, allowed_suffixes=allowed_suffixes)
        if entry_identity == identity:
            matches.append(entry)
    return matches
