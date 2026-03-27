from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path

POSITIVE_LABELS = frozenset({'1', 'true', 'yes', 'vuln', 'vulnerable'})
NEGATIVE_LABELS = frozenset({'0', 'false', 'no', 'safe', 'clean', 'non_vuln'})
LINE_SPLIT_RE = re.compile(r'[\s,]+')


@dataclass(frozen=True)
class BuildTarget:
    testcase_key: str
    workdir: Path
    build_command: str


@dataclass(frozen=True)
class ManualLineRecord:
    testcase_key: str
    file_path: str
    line_number: int
    label: str
    note: str


def normalize_source_path(path_like: str | Path, *, source_root: Path) -> str:
    raw = str(path_like or '').strip()
    if not raw:
        return ''

    candidate = Path(raw)
    if candidate.is_absolute():
        resolved = candidate.resolve()
        try:
            return resolved.relative_to(source_root.resolve()).as_posix()
        except ValueError:
            return resolved.as_posix()
    return candidate.as_posix()


def normalize_manual_label(raw_label: str | int | None) -> str:
    normalized = str(raw_label or '').strip().lower()
    if not normalized:
        raise ValueError('manual line label must not be empty')
    if normalized in POSITIVE_LABELS:
        return 'vuln'
    if normalized in NEGATIVE_LABELS:
        return 'non_vuln'
    raise ValueError(f'Unsupported manual line label: {raw_label}')


def parse_line_number_list(raw_value: str | int | None) -> list[int]:
    if raw_value is None:
        return []
    if isinstance(raw_value, int):
        return [raw_value] if raw_value > 0 else []

    tokens = [token for token in LINE_SPLIT_RE.split(str(raw_value).strip()) if token]
    line_numbers: list[int] = []
    for token in tokens:
        value = int(token)
        if value <= 0:
            raise ValueError(f'line_number must be > 0: {token}')
        if value not in line_numbers:
            line_numbers.append(value)
    return line_numbers


def load_build_targets_csv(path: Path) -> list[BuildTarget]:
    if not path.exists():
        raise FileNotFoundError(f'build_targets.csv not found: {path}')

    with path.open('r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        fieldnames = set(reader.fieldnames or [])
        required = {'testcase_key', 'workdir', 'build_command'}
        missing = sorted(required - fieldnames)
        if missing:
            raise ValueError(f'build_targets.csv missing required columns: {", ".join(missing)}')

        targets: list[BuildTarget] = []
        seen_keys: set[str] = set()
        for lineno, row in enumerate(reader, start=2):
            testcase_key = str(row.get('testcase_key') or '').strip()
            workdir_raw = str(row.get('workdir') or '').strip()
            build_command = str(row.get('build_command') or '').strip()
            if not testcase_key or not workdir_raw or not build_command:
                raise ValueError(f'Incomplete build target at line {lineno} in {path}')
            if testcase_key in seen_keys:
                raise ValueError(f'Duplicate testcase_key in build_targets.csv: {testcase_key}')
            workdir = Path(workdir_raw).resolve()
            targets.append(
                BuildTarget(
                    testcase_key=testcase_key,
                    workdir=workdir,
                    build_command=build_command,
                )
            )
            seen_keys.add(testcase_key)

    if not targets:
        raise ValueError(f'build_targets.csv is empty: {path}')
    return targets


def load_manual_line_truth_csv(path: Path, *, source_root: Path) -> list[ManualLineRecord]:
    if not path.exists():
        raise FileNotFoundError(f'manual_line_truth.csv not found: {path}')

    with path.open('r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        fieldnames = set(reader.fieldnames or [])
        required = {'testcase_key', 'file_path', 'line_number', 'label', 'note'}
        missing = sorted(required - fieldnames)
        if missing:
            raise ValueError(
                f'manual_line_truth.csv missing required columns: {", ".join(missing)}'
            )

        records: list[ManualLineRecord] = []
        for lineno, row in enumerate(reader, start=2):
            testcase_key = str(row.get('testcase_key') or '').strip()
            file_path_raw = str(row.get('file_path') or '').strip()
            note = str(row.get('note') or '').strip()
            if not testcase_key or not file_path_raw:
                raise ValueError(f'Incomplete manual line record at line {lineno} in {path}')

            normalized_path = normalize_source_path(file_path_raw, source_root=source_root)
            label = normalize_manual_label(row.get('label'))
            line_numbers = parse_line_number_list(row.get('line_number'))
            if not line_numbers:
                raise ValueError(f'No valid line numbers at line {lineno} in {path}')

            for line_number in line_numbers:
                records.append(
                    ManualLineRecord(
                        testcase_key=testcase_key,
                        file_path=normalized_path,
                        line_number=line_number,
                        label=label,
                        note=note,
                    )
                )

    if not records:
        raise ValueError(f'manual_line_truth.csv is empty: {path}')
    return records
