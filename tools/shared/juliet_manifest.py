from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from functools import lru_cache
from pathlib import Path


def resolve_testcases_root(source_root: Path) -> Path:
    testcases_root = source_root / 'testcases'
    if testcases_root.is_dir():
        return testcases_root
    return source_root


@lru_cache(maxsize=None)
def _load_manifest_file_names(manifest_xml: str) -> tuple[str, ...]:
    root = ET.parse(manifest_xml).getroot()
    file_names: list[str] = []
    seen: set[str] = set()
    for file_elem in root.iter('file'):
        file_name = Path(file_elem.attrib.get('path', '')).name
        if not file_name or file_name in seen:
            continue
        seen.add(file_name)
        file_names.append(file_name)
    return tuple(file_names)


def load_manifest_file_names(manifest_xml: Path) -> tuple[str, ...]:
    return _load_manifest_file_names(str(manifest_xml.resolve()))


def cwe_dir_name_from_file_name(file_name: str) -> str | None:
    base_name = Path(file_name).name
    if '__' in base_name:
        cwe_dir_name = base_name.split('__', 1)[0].strip()
        return cwe_dir_name or None
    return None


@lru_cache(maxsize=None)
def _index_cwe_dir(
    testcases_root: str, cwe_dir_name: str, suffixes: tuple[str, ...]
) -> tuple[tuple[str, str], ...]:
    cwe_dir = Path(testcases_root) / cwe_dir_name
    if not cwe_dir.is_dir():
        return ()

    index: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(cwe_dir):
        dirnames.sort()
        filenames.sort()
        for filename in filenames:
            path = Path(dirpath) / filename
            if suffixes and path.suffix.lower() not in suffixes:
                continue
            if filename not in index:
                index[filename] = str(path)
    return tuple(index.items())


def build_manifest_source_index(
    manifest_xml: Path,
    source_root: Path,
    suffixes: set[str] | None = None,
) -> dict[str, Path]:
    normalized_suffixes = tuple(sorted((suffixes or set())))
    testcases_root = resolve_testcases_root(source_root).resolve()
    source_index: dict[str, Path] = {}

    cwe_dir_names = {
        cwe_dir_name
        for file_name in load_manifest_file_names(manifest_xml)
        if (cwe_dir_name := cwe_dir_name_from_file_name(file_name))
    }
    cwe_indexes = {
        cwe_dir_name: dict(_index_cwe_dir(str(testcases_root), cwe_dir_name, normalized_suffixes))
        for cwe_dir_name in sorted(cwe_dir_names)
    }

    for file_name in load_manifest_file_names(manifest_xml):
        cwe_dir_name = cwe_dir_name_from_file_name(file_name)
        if cwe_dir_name is None:
            continue
        path_str = cwe_indexes.get(cwe_dir_name, {}).get(file_name)
        if path_str:
            source_index[file_name] = Path(path_str)

    return source_index
