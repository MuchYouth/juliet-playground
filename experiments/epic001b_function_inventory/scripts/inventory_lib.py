from __future__ import annotations

import csv
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
TOOLS_ROOT = REPO_ROOT / 'tools'
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))

from shared.csvio import write_csv_rows
from shared.jsonio import write_json, write_summary_json
from shared.jsonio import write_jsonl as _write_jsonl
from shared.juliet_manifest import build_manifest_source_index

TARGET_TAGS = {'comment_flaw', 'comment_fix'}
C_IDENTIFIER_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
PYC_C_FUNC_RE = re.compile(
    r'^(CWE|cwe)(?P<cwe_number>\d+)_(?P<cwe_name>.*)__(?P<function_variant>.*)_(?P<flow_variant>\d+)(?P<subfile_id>[a-z]*)_(?P<function_name>[^.]*)$',
    re.IGNORECASE,
)
CALL_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_:]*)\s*\(')
CONTROL_TOKENS = {
    'if',
    'for',
    'while',
    'switch',
    'return',
    'sizeof',
    'catch',
    'new',
    'delete',
    'static_cast',
    'reinterpret_cast',
}
QUALIFIERS = {'const', 'noexcept', 'override', 'final', 'volatile'}


@dataclass
class FunctionRow:
    function_name: str
    count: int
    simple_name: str
    flow_family: str
    operation_role: str
    role_variant: str

    def to_jsonl_record(self) -> dict[str, object]:
        return {
            'function_name': self.function_name,
            'count': self.count,
            'simple_name': self.simple_name,
            'flow_family': self.flow_family,
            'operation_role': self.operation_role,
            'role_variant': self.role_variant,
        }


@dataclass(frozen=True)
class CategorizeContext:
    input_csv: Path
    manifest_xml: Path
    source_root: Path
    output_jsonl: Path
    output_nested_json: Path


def extract_function_inventory(
    *, input_xml: Path, output_csv: Path, output_summary: Path | None = None
) -> dict[str, object]:
    if not input_xml.exists():
        raise FileNotFoundError(f'Input XML not found: {input_xml}')

    root = ET.parse(input_xml).getroot()
    counter: Counter[str] = Counter()

    total_comment_tags_seen = 0
    total_function_values = 0
    missing_or_empty_function = 0

    for elem in root.iter():
        if elem.tag not in TARGET_TAGS:
            continue
        total_comment_tags_seen += 1
        function_name = (elem.attrib.get('function') or '').strip()
        if not function_name:
            missing_or_empty_function += 1
            continue
        total_function_values += 1
        counter[function_name] += 1

    sorted_rows = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    write_csv_rows(
        output_csv,
        ['function_name', 'count'],
        ([name, count] for name, count in sorted_rows),
    )

    unique_names = list(counter.keys())
    summary = {
        'input_xml': str(input_xml),
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'total_comment_tags_seen': total_comment_tags_seen,
        'total_function_values': total_function_values,
        'missing_or_empty_function': missing_or_empty_function,
        'unique_function_names': len(unique_names),
        'starts_with_good': sum(1 for name in unique_names if name.startswith('good')),
        'starts_with_bad': sum(1 for name in unique_names if name.startswith('bad')),
        'starts_with_CWE': sum(1 for name in unique_names if name.startswith('CWE')),
        'contains_scope_resolution_double_colon': sum(1 for name in unique_names if '::' in name),
        'contains_non_c_identifier_chars': sum(
            1 for name in unique_names if not C_IDENTIFIER_RE.fullmatch(name)
        ),
        'all_functions_sorted_by_count': [
            {'function_name': name, 'count': count} for name, count in sorted_rows
        ],
    }
    if output_summary is not None:
        write_summary_json(output_summary, summary, echo=False)

    return {
        'output_csv': str(output_csv),
        'output_summary': str(output_summary) if output_summary is not None else None,
        'total_comment_tags_seen': total_comment_tags_seen,
        'total_function_values': total_function_values,
        'unique_function_names': len(unique_names),
        'missing_or_empty_function': missing_or_empty_function,
    }


def split_simple_name(function_name: str) -> str:
    match = PYC_C_FUNC_RE.match(function_name)
    return match.group('function_name') if match else function_name


def classify_flow_family(simple_name: str) -> str:
    low = simple_name.lower()
    if low.startswith('helpergood') or low == 'helperbad':
        return 'helper_family'
    if low in {'goodclass', 'badclass', 'goodbaseclass', 'badbaseclass'}:
        return 'class_family'
    if 'g2b' in low:
        return 'g2b_family'
    if 'b2g' in low:
        return 'b2g_family'
    if 'good' in low and 'bad' not in low:
        return 'g2g_family'
    if 'bad' in low and 'good' not in low:
        return 'b2b_family'
    return 'misc_family'


def classify_operation_role_from_name(simple_name: str, original_name: str) -> tuple[str, str]:
    low = simple_name.lower()
    has_source = 'source' in low
    has_vasink = ('vasink' in low) or ('va_sink' in low)
    has_sink = ('sink' in low) or has_vasink
    has_action_sink = original_name.lower().endswith('::action')

    if has_source and (has_sink or has_action_sink):
        return 'source_sink', 'source_sink'
    if has_source:
        return 'source', 'source'
    if has_action_sink:
        return 'sink', 'action_sink'
    if has_vasink:
        return 'sink', 'va_sink'
    if has_sink:
        return 'sink', 'direct_sink'
    return 'source_sink', 'source_sink'


def _agg(items: list[FunctionRow]) -> dict[str, int]:
    return {'unique_count': len(items), 'weighted_count': sum(item.count for item in items)}


def load_function_files(manifest_xml: Path) -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = defaultdict(set)
    root = ET.parse(manifest_xml).getroot()
    for file_elem in root.iter('file'):
        file_name = file_elem.attrib.get('path', '')
        for tag in TARGET_TAGS:
            for element in file_elem.findall(tag):
                function_name = (element.attrib.get('function') or '').strip()
                if function_name:
                    mapping[function_name].add(file_name)
    return mapping


def find_matching_paren(text: str, open_idx: int) -> int:
    depth = 0
    for idx in range(open_idx, len(text)):
        char = text[idx]
        if char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
            if depth == 0:
                return idx
    return -1


def skip_qualifiers(text: str, idx: int) -> int:
    cursor = idx
    while cursor < len(text):
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        progressed = False
        for qualifier in QUALIFIERS:
            if text.startswith(qualifier, cursor):
                end = cursor + len(qualifier)
                if end == len(text) or not (text[end].isalnum() or text[end] == '_'):
                    cursor = end
                    progressed = True
                    break
        if not progressed:
            break
    return cursor


def extract_function_body(content: str, function_name: str) -> str | None:
    pattern = re.compile(rf'\b{re.escape(function_name)}\s*\(')
    for match in pattern.finditer(content):
        open_paren = content.find('(', match.start())
        if open_paren < 0:
            continue
        close_paren = find_matching_paren(content, open_paren)
        if close_paren < 0:
            continue
        start = skip_qualifiers(content, close_paren + 1)
        if start >= len(content) or content[start] != '{':
            continue
        depth = 0
        for idx in range(start, len(content)):
            if content[idx] == '{':
                depth += 1
            elif content[idx] == '}':
                depth -= 1
                if depth == 0:
                    return content[start + 1 : idx]
    return None


def classify_called_name(name: str) -> str:
    tail = name.split('::')[-1].lower()
    if 'source' in tail:
        return 'source'
    if 'sink' in tail or tail == 'action':
        return 'sink'
    return 'other'


def derive_source_sink_variant_from_body(
    function_name: str,
    function_files: dict[str, set[str]],
    source_index: dict[str, Path],
    file_cache: dict[Path, str],
) -> str:
    has_source = False
    has_sink = False

    for file_name in function_files.get(function_name, set()):
        source_path = source_index.get(file_name)
        if source_path is None:
            continue
        if source_path not in file_cache:
            file_cache[source_path] = source_path.read_text(encoding='utf-8', errors='ignore')
        body = extract_function_body(file_cache[source_path], function_name)
        if not body:
            continue
        for call in CALL_RE.findall(body):
            if call.split('::')[-1] in CONTROL_TOKENS:
                continue
            kind = classify_called_name(call)
            if kind == 'source':
                has_source = True
            elif kind == 'sink':
                has_sink = True
        if has_source and has_sink:
            break

    if has_source and has_sink:
        return 'both_func_included'
    if has_source:
        return 'source_func_only'
    if has_sink:
        return 'sink_func_only'
    return 'both_func_excluded'


def load_input_rows(input_csv: Path) -> list[tuple[str, int]]:
    rows: list[tuple[str, int]] = []
    with input_csv.open('r', encoding='utf-8', newline='') as handle:
        for row in csv.DictReader(handle):
            rows.append(
                (
                    (row.get('function_name') or '').strip(),
                    int((row.get('count') or '0').strip()),
                )
            )
    return rows


def categorize_rows(
    raw_rows: list[tuple[str, int]],
    function_files: dict[str, set[str]],
    source_index: dict[str, Path],
    file_cache: dict[Path, str],
) -> list[FunctionRow]:
    variant_cache: dict[str, str] = {}
    rows: list[FunctionRow] = []

    for function_name, count in raw_rows:
        simple_name = split_simple_name(function_name)
        flow_family = classify_flow_family(simple_name)
        operation_role, role_variant = classify_operation_role_from_name(simple_name, function_name)
        if operation_role == 'source_sink':
            if function_name not in variant_cache:
                variant_cache[function_name] = derive_source_sink_variant_from_body(
                    function_name,
                    function_files,
                    source_index,
                    file_cache,
                )
            role_variant = variant_cache[function_name]
        rows.append(
            FunctionRow(
                function_name=function_name,
                count=count,
                simple_name=simple_name,
                flow_family=flow_family,
                operation_role=operation_role,
                role_variant=role_variant,
            )
        )
    return rows


def build_group_maps(
    rows: list[FunctionRow],
) -> tuple[
    dict[str, list[FunctionRow]],
    dict[str, list[FunctionRow]],
    dict[str, list[FunctionRow]],
    dict[str, dict[str, list[FunctionRow]]],
    dict[str, dict[str, dict[str, list[FunctionRow]]]],
]:
    family_groups: dict[str, list[FunctionRow]] = defaultdict(list)
    role_groups: dict[str, list[FunctionRow]] = defaultdict(list)
    variant_groups: dict[str, list[FunctionRow]] = defaultdict(list)
    family_role_groups: dict[str, dict[str, list[FunctionRow]]] = defaultdict(
        lambda: defaultdict(list)
    )
    family_role_variant_groups: dict[str, dict[str, dict[str, list[FunctionRow]]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(list))
    )

    for row in rows:
        family_groups[row.flow_family].append(row)
        role_groups[row.operation_role].append(row)
        variant_groups[row.role_variant].append(row)
        family_role_groups[row.flow_family][row.operation_role].append(row)
        family_role_variant_groups[row.flow_family][row.operation_role][row.role_variant].append(
            row
        )

    return (
        family_groups,
        role_groups,
        variant_groups,
        family_role_groups,
        family_role_variant_groups,
    )


def build_nested_output(
    family_groups: dict[str, list[FunctionRow]],
    family_role_groups: dict[str, dict[str, list[FunctionRow]]],
    family_role_variant_groups: dict[str, dict[str, dict[str, list[FunctionRow]]]],
) -> dict[str, object]:
    flow_families = []
    for flow_family in sorted(family_groups):
        family_items = sorted(
            family_groups[flow_family],
            key=lambda row: (-row.count, row.function_name),
        )
        operation_roles: dict[str, object] = {}
        for operation_role in sorted(family_role_groups[flow_family]):
            role_items = sorted(
                family_role_groups[flow_family][operation_role],
                key=lambda row: (-row.count, row.function_name),
            )
            role_variants: dict[str, object] = {}
            for role_variant in sorted(family_role_variant_groups[flow_family][operation_role]):
                variant_items = sorted(
                    family_role_variant_groups[flow_family][operation_role][role_variant],
                    key=lambda row: (-row.count, row.function_name),
                )
                role_variants[role_variant] = {
                    **_agg(variant_items),
                    'items': [
                        {
                            'function_name': row.function_name,
                            'count': row.count,
                            'simple_name': row.simple_name,
                        }
                        for row in variant_items
                    ],
                }
            operation_roles[operation_role] = {
                **_agg(role_items),
                'items': [
                    {
                        'function_name': row.function_name,
                        'count': row.count,
                        'simple_name': row.simple_name,
                        'role_variant': row.role_variant,
                    }
                    for row in role_items
                ],
                'role_variants': role_variants,
            }
        flow_families.append(
            {
                'flow_family': flow_family,
                **_agg(family_items),
                'operation_roles': operation_roles,
            }
        )

    return {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'flow_families': flow_families,
    }


def build_summary(
    *,
    context: CategorizeContext,
    rows: list[FunctionRow],
    family_groups: dict[str, list[FunctionRow]],
    role_groups: dict[str, list[FunctionRow]],
    variant_groups: dict[str, list[FunctionRow]],
    family_role_groups: dict[str, dict[str, list[FunctionRow]]],
) -> dict[str, object]:
    return {
        'input_csv': str(context.input_csv),
        'manifest_xml': str(context.manifest_xml),
        'source_root': str(context.source_root),
        'output_jsonl': str(context.output_jsonl),
        'output_nested_json': str(context.output_nested_json),
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'total_unique_function_names': len(rows),
        'total_weighted_count': sum(row.count for row in rows),
        'flow_family_distribution': {key: _agg(value) for key, value in sorted(family_groups.items())},
        'operation_role_distribution': {key: _agg(value) for key, value in sorted(role_groups.items())},
        'role_variant_distribution': {key: _agg(value) for key, value in sorted(variant_groups.items())},
        'flow_family_operation_role_distribution': {
            flow_family: {
                operation_role: _agg(items)
                for operation_role, items in sorted(family_role_groups[flow_family].items())
            }
            for flow_family in sorted(family_role_groups)
        },
    }


def categorize_function_names(
    *,
    input_csv: Path,
    manifest_xml: Path,
    source_root: Path,
    output_jsonl: Path,
    output_nested_json: Path,
    output_summary: Path | None = None,
) -> dict[str, object]:
    if not input_csv.exists():
        raise FileNotFoundError(f'Input CSV not found: {input_csv}')
    if not manifest_xml.exists():
        raise FileNotFoundError(f'Manifest XML not found: {manifest_xml}')
    if not source_root.exists():
        raise FileNotFoundError(f'Source root not found: {source_root}')

    source_index = build_manifest_source_index(
        manifest_xml=manifest_xml,
        source_root=source_root,
        suffixes={'.c', '.cpp', '.h'},
    )
    function_files = load_function_files(manifest_xml)
    file_cache: dict[Path, str] = {}
    rows = categorize_rows(
        load_input_rows(input_csv),
        function_files,
        source_index,
        file_cache,
    )
    _write_jsonl(output_jsonl, (row.to_jsonl_record() for row in rows))

    family_groups, role_groups, variant_groups, family_role_groups, family_role_variant_groups = (
        build_group_maps(rows)
    )
    write_json(
        output_nested_json,
        build_nested_output(family_groups, family_role_groups, family_role_variant_groups),
        trailing_newline=False,
    )

    summary = build_summary(
        context=CategorizeContext(
            input_csv=input_csv,
            manifest_xml=manifest_xml,
            source_root=source_root,
            output_jsonl=output_jsonl,
            output_nested_json=output_nested_json,
        ),
        rows=rows,
        family_groups=family_groups,
        role_groups=role_groups,
        variant_groups=variant_groups,
        family_role_groups=family_role_groups,
    )
    if output_summary is not None:
        write_summary_json(output_summary, summary, echo=False)

    return {
        'output_jsonl': str(output_jsonl),
        'output_nested_json': str(output_nested_json),
        'output_summary': str(output_summary) if output_summary is not None else None,
        'total_unique_function_names': len(rows),
        'total_weighted_count': sum(row.count for row in rows),
    }
