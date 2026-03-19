from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
TOOLS_ROOT = REPO_ROOT / 'tools'
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))

from shared.callsite_extraction import extract_call_sites_for_line, load_file_context
from shared.csvio import write_csv_rows
from shared.dataset_sources import load_tree_sitter_parsers
from shared.jsonio import write_jsonl, write_stage_summary
from shared.juliet_manifest import build_manifest_source_index
from stage import stage02a_taint as _stage02a_taint

ROLE_TAGS = {'source', 'sink'}
TARGET_TAGS = {'fix', 'flaw'}
DEFAULT_OUTPUT_DIR = REPO_ROOT / 'experiments' / 'epic001e_flow_role_call_inventory' / 'outputs'


def _safe_int(raw_value: str | None) -> int:
    try:
        return int(str(raw_value or '').strip())
    except ValueError:
        return 0


def _fallback_resolution(raw_function_name: str) -> _stage02a_taint.ResolutionResult:
    return _stage02a_taint.ResolutionResult(
        [raw_function_name],
        'no_macro_match',
        0,
        '',
        '',
    )


def _iter_role_elements(root: ET.Element):
    for testcase_index, testcase in enumerate(root.findall('testcase'), start=1):
        testcase_label = testcase.attrib.get('testcase_index') or str(testcase_index)
        for flow_index, flow in enumerate(testcase.findall('flow'), start=1):
            flow_label = flow.attrib.get('flow_index') or str(flow_index)
            flow_type = (flow.attrib.get('type') or '').strip()
            classification_method = (flow.attrib.get('classification_method') or '').strip()
            for child in flow:
                if child.tag not in TARGET_TAGS:
                    continue
                role = (child.attrib.get('role') or '').strip()
                if role not in ROLE_TAGS:
                    continue
                yield testcase_label, flow_label, flow_type, classification_method, child


def extract_flow_role_call_inventory(
    *,
    input_xml: Path,
    source_root: Path,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> dict[str, object]:
    if not input_xml.exists():
        raise FileNotFoundError(
            f'Input XML not found: {input_xml}. Expected 02a_taint/source_sink_classified_with_code.xml'
        )
    if not source_root.exists():
        raise FileNotFoundError(f'Source root not found: {source_root}')

    root = ET.parse(input_xml).getroot()
    if not any(True for _ in _iter_role_elements(root)):
        raise ValueError(f'No role-tagged flow elements found in {input_xml}')

    output_dir.mkdir(parents=True, exist_ok=True)
    parsers = load_tree_sitter_parsers()
    source_index = build_manifest_source_index(
        manifest_xml=input_xml,
        source_root=source_root,
    )
    ctx_cache: dict[str, object | None] = {}
    core = _stage02a_taint.build_taint_inventory_core(input_xml=input_xml, source_root=source_root)
    resolution_map = core.resolution_map

    occurrence_rows: list[dict[str, object]] = []
    call_rows: list[dict[str, object]] = []
    role_code_aggregate: dict[tuple[str, str], dict[str, object]] = {}
    function_summary: dict[tuple[str, str, int], dict[str, object]] = {}
    argument_summary: dict[tuple[str, str, int, int], dict[str, object]] = {}
    role_counts: Counter[str] = Counter()
    raw_function_names: set[str] = set()
    resolved_function_names: set[str] = set()
    empty_code_count = 0
    rows_without_calls = 0

    for testcase_index, flow_index, flow_type, classification_method, child in _iter_role_elements(root):
        role = str(child.attrib.get('role') or '').strip()
        tag = child.tag
        code = str(child.attrib.get('code') or '')
        code_key = code.strip()
        file_name = str(child.attrib.get('file') or '')
        line_no = _safe_int(child.attrib.get('line'))
        safety = str(child.attrib.get('safety') or '').strip()

        role_counts[role] += 1
        if not code_key:
            empty_code_count += 1

        if file_name not in ctx_cache:
            source_path = source_index.get(file_name)
            ctx_cache[file_name] = load_file_context(source_path, parsers) if source_path else None
        ctx = ctx_cache[file_name]

        call_sites = (
            extract_call_sites_for_line(
                ctx=ctx,
                line_no=line_no,
                target_text=code_key or None,
            )
            if ctx is not None and line_no > 0
            else []
        )

        serialized_calls: list[dict[str, object]] = []
        for call_ordinal, call_site in enumerate(call_sites, start=1):
            if call_site.raw_function_name:
                raw_function_names.add(call_site.raw_function_name)
                resolution = resolution_map.get(
                    call_site.raw_function_name,
                    _fallback_resolution(call_site.raw_function_name),
                )
                resolved_names = resolution.resolved_names or [call_site.raw_function_name]
                resolved_function_names.update(resolved_names)
                resolution_status = resolution.status
            else:
                resolved_names = []
                resolution_status = 'empty_name'
            arguments = [argument.to_dict() for argument in call_site.arguments]
            serialized_calls.append(
                {
                    **call_site.to_dict(),
                    'call_ordinal': call_ordinal,
                    'resolved_function_names': resolved_names,
                    'resolution_status': resolution_status,
                }
            )

            for resolved_function_name in resolved_names:
                call_row = {
                    'role': role,
                    'tag': tag,
                    'flow_type': flow_type,
                    'classification_method': classification_method,
                    'safety': safety,
                    'testcase_index': testcase_index,
                    'flow_index': flow_index,
                    'file': file_name,
                    'line': line_no,
                    'code': code,
                    'raw_function_name': call_site.raw_function_name,
                    'resolved_function_name': resolved_function_name,
                    'argc': call_site.argc,
                    'call_ordinal': call_ordinal,
                    'call_text': call_site.call_text,
                    'lhs_text': call_site.lhs_text,
                    'arguments': arguments,
                }
                call_rows.append(call_row)

                function_key = (role, resolved_function_name, call_site.argc)
                function_entry = function_summary.setdefault(
                    function_key,
                    {
                        'role': role,
                        'resolved_function_name': resolved_function_name,
                        'argc': call_site.argc,
                        'call_occurrence_count': 0,
                        '_codes': set(),
                        '_files': set(),
                    },
                )
                function_entry['call_occurrence_count'] += 1
                function_entry['_codes'].add(code_key)
                function_entry['_files'].add(file_name)

                for argument in call_site.arguments:
                    argument_key = (role, resolved_function_name, call_site.argc, argument.position)
                    argument_entry = argument_summary.setdefault(
                        argument_key,
                        {
                            'role': role,
                            'resolved_function_name': resolved_function_name,
                            'argc': call_site.argc,
                            'arg_position': argument.position,
                            'call_occurrence_count': 0,
                            '_codes': set(),
                            '_sample_arguments': [],
                        },
                    )
                    argument_entry['call_occurrence_count'] += 1
                    argument_entry['_codes'].add(code_key)
                    if argument.text not in argument_entry['_sample_arguments']:
                        argument_entry['_sample_arguments'].append(argument.text)

        occurrence_row = {
            'role': role,
            'tag': tag,
            'flow_type': flow_type,
            'classification_method': classification_method,
            'safety': safety,
            'testcase_index': testcase_index,
            'flow_index': flow_index,
            'file': file_name,
            'line': line_no,
            'code': code,
            'selected_call_count': len(serialized_calls),
            'calls': serialized_calls,
        }
        occurrence_rows.append(occurrence_row)
        if not serialized_calls:
            rows_without_calls += 1

        aggregate_key = (role, code_key)
        aggregate_entry = role_code_aggregate.setdefault(
            aggregate_key,
            {
                'role': role,
                'code': code_key,
                'occurrence_count': 0,
                '_testcase_indexes': set(),
                '_files': set(),
                'selected_call_occurrence_count': 0,
                'example_file': file_name,
                'example_line': line_no,
            },
        )
        aggregate_entry['occurrence_count'] += 1
        aggregate_entry['_testcase_indexes'].add(testcase_index)
        aggregate_entry['_files'].add(file_name)
        aggregate_entry['selected_call_occurrence_count'] += len(serialized_calls)

    role_code_unique_rows = sorted(
        (
            {
                'role': entry['role'],
                'occurrence_count': entry['occurrence_count'],
                'unique_testcase_count': len(entry['_testcase_indexes']),
                'unique_file_count': len(entry['_files']),
                'selected_call_occurrence_count': entry['selected_call_occurrence_count'],
                'example_file': entry['example_file'],
                'example_line': entry['example_line'],
                'code': entry['code'],
            }
            for entry in role_code_aggregate.values()
        ),
        key=lambda row: (str(row['role']), -int(row['occurrence_count']), str(row['code'])),
    )
    function_summary_rows = sorted(
        (
            {
                'role': entry['role'],
                'resolved_function_name': entry['resolved_function_name'],
                'argc': entry['argc'],
                'call_occurrence_count': entry['call_occurrence_count'],
                'unique_code_count': len(entry['_codes']),
                'unique_file_count': len(entry['_files']),
            }
            for entry in function_summary.values()
        ),
        key=lambda row: (
            str(row['role']),
            -int(row['call_occurrence_count']),
            str(row['resolved_function_name']),
            int(row['argc']),
        ),
    )
    argument_summary_rows = sorted(
        (
            {
                'role': entry['role'],
                'resolved_function_name': entry['resolved_function_name'],
                'argc': entry['argc'],
                'arg_position': entry['arg_position'],
                'call_occurrence_count': entry['call_occurrence_count'],
                'unique_code_count': len(entry['_codes']),
                'sample_arguments': ' | '.join(entry['_sample_arguments'][:5]),
            }
            for entry in argument_summary.values()
        ),
        key=lambda row: (
            str(row['role']),
            str(row['resolved_function_name']),
            int(row['argc']),
            int(row['arg_position']),
        ),
    )

    artifacts = {
        'role_code_occurrences_jsonl': str(output_dir / 'role_code_occurrences.jsonl'),
        'role_code_unique_csv': str(output_dir / 'role_code_unique.csv'),
        'role_call_rows_jsonl': str(output_dir / 'role_call_rows.jsonl'),
        'function_call_summary_csv': str(output_dir / 'function_call_summary.csv'),
        'argument_position_summary_csv': str(output_dir / 'argument_position_summary.csv'),
        'summary_json': str(output_dir / 'summary.json'),
    }

    write_jsonl(Path(artifacts['role_code_occurrences_jsonl']), occurrence_rows)
    write_csv_rows(
        Path(artifacts['role_code_unique_csv']),
        [
            'role',
            'occurrence_count',
            'unique_testcase_count',
            'unique_file_count',
            'selected_call_occurrence_count',
            'example_file',
            'example_line',
            'code',
        ],
        (
            [
                row['role'],
                row['occurrence_count'],
                row['unique_testcase_count'],
                row['unique_file_count'],
                row['selected_call_occurrence_count'],
                row['example_file'],
                row['example_line'],
                row['code'],
            ]
            for row in role_code_unique_rows
        ),
    )
    write_jsonl(Path(artifacts['role_call_rows_jsonl']), call_rows)
    write_csv_rows(
        Path(artifacts['function_call_summary_csv']),
        [
            'role',
            'resolved_function_name',
            'argc',
            'call_occurrence_count',
            'unique_code_count',
            'unique_file_count',
        ],
        (
            [
                row['role'],
                row['resolved_function_name'],
                row['argc'],
                row['call_occurrence_count'],
                row['unique_code_count'],
                row['unique_file_count'],
            ]
            for row in function_summary_rows
        ),
    )
    write_csv_rows(
        Path(artifacts['argument_position_summary_csv']),
        [
            'role',
            'resolved_function_name',
            'argc',
            'arg_position',
            'call_occurrence_count',
            'unique_code_count',
            'sample_arguments',
        ],
        (
            [
                row['role'],
                row['resolved_function_name'],
                row['argc'],
                row['arg_position'],
                row['call_occurrence_count'],
                row['unique_code_count'],
                row['sample_arguments'],
            ]
            for row in argument_summary_rows
        ),
    )

    stats = {
        'role_tag_occurrences': len(occurrence_rows),
        'source_occurrences': role_counts['source'],
        'sink_occurrences': role_counts['sink'],
        'source_unique_codes': sum(1 for row in role_code_unique_rows if row['role'] == 'source'),
        'sink_unique_codes': sum(1 for row in role_code_unique_rows if row['role'] == 'sink'),
        'empty_code_occurrences': empty_code_count,
        'occurrences_without_calls': rows_without_calls,
        'call_rows': len(call_rows),
        'unique_raw_function_names': len(raw_function_names),
        'unique_resolved_function_names': len(resolved_function_names),
        'function_summary_rows': len(function_summary_rows),
        'argument_position_rows': len(argument_summary_rows),
    }
    write_stage_summary(
        Path(artifacts['summary_json']),
        artifacts=artifacts,
        stats=stats,
        echo=False,
    )
    return {'artifacts': artifacts, 'stats': stats}
