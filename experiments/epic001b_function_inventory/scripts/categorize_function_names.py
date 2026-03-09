#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PYC_C_FUNC_RE = re.compile(
    r"^(CWE|cwe)(?P<cwe_number>\d+)_(?P<cwe_name>.*)__(?P<function_variant>.*)_(?P<flow_variant>\d+)(?P<subfile_id>[a-z]*)_(?P<function_name>[^.]*)$",
    re.IGNORECASE,
)
CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_:]*)\s*\(")
CONTROL_TOKENS = {
    "if", "for", "while", "switch", "return", "sizeof", "catch", "new", "delete", "static_cast", "reinterpret_cast",
}
QUALIFIERS = {"const", "noexcept", "override", "final", "volatile"}


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
            "function_name": self.function_name,
            "count": self.count,
            "simple_name": self.simple_name,
            "flow_family": self.flow_family,
            "operation_role": self.operation_role,
            "role_variant": self.role_variant,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Categorize function names into flow_family/operation_role groups.")
    parser.add_argument("--input-csv", type=Path, default=Path("experiments/epic001b_function_inventory/outputs/function_names_unique.csv"))
    parser.add_argument("--manifest-xml", type=Path, default=Path("experiments/epic001_manifest_comment_scan/outputs/manifest_with_comments.xml"))
    parser.add_argument("--source-root", type=Path, default=Path("juliet-test-suite-v1.3/C/testcases"))
    parser.add_argument("--output-jsonl", type=Path, default=Path("experiments/epic001b_function_inventory/outputs/function_names_categorized.jsonl"))
    parser.add_argument("--output-nested-json", type=Path, default=Path("experiments/epic001b_function_inventory/outputs/grouped_family_role.json"))
    parser.add_argument("--output-summary", type=Path, default=Path("experiments/epic001b_function_inventory/outputs/category_summary.json"))
    return parser.parse_args()


def split_simple_name(function_name: str) -> str:
    m = PYC_C_FUNC_RE.match(function_name)
    return m.group("function_name") if m else function_name


def classify_flow_family(simple_name: str) -> str:
    low = simple_name.lower()
    if low.startswith("helpergood") or low == "helperbad":
        return "helper_family"
    if low in {"goodclass", "badclass", "goodbaseclass", "badbaseclass"}:
        return "class_family"
    if "g2b" in low:
        return "g2b_family"
    if "b2g" in low:
        return "b2g_family"
    if "good" in low and "bad" not in low:
        return "g2g_family"
    if "bad" in low and "good" not in low:
        return "b2b_family"
    return "misc_family"


def classify_operation_role_from_name(simple_name: str, original_name: str) -> tuple[str, str]:
    low = simple_name.lower()
    has_source = "source" in low
    has_vasink = ("vasink" in low) or ("va_sink" in low)
    has_sink = ("sink" in low) or has_vasink
    has_action_sink = original_name.lower().endswith("::action")

    if has_source and (has_sink or has_action_sink):
        return "source_sink", "source_sink"
    if has_source:
        return "source", "source"
    if has_action_sink:
        return "sink", "action_sink"
    if has_vasink:
        return "sink", "va_sink"
    if has_sink:
        return "sink", "direct_sink"
    return "source_sink", "source_sink"


def _agg(items: list[FunctionRow]) -> dict[str, int]:
    return {"unique_count": len(items), "weighted_count": sum(x.count for x in items)}


def build_source_index(source_root: Path) -> dict[str, Path]:
    idx: dict[str, Path] = {}
    for p in source_root.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".c", ".cpp", ".h"} and p.name not in idx:
            idx[p.name] = p
    return idx


def load_function_files(manifest_xml: Path) -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = defaultdict(set)
    root = ET.parse(manifest_xml).getroot()
    for file_elem in root.iter("file"):
        file_name = file_elem.attrib.get("path", "")
        for tag in ("comment_flaw", "comment_fix"):
            for e in file_elem.findall(tag):
                fn = (e.attrib.get("function") or "").strip()
                if fn:
                    mapping[fn].add(file_name)
    return mapping


def find_matching_paren(text: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def skip_qualifiers(text: str, idx: int) -> int:
    i = idx
    n = len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        progressed = False
        for q in QUALIFIERS:
            if text.startswith(q, i):
                j = i + len(q)
                if j == n or not (text[j].isalnum() or text[j] == "_"):
                    i = j
                    progressed = True
                    break
        if not progressed:
            break
    return i


def extract_function_body(content: str, function_name: str) -> str | None:
    pattern = re.compile(rf"\b{re.escape(function_name)}\s*\(")
    for m in pattern.finditer(content):
        open_paren = content.find("(", m.start())
        if open_paren < 0:
            continue
        close_paren = find_matching_paren(content, open_paren)
        if close_paren < 0:
            continue
        i = skip_qualifiers(content, close_paren + 1)
        if i >= len(content) or content[i] != "{":
            continue
        depth = 0
        for j in range(i, len(content)):
            if content[j] == "{":
                depth += 1
            elif content[j] == "}":
                depth -= 1
                if depth == 0:
                    return content[i + 1 : j]
    return None


def classify_called_name(name: str) -> str:
    tail = name.split("::")[-1]
    low = tail.lower()
    if "source" in low:
        return "source"
    if "sink" in low or low == "action":
        return "sink"
    return "other"


def derive_source_sink_variant_from_body(
    function_name: str,
    function_files: dict[str, set[str]],
    source_index: dict[str, Path],
    file_cache: dict[Path, str],
) -> str:
    files = function_files.get(function_name, set())
    has_source = False
    has_sink = False

    for file_name in files:
        src = source_index.get(file_name)
        if src is None:
            continue
        if src not in file_cache:
            file_cache[src] = src.read_text(encoding="utf-8", errors="ignore")
        body = extract_function_body(file_cache[src], function_name)
        if not body:
            continue
        for call in CALL_RE.findall(body):
            token = call.split("::")[-1]
            if token in CONTROL_TOKENS:
                continue
            kind = classify_called_name(call)
            if kind == "source":
                has_source = True
            elif kind == "sink":
                has_sink = True
        if has_source and has_sink:
            break

    if has_source and has_sink:
        return "both_func_included"
    if has_source:
        return "source_func_only"
    if has_sink:
        return "sink_func_only"
    return "both_func_excluded"


def validate_inputs(args: argparse.Namespace) -> None:
    if not args.input_csv.exists():
        raise FileNotFoundError(f"Input CSV not found: {args.input_csv}")
    if not args.manifest_xml.exists():
        raise FileNotFoundError(f"Manifest XML not found: {args.manifest_xml}")
    if not args.source_root.exists():
        raise FileNotFoundError(f"Source root not found: {args.source_root}")


def load_input_rows(input_csv: Path) -> list[tuple[str, int]]:
    rows: list[tuple[str, int]] = []
    with input_csv.open("r", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            function_name = (r.get("function_name") or "").strip()
            count = int((r.get("count") or "0").strip())
            rows.append((function_name, count))
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

        if operation_role == "source_sink":
            if function_name not in variant_cache:
                variant_cache[function_name] = derive_source_sink_variant_from_body(
                    function_name, function_files, source_index, file_cache
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


def write_jsonl(rows: list[FunctionRow], output_jsonl: Path) -> None:
    output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with output_jsonl.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row.to_jsonl_record(), ensure_ascii=False) + "\n")


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
    family_role_groups: dict[str, dict[str, list[FunctionRow]]] = defaultdict(lambda: defaultdict(list))
    family_role_variant_groups: dict[str, dict[str, dict[str, list[FunctionRow]]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(list))
    )

    for row in rows:
        ff = row.flow_family
        op = row.operation_role
        rv = row.role_variant
        family_groups[ff].append(row)
        role_groups[op].append(row)
        variant_groups[rv].append(row)
        family_role_groups[ff][op].append(row)
        family_role_variant_groups[ff][op][rv].append(row)

    return family_groups, role_groups, variant_groups, family_role_groups, family_role_variant_groups


def build_nested_output(
    family_groups: dict[str, list[FunctionRow]],
    family_role_groups: dict[str, dict[str, list[FunctionRow]]],
    family_role_variant_groups: dict[str, dict[str, dict[str, list[FunctionRow]]]],
) -> dict[str, object]:
    nested: dict[str, object] = {"generated_at": datetime.now(timezone.utc).isoformat(), "flow_families": []}
    flow_families = []

    for ff in sorted(family_groups.keys()):
        ff_items = sorted(family_groups[ff], key=lambda x: (-x.count, x.function_name))
        roles_obj: dict[str, object] = {}

        for op in sorted(family_role_groups[ff].keys()):
            op_items = sorted(family_role_groups[ff][op], key=lambda x: (-x.count, x.function_name))
            variants_obj: dict[str, object] = {}

            for rv in sorted(family_role_variant_groups[ff][op].keys()):
                rv_items = sorted(family_role_variant_groups[ff][op][rv], key=lambda x: (-x.count, x.function_name))
                variants_obj[rv] = {
                    **_agg(rv_items),
                    "items": [
                        {"function_name": x.function_name, "count": x.count, "simple_name": x.simple_name}
                        for x in rv_items
                    ],
                }

            roles_obj[op] = {
                **_agg(op_items),
                "items": [
                    {
                        "function_name": x.function_name,
                        "count": x.count,
                        "simple_name": x.simple_name,
                        "role_variant": x.role_variant,
                    }
                    for x in op_items
                ],
                "role_variants": variants_obj,
            }

        flow_families.append({"flow_family": ff, **_agg(ff_items), "operation_roles": roles_obj})

    nested["flow_families"] = flow_families
    return nested


def write_nested_json(nested: dict[str, object], output_nested_json: Path) -> None:
    output_nested_json.parent.mkdir(parents=True, exist_ok=True)
    with output_nested_json.open("w", encoding="utf-8") as f:
        json.dump(nested, f, ensure_ascii=False, indent=2)


def build_summary(
    args: argparse.Namespace,
    rows: list[FunctionRow],
    family_groups: dict[str, list[FunctionRow]],
    role_groups: dict[str, list[FunctionRow]],
    variant_groups: dict[str, list[FunctionRow]],
    family_role_groups: dict[str, dict[str, list[FunctionRow]]],
) -> dict[str, object]:
    return {
        "input_csv": str(args.input_csv),
        "manifest_xml": str(args.manifest_xml),
        "source_root": str(args.source_root),
        "output_jsonl": str(args.output_jsonl),
        "output_nested_json": str(args.output_nested_json),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_unique_function_names": len(rows),
        "total_weighted_count": sum(r.count for r in rows),
        "flow_family_distribution": {k: _agg(v) for k, v in sorted(family_groups.items())},
        "operation_role_distribution": {k: _agg(v) for k, v in sorted(role_groups.items())},
        "role_variant_distribution": {k: _agg(v) for k, v in sorted(variant_groups.items())},
        "flow_family_operation_role_distribution": {
            ff: {op: _agg(v) for op, v in sorted(family_role_groups[ff].items())}
            for ff in sorted(family_role_groups)
        },
    }


def write_summary(summary: dict[str, object], output_summary: Path) -> None:
    output_summary.parent.mkdir(parents=True, exist_ok=True)
    with output_summary.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)


def main() -> int:
    args = parse_args()
    validate_inputs(args)

    source_index = build_source_index(args.source_root)
    function_files = load_function_files(args.manifest_xml)
    file_cache: dict[Path, str] = {}
    raw_rows = load_input_rows(args.input_csv)
    rows = categorize_rows(raw_rows, function_files, source_index, file_cache)
    write_jsonl(rows, args.output_jsonl)

    family_groups, role_groups, variant_groups, family_role_groups, family_role_variant_groups = build_group_maps(rows)
    nested = build_nested_output(family_groups, family_role_groups, family_role_variant_groups)
    write_nested_json(nested, args.output_nested_json)

    summary = build_summary(args, rows, family_groups, role_groups, variant_groups, family_role_groups)
    write_summary(summary, args.output_summary)

    print(
        json.dumps(
            {
                "output_jsonl": str(args.output_jsonl),
                "output_nested_json": str(args.output_nested_json),
                "output_summary": str(args.output_summary),
                "total_unique_function_names": len(rows),
                "total_weighted_count": sum(r.count for r in rows),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
