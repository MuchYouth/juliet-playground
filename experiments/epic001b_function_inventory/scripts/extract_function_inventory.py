#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

TARGET_TAGS = {"comment_flaw", "comment_fix"}
C_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract function-name inventory from manifest_with_comments.xml"
    )
    parser.add_argument(
        "--input-xml",
        type=Path,
        default=Path("experiments/epic001_manifest_comment_scan/outputs/manifest_with_comments.xml"),
        help="Input XML containing comment_flaw/comment_fix tags",
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=Path("experiments/epic001b_function_inventory/outputs/function_names_unique.csv"),
        help="Output CSV path for unique function names and counts",
    )
    parser.add_argument(
        "--output-summary",
        type=Path,
        default=Path("experiments/epic001b_function_inventory/outputs/summary.json"),
        help="Output JSON path for summary stats",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.input_xml.exists():
        raise FileNotFoundError(f"Input XML not found: {args.input_xml}")

    root = ET.parse(args.input_xml).getroot()
    counter: Counter[str] = Counter()

    total_comment_tags_seen = 0
    total_function_values = 0
    missing_or_empty_function = 0

    for elem in root.iter():
        if elem.tag not in TARGET_TAGS:
            continue
        total_comment_tags_seen += 1
        function_name = (elem.attrib.get("function") or "").strip()
        if not function_name:
            missing_or_empty_function += 1
            continue
        total_function_values += 1
        counter[function_name] += 1

    sorted_rows = sorted(counter.items(), key=lambda item: (-item[1], item[0]))

    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.output_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["function_name", "count"])
        writer.writerows(sorted_rows)

    unique_names = list(counter.keys())
    starts_with_good = sum(1 for name in unique_names if name.startswith("good"))
    starts_with_bad = sum(1 for name in unique_names if name.startswith("bad"))
    starts_with_cwe = sum(1 for name in unique_names if name.startswith("CWE"))
    contains_scope_resolution_double_colon = sum(1 for name in unique_names if "::" in name)
    contains_non_c_identifier_chars = sum(
        1 for name in unique_names if not C_IDENTIFIER_RE.fullmatch(name)
    )

    summary = {
        "input_xml": str(args.input_xml),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_comment_tags_seen": total_comment_tags_seen,
        "total_function_values": total_function_values,
        "missing_or_empty_function": missing_or_empty_function,
        "unique_function_names": len(unique_names),
        "starts_with_good": starts_with_good,
        "starts_with_bad": starts_with_bad,
        "starts_with_CWE": starts_with_cwe,
        "contains_scope_resolution_double_colon": contains_scope_resolution_double_colon,
        "contains_non_c_identifier_chars": contains_non_c_identifier_chars,
        "all_functions_sorted_by_count": [
            {"function_name": name, "count": count} for name, count in sorted_rows
        ],
    }

    args.output_summary.parent.mkdir(parents=True, exist_ok=True)
    with args.output_summary.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(
        json.dumps(
            {
                "output_csv": str(args.output_csv),
                "output_summary": str(args.output_summary),
                "total_comment_tags_seen": total_comment_tags_seen,
                "total_function_values": total_function_values,
                "unique_function_names": len(unique_names),
                "missing_or_empty_function": missing_or_empty_function,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
