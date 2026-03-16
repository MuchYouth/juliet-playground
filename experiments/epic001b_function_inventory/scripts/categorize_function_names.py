#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage import stage02b_flow as _stage02b_flow


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Categorize function names into flow_family/operation_role groups.'
    )
    parser.add_argument(
        '--input-csv',
        type=Path,
        default=Path('experiments/epic001b_function_inventory/outputs/function_names_unique.csv'),
    )
    parser.add_argument(
        '--manifest-xml',
        type=Path,
        default=Path(
            'experiments/epic001_manifest_comment_scan/outputs/manifest_with_comments.xml'
        ),
    )
    parser.add_argument('--source-root', type=Path, default=Path('juliet-test-suite-v1.3/C/testcases'))
    parser.add_argument(
        '--output-jsonl',
        type=Path,
        default=Path(
            'experiments/epic001b_function_inventory/outputs/function_names_categorized.jsonl'
        ),
    )
    parser.add_argument(
        '--output-nested-json',
        type=Path,
        default=Path('experiments/epic001b_function_inventory/outputs/grouped_family_role.json'),
    )
    parser.add_argument(
        '--output-summary',
        type=Path,
        default=Path('experiments/epic001b_function_inventory/outputs/category_summary.json'),
    )
    args = parser.parse_args()

    payload = _stage02b_flow.categorize_function_names(
        input_csv=args.input_csv,
        manifest_xml=args.manifest_xml,
        source_root=args.source_root,
        output_jsonl=args.output_jsonl,
        output_nested_json=args.output_nested_json,
        output_summary=args.output_summary,
    )
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
