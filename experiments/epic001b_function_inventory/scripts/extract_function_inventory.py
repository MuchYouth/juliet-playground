#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from inventory_lib import extract_function_inventory


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Extract function-name inventory from manifest_with_comments.xml'
    )
    parser.add_argument(
        '--input-xml',
        type=Path,
        default=Path(
            'experiments/epic001_manifest_comment_scan/outputs/manifest_with_comments.xml'
        ),
    )
    parser.add_argument(
        '--output-csv',
        type=Path,
        default=Path('experiments/epic001b_function_inventory/outputs/function_names_unique.csv'),
    )
    parser.add_argument(
        '--output-summary',
        type=Path,
        default=Path('experiments/epic001b_function_inventory/outputs/summary.json'),
    )
    args = parser.parse_args()

    payload = extract_function_inventory(
        input_xml=args.input_xml,
        output_csv=args.output_csv,
        output_summary=args.output_summary,
    )
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
