#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from inventory_lib import DEFAULT_OUTPUT_DIR, extract_flow_role_call_inventory


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Extract role-aware code, call, and argument-position inventory from flow XML.'
    )
    parser.add_argument(
        '--input-xml',
        type=Path,
        required=True,
        help='Path to 02a_taint/source_sink_classified_with_code.xml',
    )
    parser.add_argument('--source-root', type=Path, default=Path('juliet-test-suite-v1.3/C'))
    parser.add_argument('--output-dir', type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    payload = extract_flow_role_call_inventory(
        input_xml=args.input_xml,
        source_root=args.source_root,
        output_dir=args.output_dir,
    )
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
