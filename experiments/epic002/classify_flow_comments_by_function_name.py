#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_ROOT = REPO_ROOT / 'tools'
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))

from stage import stage02b_epic002 as _stage02b_epic002


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            'Variant classifier: ignore constructor/destructor-specific handling and classify '
            'flow-level flaw/fix tags using function-name rules plus '
            'same-function line order.'
        )
    )
    parser.add_argument(
        '--manifest-xml',
        type=Path,
        required=True,
        help='입력 manifest_with_testcase_flows.xml 경로',
    )
    parser.add_argument(
        '--output-xml',
        type=Path,
        required=True,
        help='source/sink 분류 결과를 저장할 xml 경로',
    )
    parser.add_argument(
        '--exceptions-xml',
        type=Path,
        default=None,
        help='분류하지 못한 flow를 저장할 XML 경로 (선택)',
    )
    parser.add_argument(
        '--summary-json',
        type=Path,
        default=None,
        help='요약 통계만 따로 저장할 JSON 경로 (선택)',
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summary = _stage02b_epic002.write_classification_outputs(
        manifest_xml=args.manifest_xml.resolve(),
        output_xml=args.output_xml.resolve(),
        exceptions_xml=args.exceptions_xml.resolve() if args.exceptions_xml is not None else None,
        summary_json=args.summary_json.resolve() if args.summary_json is not None else None,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
