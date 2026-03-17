#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage import stage02b_flow as _stage02b_flow


def main() -> int:
    parser = argparse.ArgumentParser(description='Add per-testcase flow tags (b2b/b2g/g2b).')
    parser.add_argument(
        '--input-xml',
        type=Path,
        default=Path(
            'experiments/epic001_manifest_comment_scan/outputs/manifest_with_comments.xml'
        ),
    )
    parser.add_argument(
        '--output-xml',
        type=Path,
        default=Path(
            'experiments/epic001c_testcase_flow_partition/outputs/manifest_with_testcase_flows.xml'
        ),
    )
    parser.add_argument(
        '--summary-json',
        type=Path,
        default=Path('experiments/epic001c_testcase_flow_partition/outputs/summary.json'),
    )
    args = parser.parse_args()

    payload = _stage02b_flow.add_flow_tags_to_testcase(
        input_xml=args.input_xml,
        output_xml=args.output_xml,
        summary_json=args.summary_json,
    )
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
