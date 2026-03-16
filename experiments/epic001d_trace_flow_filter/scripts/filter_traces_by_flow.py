#!/usr/bin/env python3
from __future__ import annotations

import argparse

from pathlib import Path

from stage import stage04_trace_flow as _trace_flow

FlowPoint = _trace_flow.FlowPoint
TARGET_TAGS = _trace_flow.TARGET_TAGS
build_trace_line_set = _trace_flow.build_trace_line_set
choose_best_flow = _trace_flow.choose_best_flow
derive_testcase_key_from_file_name = _trace_flow.derive_testcase_key_from_file_name
filter_traces_by_flow = _trace_flow.filter_traces_by_flow
load_flow_index = _trace_flow.load_flow_index
match_trace_to_flows = _trace_flow.match_trace_to_flows


def main() -> int:
    parser = argparse.ArgumentParser(description='Filter signature traces by testcase flow tags.')
    parser.add_argument('--flow-xml', type=Path, required=True)
    parser.add_argument('--signatures-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()

    filter_traces_by_flow(
        flow_xml=args.flow_xml,
        signatures_dir=args.signatures_dir,
        output_dir=args.output_dir,
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
