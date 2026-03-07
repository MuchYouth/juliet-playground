from __future__ import annotations

import json


def new_stats() -> dict:
    return {
        "total_files": 0,
        "scanned_files": 0,
        "missing_files": 0,
        "parse_failed_files": 0,
        "dropped_comment_lines": 0,
    }


def inc(stats: dict, key: str, n: int = 1) -> None:
    stats[key] += n


def print_summary(output_xml: str, stats: dict) -> None:
    payload = {"output_xml": output_xml, **stats}
    print(json.dumps(payload, ensure_ascii=False))
