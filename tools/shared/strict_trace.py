from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class StrictTraceRecord:
    testcase_key: str
    trace_file: Path
    best_flow_type: str
    bug_trace_length: int
    procedure: str | None
    raw: dict[str, Any] | None = None


def validate_strict_trace_jsonl(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f'Strict trace JSONL not found: {path}')
    if not path.is_file():
        raise FileNotFoundError(f'Strict trace JSONL is not a file: {path}')


def load_strict_records(
    path: Path,
    *,
    include_raw: bool = False,
) -> list[StrictTraceRecord]:
    validate_strict_trace_jsonl(path)

    records: list[StrictTraceRecord] = []
    with path.open('r', encoding='utf-8') as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            testcase_key = str(obj.get('testcase_key') or '').strip()
            trace_file_raw = str(obj.get('trace_file') or '').strip()
            best_flow_type = str(obj.get('best_flow_type') or '').strip()
            if not testcase_key or not trace_file_raw or not best_flow_type:
                raise ValueError(f'Missing required keys at line {lineno} in {path}: {obj}')
            records.append(
                StrictTraceRecord(
                    testcase_key=testcase_key,
                    trace_file=Path(trace_file_raw),
                    best_flow_type=best_flow_type,
                    bug_trace_length=int(obj.get('bug_trace_length', 0) or 0),
                    procedure=obj.get('procedure'),
                    raw=obj if include_raw else None,
                )
            )
    return records
