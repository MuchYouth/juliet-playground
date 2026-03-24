from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path
from typing import Any

from shared import strict_trace as _strict_trace
from shared.artifact_layout import build_trace_dataset_paths, path_strings
from shared.fs import prepare_output_dir
from shared.jsonio import write_jsonl, write_stage_summary
from shared.signatures import load_signature_payload, stable_signature_ref, stable_trace_ref

StrictTraceRecord = _strict_trace.StrictTraceRecord


def validate_args(trace_jsonl: Path) -> None:
    _strict_trace.validate_strict_trace_jsonl(trace_jsonl)


def load_strict_records(trace_jsonl: Path) -> list[StrictTraceRecord]:
    return _strict_trace.load_strict_records(trace_jsonl)


def make_trace_id(record: StrictTraceRecord, signature_payload: dict[str, Any]) -> str:
    seed = '||'.join(
        [
            record.testcase_key,
            record.best_flow_type,
            str(record.bug_trace_length),
            str(record.procedure or ''),
            stable_signature_ref(signature_payload, record.trace_file),
            stable_trace_ref(record.trace_file),
        ]
    )
    return hashlib.sha1(seed.encode('utf-8')).hexdigest()[:16]


def build_trace_dataset(
    *,
    trace_jsonl: Path,
    output_dir: Path,
    overwrite: bool = False,
) -> dict[str, Any]:
    validate_args(trace_jsonl)
    prepare_output_dir(output_dir, overwrite)

    paths = build_trace_dataset_paths(output_dir)
    strict_records = load_strict_records(trace_jsonl)

    trace_rows: list[dict[str, Any]] = []
    flow_counts = Counter()
    target_counts = Counter()
    testcase_keys: set[str] = set()

    for record in strict_records:
        payload = load_signature_payload(record.trace_file)
        trace_id = make_trace_id(record, payload)
        target = 1 if record.best_flow_type == 'b2b' else 0
        trace_rows.append(
            {
                'trace_id': trace_id,
                'testcase_key': record.testcase_key,
                'best_flow_type': record.best_flow_type,
                'target': target,
                'trace_file': str(record.trace_file),
                'bug_trace_length': record.bug_trace_length,
                'procedure': record.procedure,
            }
        )
        testcase_keys.add(record.testcase_key)
        flow_counts[record.best_flow_type] += 1
        target_counts[str(target)] += 1

    write_jsonl(paths['traces_jsonl'], trace_rows)
    artifacts = path_strings(paths)
    stats = {
        'records_total': len(strict_records),
        'traces_total': len(trace_rows),
        'testcases_total': len(testcase_keys),
        'best_flow_counts': dict(flow_counts),
        'target_counts': dict(target_counts),
    }
    write_stage_summary(paths['summary_json'], artifacts=artifacts, stats=stats)
    return {'artifacts': artifacts, 'stats': stats}
