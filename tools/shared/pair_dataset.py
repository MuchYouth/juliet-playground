from __future__ import annotations

from pathlib import Path
from typing import Any

from shared.jsonio import write_json


def write_pair_signature_exports(
    *,
    signatures_dir: Path,
    testcase_key: str,
    counterpart_flow_type: str,
    b2b_payload: dict[str, Any],
    b2b_pairing_meta: dict[str, Any],
    counterpart_payload: dict[str, Any],
    counterpart_pairing_meta: dict[str, Any],
) -> dict[str, str]:
    testcase_dir = signatures_dir / testcase_key
    testcase_dir.mkdir(parents=True, exist_ok=True)

    b2b_output_path = testcase_dir / 'b2b.json'
    counterpart_output_path = testcase_dir / f'{counterpart_flow_type}.json'

    b2b_export = dict(b2b_payload)
    b2b_export['pairing_meta'] = dict(b2b_pairing_meta)
    counterpart_export = dict(counterpart_payload)
    counterpart_export['pairing_meta'] = dict(counterpart_pairing_meta)

    write_json(b2b_output_path, b2b_export)
    write_json(counterpart_output_path, counterpart_export)

    return {
        'b2b': str(b2b_output_path),
        counterpart_flow_type: str(counterpart_output_path),
    }


def build_pair_dataset_row(
    *,
    pair_id: str,
    testcase_key: str,
    selection_reason: str,
    b2b_flow_type: str,
    b2b_trace_file: str,
    b2b_bug_trace_length: int,
    b2b_signature: Any,
    counterpart_flow_type: str,
    counterpart_trace_file: str,
    counterpart_bug_trace_length: int,
    counterpart_signature: Any,
    output_files: dict[str, str],
    leading_fields: dict[str, Any] | None = None,
    trailing_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        'pair_id': pair_id,
        'testcase_key': testcase_key,
        'selection_reason': selection_reason,
    }
    if leading_fields:
        row.update(leading_fields)
    row.update(
        {
            'b2b_flow_type': b2b_flow_type,
            'b2b_trace_file': b2b_trace_file,
            'b2b_bug_trace_length': b2b_bug_trace_length,
            'b2b_signature': b2b_signature,
            'counterpart_flow_type': counterpart_flow_type,
            'counterpart_trace_file': counterpart_trace_file,
            'counterpart_bug_trace_length': counterpart_bug_trace_length,
            'counterpart_signature': counterpart_signature,
            'output_files': output_files,
        }
    )
    if trailing_fields:
        row.update(trailing_fields)
    return row
