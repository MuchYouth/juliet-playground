#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

import typer
from shared.paths import RESULT_DIR
from stage import signature as _signature_stage

find_latest_infer_run_dir = _signature_stage.find_latest_infer_run_dir
resolve_infer_run_name = _signature_stage.resolve_infer_run_name
get_group_key = _signature_stage.get_group_key
write_signature_stats_csv = _signature_stage.write_signature_stats_csv
generate_signatures = _signature_stage.generate_signatures


def main(
    input_dir: Path = typer.Option(None, '--input-dir', help='Input infer-* directory'),
    output_root: Path = typer.Option(
        Path(RESULT_DIR) / 'signatures',
        '--output-root',
        help='Root directory for signatures output',
    ),
):
    return _signature_stage.main(input_dir=input_dir, output_root=output_root)


if __name__ == '__main__':
    typer.run(main)
