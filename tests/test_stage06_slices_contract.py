from __future__ import annotations

import json

from tests.golden.helpers import (
    REPO_ROOT,
    load_module_from_path,
    prepare_workspace,
    run_module_main,
)


def test_stage06_slices_contract(tmp_path):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_stage06_slices_contract',
        REPO_ROOT / 'tools/generate_slices.py',
    )

    output_dir = work_root / 'expected/06_slices'
    assert (
        run_module_main(
            module,
            [
                '--signature-db-dir',
                str(baseline_root / 'expected/05_pair_trace_ds/paired_signatures'),
                '--output-dir',
                str(output_dir),
            ],
        )
        == 0
    )

    slice_dir = output_dir / 'slice'
    summary_path = output_dir / 'summary.json'
    assert slice_dir.exists()
    assert summary_path.exists()

    slice_files = sorted(path for path in slice_dir.iterdir() if path.is_file())
    assert slice_files
    for path in slice_files:
        assert path.suffix in {'.c', '.cpp'}
        assert path.read_text(encoding='utf-8').strip()

    summary = json.loads(summary_path.read_text(encoding='utf-8'))
    assert {'signature_db_dir', 'output_dir', 'slice_dir', 'total_slices', 'counts'} <= set(summary)
    assert summary['total_slices'] == len(slice_files)
    assert summary['counts']['generated'] == len(slice_files)
