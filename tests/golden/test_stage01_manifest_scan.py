from __future__ import annotations

import io
import json
from contextlib import redirect_stdout

from tests.golden.helpers import (
    REPO_ROOT,
    assert_directory_matches,
    load_module_from_path,
    prepare_workspace,
    run_module_main,
)


def test_stage01_manifest_scan_matches_golden(tmp_path):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_golden_stage01_manifest_scan',
        REPO_ROOT / 'experiments/epic001_manifest_comment_scan/scripts/scan_manifest_comments.py',
    )

    output_dir = work_root / 'expected/01_manifest'
    output_xml = output_dir / 'manifest_with_comments.xml'
    output_dir.mkdir(parents=True, exist_ok=True)

    stdout = io.StringIO()
    with redirect_stdout(stdout):
        assert (
            run_module_main(
                module,
                [
                    '--manifest',
                    str(baseline_root / 'seed/manifest_subset.xml'),
                    '--source-root',
                    str(REPO_ROOT / 'juliet-test-suite-v1.3/C'),
                    '--output-xml',
                    str(output_xml),
                ],
            )
            == 0
        )

    payload = json.loads(stdout.getvalue().strip().splitlines()[-1])
    (output_dir / 'summary.stdout.json').write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )

    assert_directory_matches(
        expected_dir=baseline_root / 'expected/01_manifest',
        actual_dir=output_dir,
        root_aliases=[(baseline_root, ''), (work_root, ''), (REPO_ROOT, '')],
    )
