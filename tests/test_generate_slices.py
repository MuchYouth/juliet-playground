from __future__ import annotations

import json


def test_process_signature_db_uses_longest_subtrace_and_dedupes_locations(
    tmp_path, load_tools_module
):
    module = load_tools_module('test_generate_slices_module', 'generate_slices.py')

    source_file = tmp_path / 'sample.c'
    source_file.write_text('line 1\nline 2\nline 3\n', encoding='utf-8')

    testcase_dir = tmp_path / 'signatures' / 'CASE001'
    testcase_dir.mkdir(parents=True)
    (testcase_dir / 'b2b.json').write_text(
        json.dumps(
            {
                'file': str(source_file),
                'bug_trace': [
                    [{'filename': str(source_file), 'line_number': 1}],
                    [
                        {'filename': str(source_file), 'line_number': 2},
                        {'filename': str(source_file), 'line_number': 2},
                        {'filename': str(source_file), 'line_number': 3},
                    ],
                ],
            }
        ),
        encoding='utf-8',
    )

    slice_dir = tmp_path / 'out' / 'slice'
    summary = module.process_signature_db(
        signature_db_dir=tmp_path / 'signatures',
        slice_dir=slice_dir,
        old_prefix=None,
        new_prefix=None,
    )

    assert summary['total_slices'] == 1
    assert summary['counts']['generated'] == 1

    generated_files = list(slice_dir.iterdir())
    assert len(generated_files) == 1
    assert generated_files[0].name == 'slice_CASE001_b2b.c'
    assert generated_files[0].read_text(encoding='utf-8') == 'line 2\nline 3\n'
