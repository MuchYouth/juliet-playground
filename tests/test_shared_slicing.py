from __future__ import annotations

from tests.helpers import REPO_ROOT, load_module_from_path


def _load_module():
    return load_module_from_path(
        'test_shared_slicing_module',
        REPO_ROOT / 'tools/shared/slicing.py',
    )


def test_build_slice_rewrites_prefix_and_dedupes_locations(tmp_path):
    module = _load_module()
    source_file = tmp_path / 'sample.c'
    source_file.write_text('line 1\nline 2\nline 3\n', encoding='utf-8')

    result, reason = module.build_slice(
        [
            {'filename': '/old/root/sample.c', 'line_number': 2},
            {'filename': '/old/root/sample.c', 'line_number': 2},
            {'filename': '/old/root/sample.c', 'line_number': 3},
        ],
        old_prefix='/old/root',
        new_prefix=str(tmp_path),
    )

    assert reason is None
    assert result == 'line 2\nline 3\n'


def test_build_slice_reports_missing_source_line(tmp_path):
    module = _load_module()
    source_file = tmp_path / 'sample.c'
    source_file.write_text('line 1\n', encoding='utf-8')

    result, reason = module.build_slice(
        [{'filename': str(source_file), 'line_number': 2}],
    )

    assert result is None
    assert reason == 'missing_source_line'


def test_guess_output_suffix_uses_extra_candidates():
    module = _load_module()

    suffix = module.guess_output_suffix(
        {'file': ''},
        [],
        extra_candidates=['fallback.cpp'],
    )

    assert suffix == '.cpp'
