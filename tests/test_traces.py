from __future__ import annotations

from shared.traces import extract_std_bug_trace


def test_extract_std_bug_trace_accepts_flat_trace():
    trace = [{'filename': 'a.c', 'line_number': 1}, {'filename': 'a.c', 'line_number': 2}]

    assert extract_std_bug_trace(trace) == trace


def test_extract_std_bug_trace_selects_longest_nested_trace():
    nested = [
        [{'filename': 'a.c', 'line_number': 1}],
        [
            {'filename': 'b.c', 'line_number': 3},
            {'filename': 'b.c', 'line_number': 4},
        ],
    ]

    assert extract_std_bug_trace(nested) == nested[1]


def test_extract_std_bug_trace_handles_empty_and_invalid_inputs():
    assert extract_std_bug_trace([]) == []
    assert extract_std_bug_trace(None) == []
    assert extract_std_bug_trace(['not-a-dict']) == []
