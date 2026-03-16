from __future__ import annotations

from tests.helpers import REPO_ROOT, load_module_from_path


def test_make_pair_id_is_stable_without_namespace():
    module = load_module_from_path(
        'test_shared_pairing_module',
        REPO_ROOT / 'tools/shared/pairing.py',
    )

    left = module.make_pair_id(
        testcase_key='CASE001',
        b2b_payload={'hash': 'hash-b2b'},
        b2b_trace_file='/tmp/run-a/non_empty/CASE001/1.json',
        b2b_flow_type='b2b',
        counterpart_payload={'hash': 'hash-g2b'},
        counterpart_trace_file='/tmp/run-a/non_empty/CASE001/2.json',
        counterpart_flow_type='g2b',
    )
    right = module.make_pair_id(
        testcase_key='CASE001',
        b2b_payload={'hash': 'hash-b2b'},
        b2b_trace_file='/tmp/run-b/non_empty/CASE001/1.json',
        b2b_flow_type='b2b',
        counterpart_payload={'hash': 'hash-g2b'},
        counterpart_trace_file='/tmp/run-b/non_empty/CASE001/2.json',
        counterpart_flow_type='g2b',
    )

    assert left == right


def test_make_pair_id_changes_when_dataset_namespace_changes():
    module = load_module_from_path(
        'test_shared_pairing_namespace_module',
        REPO_ROOT / 'tools/shared/pairing.py',
    )

    base = module.make_pair_id(
        testcase_key='CASE001',
        b2b_payload={'hash': 'hash-b2b'},
        b2b_trace_file='CASE001/1.json',
        b2b_flow_type='b2b',
        counterpart_payload={'hash': 'hash-g2b'},
        counterpart_trace_file='CASE001/2.json',
        counterpart_flow_type='g2b',
    )
    namespaced = module.make_pair_id(
        testcase_key='CASE001',
        b2b_payload={'hash': 'hash-b2b'},
        b2b_trace_file='CASE001/1.json',
        b2b_flow_type='b2b',
        counterpart_payload={'hash': 'hash-g2b'},
        counterpart_trace_file='CASE001/2.json',
        counterpart_flow_type='g2b',
        dataset_namespace='train_patched_counterparts',
    )

    assert base != namespaced
