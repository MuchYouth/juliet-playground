#!/usr/bin/env python3
from __future__ import annotations

import random
from pathlib import Path
from typing import Any

from shared.artifact_layout import build_dataset_export_paths
from shared.dataset_export_core import DatasetExportRequest, run_configured_step07_export
from shared.dataset_sources import (
    build_source_file_candidates,
    collect_identifier_inventory,
    expand_source_candidates_for_identifier_inventory,
)
from shared.jsonio import load_jsonl as _load_jsonl


def load_pairs_jsonl(path: Path) -> list[dict[str, Any]]:
    records = _load_jsonl(path)
    for lineno, obj in enumerate(records, start=1):
        pair_id = obj.get('pair_id')
        testcase_key = obj.get('testcase_key')
        if not pair_id or not testcase_key:
            raise ValueError(f'Missing pair_id/testcase_key at line {lineno} in {path}')
    return records


def compute_pair_split(pair_ids: list[str], train_ratio: float, seed: int) -> dict[str, str]:
    keys = sorted(set(pair_ids))
    shuffled = list(keys)
    random.Random(seed).shuffle(shuffled)

    test_ratio = 1.0 - train_ratio
    test_count = int(round(len(shuffled) * test_ratio))
    if len(shuffled) > 1:
        test_count = max(1, min(len(shuffled) - 1, test_count))
    else:
        test_count = 0

    test_keys = set(shuffled[:test_count])
    split_map: dict[str, str] = {}
    for key in shuffled:
        split_map[key] = 'test' if key in test_keys else 'train_val'
    return split_map


def export_primary_dataset(
    *,
    pairs_jsonl: Path,
    paired_signatures_dir: Path,
    slice_dir: Path,
    output_dir: Path,
    split_seed: int,
    train_ratio: float,
    dedup_mode: str,
) -> dict[str, Any]:
    if not pairs_jsonl.exists():
        raise FileNotFoundError(f'Pairs JSONL not found: {pairs_jsonl}')
    if not (0.0 < train_ratio < 1.0):
        raise ValueError(f'train_ratio must be between 0 and 1: {train_ratio}')

    pairs = load_pairs_jsonl(pairs_jsonl)
    export_paths = build_dataset_export_paths(output_dir)
    return run_configured_step07_export(
        DatasetExportRequest(
            pairs=pairs,
            paired_signatures_dir=paired_signatures_dir,
            slice_dir=slice_dir,
            export_paths=export_paths,
            dedup_mode=dedup_mode,
            split_assignments_fn=lambda pair_ids: compute_pair_split(
                pair_ids, train_ratio=train_ratio, seed=split_seed
            ),
            collect_identifier_inventory_fn=collect_identifier_inventory,
            build_source_file_candidates_fn=build_source_file_candidates,
            expand_inventory_source_candidates_fn=expand_source_candidates_for_identifier_inventory,
        )
    )


def export_dataset_from_pipeline(
    *,
    pairs_jsonl: Path,
    paired_signatures_dir: Path,
    slice_dir: Path,
    output_dir: Path,
    split_seed: int,
    train_ratio: float,
    dedup_mode: str,
) -> dict[str, Any]:
    return export_primary_dataset(
        pairs_jsonl=pairs_jsonl,
        paired_signatures_dir=paired_signatures_dir,
        slice_dir=slice_dir,
        output_dir=output_dir,
        split_seed=split_seed,
        train_ratio=train_ratio,
        dedup_mode=dedup_mode,
    )
