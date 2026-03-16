#!/usr/bin/env python3
from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shared.dataset_export_core import run_step07_export_core
from shared.dataset_sources import build_source_file_candidates, collect_defined_function_names


@dataclass(frozen=True)
class PrimaryDatasetExportParams:
    pairs_jsonl: Path
    paired_signatures_dir: Path
    slice_dir: Path
    output_dir: Path
    split_seed: int
    train_ratio: float
    dedup_mode: str


@dataclass(frozen=True)
class PrimaryDatasetExportResult:
    summary_json: Path
    output_dir: Path
    normalized_slices_dir: Path
    real_vul_data_csv: Path
    dedup_dropped_csv: Path
    normalized_token_counts_csv: Path
    slice_token_distribution_png: Path
    split_manifest_json: Path

    def to_payload(self) -> dict[str, object]:
        return {
            'summary_json': str(self.summary_json),
            'output_dir': str(self.output_dir),
            'normalized_slices_dir': str(self.normalized_slices_dir),
            'real_vul_data_csv': str(self.real_vul_data_csv),
            'dedup_dropped_csv': str(self.dedup_dropped_csv),
            'normalized_token_counts_csv': str(self.normalized_token_counts_csv),
            'slice_token_distribution_png': str(self.slice_token_distribution_png),
            'split_manifest_json': str(self.split_manifest_json),
        }


def load_pairs_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open('r', encoding='utf-8') as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            pair_id = obj.get('pair_id')
            testcase_key = obj.get('testcase_key')
            if not pair_id or not testcase_key:
                raise ValueError(f'Missing pair_id/testcase_key at line {lineno} in {path}')
            records.append(obj)
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


def export_primary_dataset(params: PrimaryDatasetExportParams) -> PrimaryDatasetExportResult:
    if not params.pairs_jsonl.exists():
        raise FileNotFoundError(f'Pairs JSONL not found: {params.pairs_jsonl}')
    if not params.paired_signatures_dir.exists():
        raise FileNotFoundError(f'Paired signatures dir not found: {params.paired_signatures_dir}')
    if not params.slice_dir.exists():
        raise FileNotFoundError(f'Slice dir not found: {params.slice_dir}')
    if not (0.0 < params.train_ratio < 1.0):
        raise ValueError(f'train_ratio must be between 0 and 1: {params.train_ratio}')
    if params.dedup_mode not in {'none', 'row'}:
        raise ValueError(f'Unsupported dedup_mode: {params.dedup_mode}')

    params.output_dir.mkdir(parents=True, exist_ok=True)
    normalized_slices_dir = params.output_dir / 'normalized_slices'
    real_vul_data_csv = params.output_dir / 'Real_Vul_data.csv'
    dedup_dropped_csv = params.output_dir / 'Real_Vul_data_dedup_dropped.csv'
    normalized_token_counts_csv = params.output_dir / 'normalized_token_counts.csv'
    slice_token_distribution_png = params.output_dir / 'slice_token_distribution.png'
    split_manifest_json = params.output_dir / 'split_manifest.json'
    summary_json = params.output_dir / 'summary.json'

    pairs = load_pairs_jsonl(params.pairs_jsonl)

    run_step07_export_core(
        pairs=pairs,
        paired_signatures_dir=params.paired_signatures_dir,
        slice_dir=params.slice_dir,
        csv_path=real_vul_data_csv,
        dedup_dropped_csv=dedup_dropped_csv,
        normalized_slices_dir=normalized_slices_dir,
        token_counts_csv=normalized_token_counts_csv,
        token_distribution_png=slice_token_distribution_png,
        split_manifest_json=split_manifest_json,
        summary_json=summary_json,
        dedup_mode=params.dedup_mode,
        split_assignments_fn=lambda pair_ids: compute_pair_split(
            pair_ids, train_ratio=params.train_ratio, seed=params.split_seed
        ),
        summary_metadata={
            'pairs_jsonl': str(params.pairs_jsonl),
            'paired_signatures_dir': str(params.paired_signatures_dir),
            'slice_dir': str(params.slice_dir),
            'output_dir': str(params.output_dir),
            'real_vul_data_csv': str(real_vul_data_csv),
            'normalized_token_counts_csv': str(normalized_token_counts_csv),
            'slice_token_distribution_png': str(slice_token_distribution_png),
            'seed': params.split_seed,
            'train_ratio': params.train_ratio,
            'test_ratio': round(1.0 - params.train_ratio, 6),
        },
        split_manifest_metadata={
            'output_dir': str(params.output_dir),
            'pairs_jsonl': str(params.pairs_jsonl),
            'paired_signatures_dir': str(params.paired_signatures_dir),
            'slice_dir': str(params.slice_dir),
            'split_unit': 'pair_id',
            'train_ratio': params.train_ratio,
            'test_ratio': round(1.0 - params.train_ratio, 6),
            'seed': params.split_seed,
        },
        collect_defined_function_names_fn=collect_defined_function_names,
        build_source_file_candidates_fn=build_source_file_candidates,
    )

    return PrimaryDatasetExportResult(
        summary_json=summary_json,
        output_dir=params.output_dir,
        normalized_slices_dir=normalized_slices_dir,
        real_vul_data_csv=real_vul_data_csv,
        dedup_dropped_csv=dedup_dropped_csv,
        normalized_token_counts_csv=normalized_token_counts_csv,
        slice_token_distribution_png=slice_token_distribution_png,
        split_manifest_json=split_manifest_json,
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
) -> dict[str, object]:
    return export_primary_dataset(
        PrimaryDatasetExportParams(
            pairs_jsonl=pairs_jsonl,
            paired_signatures_dir=paired_signatures_dir,
            slice_dir=slice_dir,
            output_dir=output_dir,
            split_seed=split_seed,
            train_ratio=train_ratio,
            dedup_mode=dedup_mode,
        )
    ).to_payload()
