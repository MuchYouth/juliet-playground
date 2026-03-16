from __future__ import annotations

from dataclasses import dataclass, fields
from pathlib import Path
from typing import ClassVar

TRAIN_PATCHED_COUNTERPARTS_BASENAME = 'train_patched_counterparts'


@dataclass(frozen=True)
class PathBundle:
    _required_fields: ClassVar[tuple[str, ...]] = ()

    def to_payload(
        self,
        *,
        prefix: str = '',
        rename: dict[str, str] | None = None,
        include: tuple[str, ...] | None = None,
    ) -> dict[str, str]:
        payload: dict[str, str] = {}
        include_set = set(include) if include is not None else None
        rename = rename or {}
        for field in fields(self):
            value = getattr(self, field.name)
            if not isinstance(value, Path):
                continue
            if include_set is not None and field.name not in include_set:
                continue
            payload[f'{prefix}{rename.get(field.name, field.name)}'] = str(value)
        return payload

    def required_outputs(
        self,
        *,
        prefix: str = '',
        rename: dict[str, str] | None = None,
    ) -> list[tuple[Path, str]]:
        rename = rename or {}
        outputs: list[tuple[Path, str]] = []
        for field_name in self._required_fields:
            path = getattr(self, field_name)
            label = f'{prefix}{rename.get(field_name, field_name)}'
            outputs.append((path, f'Expected {label} not found: {path}'))
        return outputs


@dataclass(frozen=True)
class DatasetExportPaths(PathBundle):
    output_dir: Path
    csv_path: Path
    dedup_dropped_csv: Path
    normalized_slices_dir: Path
    token_counts_csv: Path
    token_distribution_png: Path
    split_manifest_json: Path
    summary_json: Path

    _required_fields: ClassVar[tuple[str, ...]] = (
        'normalized_slices_dir',
        'csv_path',
        'dedup_dropped_csv',
        'token_counts_csv',
        'token_distribution_png',
        'split_manifest_json',
        'summary_json',
    )


@dataclass(frozen=True)
class PairTracePaths(PathBundle):
    output_dir: Path
    pairs_jsonl: Path
    leftover_counterparts_jsonl: Path
    paired_signatures_dir: Path
    summary_json: Path

    _required_fields: ClassVar[tuple[str, ...]] = (
        'pairs_jsonl',
        'paired_signatures_dir',
        'summary_json',
    )


@dataclass(frozen=True)
class PatchedPairingPaths(PathBundle):
    output_dir: Path
    pairs_jsonl: Path
    signatures_dir: Path
    selection_summary_json: Path

    _required_fields: ClassVar[tuple[str, ...]] = (
        'pairs_jsonl',
        'signatures_dir',
        'selection_summary_json',
    )


@dataclass(frozen=True)
class SliceStagePaths(PathBundle):
    output_dir: Path
    slice_dir: Path
    summary_json: Path

    _required_fields: ClassVar[tuple[str, ...]] = (
        'slice_dir',
        'summary_json',
    )


def build_dataset_export_paths(
    output_dir: Path,
    dataset_basename: str | None = None,
) -> DatasetExportPaths:
    if dataset_basename:
        return DatasetExportPaths(
            output_dir=output_dir,
            csv_path=output_dir / f'{dataset_basename}.csv',
            dedup_dropped_csv=output_dir / f'{dataset_basename}_dedup_dropped.csv',
            normalized_slices_dir=output_dir / f'{dataset_basename}_slices',
            token_counts_csv=output_dir / f'{dataset_basename}_token_counts.csv',
            token_distribution_png=output_dir / f'{dataset_basename}_token_distribution.png',
            split_manifest_json=output_dir / f'{dataset_basename}_split_manifest.json',
            summary_json=output_dir / f'{dataset_basename}_summary.json',
        )
    return DatasetExportPaths(
        output_dir=output_dir,
        csv_path=output_dir / 'Real_Vul_data.csv',
        dedup_dropped_csv=output_dir / 'Real_Vul_data_dedup_dropped.csv',
        normalized_slices_dir=output_dir / 'normalized_slices',
        token_counts_csv=output_dir / 'normalized_token_counts.csv',
        token_distribution_png=output_dir / 'slice_token_distribution.png',
        split_manifest_json=output_dir / 'split_manifest.json',
        summary_json=output_dir / 'summary.json',
    )


def build_pair_trace_paths(pair_dir: Path) -> PairTracePaths:
    return PairTracePaths(
        output_dir=pair_dir,
        pairs_jsonl=pair_dir / 'pairs.jsonl',
        leftover_counterparts_jsonl=pair_dir / 'leftover_counterparts.jsonl',
        paired_signatures_dir=pair_dir / 'paired_signatures',
        summary_json=pair_dir / 'summary.json',
    )


def build_patched_pairing_paths(
    pair_dir: Path,
    dataset_basename: str = TRAIN_PATCHED_COUNTERPARTS_BASENAME,
) -> PatchedPairingPaths:
    return PatchedPairingPaths(
        output_dir=pair_dir,
        pairs_jsonl=pair_dir / f'{dataset_basename}_pairs.jsonl',
        signatures_dir=pair_dir / f'{dataset_basename}_signatures',
        selection_summary_json=pair_dir / f'{dataset_basename}_selection_summary.json',
    )


def build_slice_stage_paths(stage_dir: Path) -> SliceStagePaths:
    return SliceStagePaths(
        output_dir=stage_dir,
        slice_dir=stage_dir / 'slice',
        summary_json=stage_dir / 'summary.json',
    )
