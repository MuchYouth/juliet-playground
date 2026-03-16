from __future__ import annotations

from pathlib import Path
from typing import Callable

from shared.pipeline_runs import find_latest_pipeline_run_dir


def resolve_run_dir(
    *,
    run_dir: Path | None,
    pipeline_root: Path,
    inferred_from_path: Path | None = None,
    infer_run_dir_fn: Callable[[Path], Path | None] | None = None,
    use_latest_if_unresolved: bool = False,
) -> Path | None:
    if run_dir is not None:
        return run_dir.resolve()

    if inferred_from_path is not None and infer_run_dir_fn is not None:
        resolved = infer_run_dir_fn(inferred_from_path.resolve())
        if resolved is not None:
            return resolved.resolve()

    if use_latest_if_unresolved:
        return find_latest_pipeline_run_dir(pipeline_root.resolve())

    return None


def resolve_standard_stage_paths(
    *,
    primary_input: Path | None,
    output_dir: Path | None,
    run_dir: Path | None,
    pipeline_root: Path,
    infer_run_dir_from_input: Callable[[Path], Path | None],
    default_input_from_run_dir: Callable[[Path], Path],
    default_output_from_run_dir: Callable[[Path], Path],
    missing_output_dir_message: str,
) -> tuple[Path, Path, Path | None]:
    resolved_run_dir = resolve_run_dir(
        run_dir=run_dir,
        pipeline_root=pipeline_root,
        inferred_from_path=primary_input,
        infer_run_dir_fn=infer_run_dir_from_input,
        use_latest_if_unresolved=primary_input is None,
    )

    if primary_input is None:
        assert resolved_run_dir is not None
        resolved_primary_input = default_input_from_run_dir(resolved_run_dir)
    else:
        resolved_primary_input = primary_input.resolve()

    if output_dir is None:
        if resolved_run_dir is None:
            raise ValueError(missing_output_dir_message)
        resolved_output_dir = default_output_from_run_dir(resolved_run_dir)
    else:
        resolved_output_dir = output_dir.resolve()

    return resolved_primary_input, resolved_output_dir, resolved_run_dir


def require_existing_file(
    path: Path,
    *,
    missing_message: str,
    not_file_message: str,
) -> None:
    if not path.exists():
        raise FileNotFoundError(missing_message)
    if not path.is_file():
        raise FileNotFoundError(not_file_message)


def require_existing_dir(
    path: Path,
    *,
    missing_message: str,
    not_dir_message: str,
) -> None:
    if not path.exists():
        raise FileNotFoundError(missing_message)
    if not path.is_dir():
        raise NotADirectoryError(not_dir_message)


def validate_prefix_pair(old_prefix: str | None, new_prefix: str | None) -> None:
    if bool(old_prefix) != bool(new_prefix):
        raise ValueError('--old-prefix and --new-prefix must be provided together.')
