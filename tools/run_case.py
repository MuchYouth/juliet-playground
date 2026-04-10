#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import run_external_trace_pipeline as _run_external_trace_pipeline
from shared.external_case import (
    TRACK_NAMES,
    CaseRunPaths,
    ensure_relative_symlink,
    infer_project_name_from_repo,
    resolve_case_run_paths,
)
from shared.paths import EXTERNAL_RUNS_DIR


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Run a case-managed external-project trace pipeline run.'
    )
    parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--track', type=str, choices=sorted(TRACK_NAMES), required=True)
    parser.add_argument('--run', type=str, required=True)
    parser.add_argument('--project-name', type=str, default=None)
    parser.add_argument(
        '--artifact-root',
        type=Path,
        default=Path(EXTERNAL_RUNS_DIR),
        help='Root directory that contains external case run outputs.',
    )
    parser.add_argument('--overwrite', action='store_true')
    return parser.parse_args()


def run_case(args: argparse.Namespace) -> int:
    paths = resolve_case_run_paths(
        args.case,
        track=args.track,
        run_id=args.run,
        artifact_root=args.artifact_root,
    )
    _validate_required_paths(paths)

    project_name = args.project_name or infer_project_name_from_repo(paths.repo_dir)
    pipeline_args = argparse.Namespace(
        source_root=paths.repo_dir,
        build_targets=paths.build_targets_csv,
        manual_line_truth=paths.manual_line_truth_csv,
        pulse_taint_config=paths.pulse_taint_config,
        output_root=paths.artifact_output_root,
        run_id=paths.run_id,
        project_name=project_name,
        overwrite=args.overwrite,
    )
    result = _run_external_trace_pipeline.run_external_trace_pipeline(pipeline_args)
    ensure_relative_symlink(paths.outputs_link, paths.artifact_run_dir)

    print(f'Case run completed: {paths.case_id}/{paths.track}/{paths.run_id}')
    print(f'  - case_run_dir: {paths.run_dir}')
    print(f'  - outputs_link: {paths.outputs_link}')
    return result


def _validate_required_paths(paths: CaseRunPaths) -> None:
    required = {
        'track directory': paths.track_dir,
        'repo directory': paths.repo_dir,
        'runs directory': paths.runs_dir,
        'base-run directory': paths.base_run_dir,
        'run directory': paths.run_dir,
        'build_targets.csv': paths.build_targets_csv,
        'manual_line_truth.csv': paths.manual_line_truth_csv,
        'pulse-taint-config.json': paths.pulse_taint_config,
    }
    for label, path in required.items():
        if not path.exists():
            raise ValueError(f'Missing {label}: {path}')


def main() -> int:
    args = parse_args()
    try:
        return run_case(args)
    except (ValueError, FileExistsError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
