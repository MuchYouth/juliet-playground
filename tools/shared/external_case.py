from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from shared.paths import EXTERNAL_RUNS_DIR

TRACK_NAMES = frozenset({'vulnerable', 'patched'})
REMOTE_URL_RE = re.compile(r'^\s*url\s*=\s*(?P<url>\S+)\s*$')


@dataclass(frozen=True)
class CaseRunPaths:
    case_dir: Path
    case_id: str
    track: str
    run_id: str
    track_dir: Path
    repo_dir: Path
    worklog_path: Path
    trace_output_dir: Path
    selected_runs_dir: Path
    runs_dir: Path
    base_run_dir: Path
    run_dir: Path
    build_targets_csv: Path
    manual_line_truth_csv: Path
    pulse_taint_config: Path
    outputs_link: Path
    artifact_output_root: Path
    artifact_run_dir: Path


def resolve_case_run_paths(
    case_dir: Path,
    *,
    track: str,
    run_id: str,
    artifact_root: Path | None = None,
) -> CaseRunPaths:
    normalized_case_dir = case_dir.resolve()
    if not normalized_case_dir.exists():
        raise ValueError(f'Case directory not found: {normalized_case_dir}')
    if track not in TRACK_NAMES:
        raise ValueError(f'Unsupported track: {track}')

    resolved_artifact_root = (artifact_root or Path(EXTERNAL_RUNS_DIR)).resolve()
    track_dir = normalized_case_dir / track
    runs_dir = track_dir / 'runs'
    run_dir = runs_dir / run_id

    return CaseRunPaths(
        case_dir=normalized_case_dir,
        case_id=normalized_case_dir.name,
        track=track,
        run_id=run_id,
        track_dir=track_dir,
        repo_dir=track_dir / 'repo',
        worklog_path=track_dir / 'WORKLOG.md',
        trace_output_dir=track_dir / 'trace_output',
        selected_runs_dir=track_dir / 'trace_output' / 'selected_runs',
        runs_dir=runs_dir,
        base_run_dir=runs_dir / 'base-run',
        run_dir=run_dir,
        build_targets_csv=run_dir / 'build_targets.csv',
        manual_line_truth_csv=run_dir / 'manual_line_truth.csv',
        pulse_taint_config=run_dir / 'pulse-taint-config.json',
        outputs_link=run_dir / 'outputs',
        artifact_output_root=resolved_artifact_root / normalized_case_dir.name / track,
        artifact_run_dir=resolved_artifact_root / normalized_case_dir.name / track / run_id,
    )


def infer_project_name_from_repo(repo_dir: Path) -> str:
    source_root = repo_dir.resolve()
    if source_root.name == 'raw_code' and source_root.parent.name:
        return source_root.parent.name
    if source_root.name != 'repo':
        return source_root.name

    origin_url = _read_git_origin_url(source_root)
    if origin_url:
        project_name = _project_name_from_git_url(origin_url)
        if project_name:
            return project_name

    return source_root.parent.name or source_root.name


def ensure_relative_symlink(link_path: Path, target_path: Path) -> None:
    normalized_link = link_path
    normalized_target = target_path.resolve()
    relative_target = Path(os.path.relpath(normalized_target, start=normalized_link.parent))

    if normalized_link.is_symlink():
        if normalized_link.resolve() == normalized_target:
            return
        normalized_link.unlink()
    elif normalized_link.exists():
        raise FileExistsError(f'Cannot replace non-symlink path: {normalized_link}')
    else:
        normalized_link.parent.mkdir(parents=True, exist_ok=True)

    normalized_link.symlink_to(relative_target, target_is_directory=normalized_target.is_dir())


def _read_git_origin_url(repo_dir: Path) -> str | None:
    git_config = repo_dir / '.git' / 'config'
    if not git_config.exists():
        return None

    in_origin = False
    for raw_line in git_config.read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith('['):
            in_origin = line == '[remote "origin"]'
            continue
        if not in_origin:
            continue

        match = REMOTE_URL_RE.match(raw_line)
        if match:
            return match.group('url')
    return None


def _project_name_from_git_url(raw_url: str) -> str:
    cleaned = raw_url.rstrip('/')
    if not cleaned:
        return ''

    tail = cleaned.rsplit(':', maxsplit=1)[-1] if '://' not in cleaned else cleaned
    name = tail.rsplit('/', maxsplit=1)[-1]
    if name.endswith('.git'):
        name = name[:-4]
    return name
