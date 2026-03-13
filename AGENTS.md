# Repository Guidelines

This repository runs Infer on the Juliet C/C++ test suite and maintains the pipeline from signatures to paired traces, slices, and dataset exports. Treat this file as a map: use it to find the right code, docs, and validation commands, then prefer the smallest change that solves the task.

## Start Here
- Read `README.md` for local setup and common commands.
- Use `docs/pipeline-runbook.md` for pipeline behavior, `docs/artifacts.md` for output layout, and `docs/rerun.md` for rerun workflows.
- For stage-specific logic, open the matching `experiments/*/README.md` before editing that stage.

## Repository Map
- `tools/`: user-facing CLI scripts such as `run-epic001-pipeline.py`, `run-infer-all-juliet.py`, and rerun/export helpers.
- `tools/lib/`: shared pipeline logic. Keep CLI wrappers thin and put reusable behavior here.
- `tests/`: unit and regression tests. `tests/golden/` contains stage-level golden fixtures and fixture update tooling.
- `experiments/`: stage-specific scripts, inputs, and notes for the EPIC001 pipeline.
- `config/`: committed configuration, including `pulse-taint-config.json`.
- `artifacts/`: generated outputs only. Juliet sources live under `juliet-test-suite-v1.3/C/`.

## Minimal Change Rule
Keep code changes minimal.

Do not:
- refactor unrelated code
- reorganize repository structure
- modify or delete generated artifacts unless requested

Also:
- preserve existing CLI flags, artifact paths, and output schemas unless the task explicitly requires a change
- keep fixes focused and avoid unrelated cleanup in the same change
- if this policy later needs many exceptions or examples, keep the summary here and split detailed rules into a separate policy document

## Setup & Development
- `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
- `source .venv/bin/activate && pre-commit install`

## Validation
### Required for most Python changes
- `source .venv/bin/activate && ruff check .`
- `source .venv/bin/activate && pytest -q`

### Targeted validation
- `source .venv/bin/activate && pytest tests/test_<feature>.py -q`
- `source .venv/bin/activate && pytest tests/golden -q` for stage-output or fixture-sensitive changes
- `source .venv/bin/activate && python tests/golden/update_goldens.py --stage <stage>` only when expected outputs intentionally change

### Expensive / optional
- `source .venv/bin/activate && python tools/run-epic001-pipeline.py 78` only when end-to-end pipeline verification is necessary

## Coding Style
- Python 3.9, 4-space indentation, 100-character lines, single quotes; `ruff format` is the formatter.
- Prefer `pathlib.Path`, explicit arguments, and type hints in new code.
- Use `snake_case` for functions, variables, modules, and tests. Keep hyphenated filenames only for CLI entrypoints.

## Testing & PR Notes
- Add unit tests as `tests/test_<feature>.py`.
- Add stage regressions as `tests/golden/test_stageXX_<name>.py`.
- Follow the existing commit style: `feat(compare): ...`, `test(cli): ...`, `docs(readme): ...`, `refactor(cli): ...`.
- PRs should list affected pipeline stages, validation commands, and any fixture or artifact changes.
