from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / 'tools'

for path in (REPO_ROOT, TOOLS_DIR):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)


def _install_typer_stub() -> None:
    if 'typer' in sys.modules:
        return

    typer_stub = types.ModuleType('typer')

    def _parameter(default=None, *args, **kwargs):
        return default

    class BadParameter(Exception):
        pass

    class Exit(Exception):
        def __init__(self, code: int = 0):
            super().__init__(code)
            self.code = code

    def run(fn):
        return fn

    typer_stub.Argument = _parameter
    typer_stub.Option = _parameter
    typer_stub.BadParameter = BadParameter
    typer_stub.Exit = Exit
    typer_stub.run = run
    sys.modules['typer'] = typer_stub


_install_typer_stub()


@pytest.fixture
def load_tools_module():
    def _load(module_name: str, filename: str):
        module_path = TOOLS_DIR / filename
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f'Failed to load module spec for: {module_path}')

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module

    return _load
