import importlib
import sys
import types
from pathlib import Path
from typing import Dict
from typing import Optional

import pytest


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def install_stub_module(name: str, **attributes):
    module = types.ModuleType(name)
    for key, value in attributes.items():
        setattr(module, key, value)
    sys.modules[name] = module
    return module


@pytest.fixture
def load_service_module():
    def _load(name: str, *, stubs: Optional[Dict[str, dict]] = None):
        for module_name in list(sys.modules):
            if module_name == f"app.services.{name}":
                del sys.modules[module_name]

        for module_name, attributes in (stubs or {}).items():
            install_stub_module(module_name, **attributes)

        return importlib.import_module(f"app.services.{name}")

    return _load


def remove_service_module(name: str):
    for module_name in list(sys.modules):
        if module_name == f"app.services.{name}":
            del sys.modules[module_name]
