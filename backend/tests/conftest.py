import os
import sys
import tempfile
from pathlib import Path

# Always import the application from THIS checkout's backend directory.
# This prevents an older clone (for example v3.1) on PYTHONPATH from being
# imported when pytest is launched from an IDE or another working directory.
_BACKEND_ROOT = str(Path(__file__).resolve().parents[1])
if _BACKEND_ROOT in sys.path:
    sys.path.remove(_BACKEND_ROOT)
sys.path.insert(0, _BACKEND_ROOT)

# Must be set BEFORE the app is imported anywhere.
_tmp = tempfile.mkdtemp()
os.environ["SID_DB_PATH"] = os.path.join(_tmp, "test.db")
os.environ["LLM_PROVIDER"] = "mock"
os.environ["ADMIN_API_KEY"] = "vishalTiwari01"   # test-only key
os.environ.pop("DATABASE_URL", None)
os.environ.pop("VERCEL", None)

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_runtime():
    from app.services.runtime import rt
    from app.providers.mock import MockProvider
    rt.reset()
    rt.provider = MockProvider(record=True)
    yield rt
