"""Test session configuration for async backend determinism.

Rationale:
- Aegis code and tests are implemented with asyncio-native primitives.
- In environments where Trio is installed, pytest-anyio may auto-run the same
  tests on Trio and trigger backend-mismatch failures unrelated to product
  behavior (for example: no running asyncio loop).
- Default to asyncio for deterministic CI/local runs.
- Allow explicit multi-backend runs via AEGIS_TEST_ALL_BACKENDS=1.
"""

import os
import pytest


@pytest.fixture
def anyio_backend(request) -> str:
    """Return the backend to use for AnyIO-marked tests.

    Default: asyncio only.
    Optional: set AEGIS_TEST_ALL_BACKENDS=1 to run asyncio and trio.
    """
    if os.getenv("AEGIS_TEST_ALL_BACKENDS") == "1":
        return request.param
    return "asyncio"


def pytest_generate_tests(metafunc) -> None:
    if "anyio_backend" not in metafunc.fixturenames:
        return
    if os.getenv("AEGIS_TEST_ALL_BACKENDS") == "1":
        metafunc.parametrize("anyio_backend", ["asyncio", "trio"], indirect=True)
