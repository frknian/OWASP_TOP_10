from typing import Generator

import httpx
import pytest

from tests.helpers.process_manager import ProcessManager
from tests.helpers.scenario_loader import get_scenario_path


def _make_client_fixture(module_dir: str, scenario_dir: str, variant: str, port: int) -> Generator[httpx.Client, None, None]:
    """Helper function to spin up a scenario backend and yield an HTTP client."""
    path = get_scenario_path(module_dir, scenario_dir, variant)
    pm = ProcessManager(port=port, workdir=path)
    pm.start()
    # Use httpx.Client to manage a session / connections
    client = httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=10.0)
    try:
        yield client
    finally:
        client.close()
        pm.stop()

@pytest.fixture
def idor_vulnerable_client() -> Generator[httpx.Client, None, None]:
    yield from _make_client_fixture("01-broken-access-control", "01-idor-horizontal-privilege-escalation", "vulnerable", 8000)

@pytest.fixture
def idor_fixed_client() -> Generator[httpx.Client, None, None]:
    yield from _make_client_fixture("01-broken-access-control", "01-idor-horizontal-privilege-escalation", "fixed", 8001)

@pytest.fixture
def sqli_vulnerable_client() -> Generator[httpx.Client, None, None]:
    yield from _make_client_fixture("05-injection", "01-sql-injection-string-concatenation", "vulnerable", 8120)

@pytest.fixture
def sqli_fixed_client() -> Generator[httpx.Client, None, None]:
    yield from _make_client_fixture("05-injection", "01-sql-injection-string-concatenation", "fixed", 8121)

@pytest.fixture
def xss_vulnerable_client() -> Generator[httpx.Client, None, None]:
    yield from _make_client_fixture("05-injection", "04-reflected-xss", "vulnerable", 8150)

@pytest.fixture
def xss_fixed_client() -> Generator[httpx.Client, None, None]:
    yield from _make_client_fixture("05-injection", "04-reflected-xss", "fixed", 8151)

@pytest.fixture
def stuffing_vulnerable_client() -> Generator[httpx.Client, None, None]:
    yield from _make_client_fixture("07-authentication-failures", "01-credential-stuffing-no-protection", "vulnerable", 8190)

@pytest.fixture
def stuffing_fixed_client() -> Generator[httpx.Client, None, None]:
    yield from _make_client_fixture("07-authentication-failures", "01-credential-stuffing-no-protection", "fixed", 8191)

@pytest.fixture
def failopen_vulnerable_client() -> Generator[httpx.Client, None, None]:
    yield from _make_client_fixture("10-mishandling-exceptional-conditions", "02-fail-open-authentication", "vulnerable", 8290)

@pytest.fixture
def failopen_fixed_client() -> Generator[httpx.Client, None, None]:
    yield from _make_client_fixture("10-mishandling-exceptional-conditions", "02-fail-open-authentication", "fixed", 8291)
