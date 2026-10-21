from pathlib import Path

import pytest

from har_inspector.parser import load

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_path():
    def get(name: str) -> str:
        return str(FIXTURES / name)

    return get


@pytest.fixture
def load_fixture(fixture_path):
    def get(name: str):
        return load(fixture_path(name))

    return get
