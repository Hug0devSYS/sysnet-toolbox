import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from netcfg_diff.masking import Masker  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture_path(name: str) -> str:
    return os.path.join(FIXTURES, name)


def read_fixture(name: str) -> str:
    with open(fixture_path(name), encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture
def masker():
    return Masker("mask", key=b"k" * 32)
