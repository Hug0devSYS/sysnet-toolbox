import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_path():
    return lambda name: str(FIXTURES / name)


@pytest.fixture
def fixture_text():
    return lambda name: (FIXTURES / name).read_text(encoding="utf-8")


def nft_doc(*objs):
    """Build a minimal `nft -j list ruleset` document."""
    return json.dumps({"nftables": [{"metainfo": {"json_schema_version": 1}}, *objs]})


def chain(name, family="inet", table="t", hook=None, policy=None, prio=0):
    c = {"family": family, "table": table, "name": name, "handle": 1}
    if hook:
        c.update({"type": "filter", "hook": hook, "prio": prio, "policy": policy or "accept"})
    return {"chain": c}


def rule(chain_name, *expr, family="inet", table="t", handle=None):
    r = {"family": family, "table": table, "chain": chain_name, "expr": list(expr)}
    if handle is not None:
        r["handle"] = handle
    return {"rule": r}


def m(left, right, op="=="):
    return {"match": {"op": op, "left": left, "right": right}}


def payload(proto, field):
    return {"payload": {"protocol": proto, "field": field}}


def meta(key):
    return {"meta": {"key": key}}


ACCEPT = {"accept": None}
DROP = {"drop": None}
