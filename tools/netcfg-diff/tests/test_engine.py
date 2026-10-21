import random

from netcfg_diff.diff import Differ, lis_indices, summarize
from netcfg_diff.model import Node, compress_ints, display, prune


def tree(spec, ordered=False):
    """Build a tree from nested lists: ["a", ("b", ["c"])]."""
    root = Node("<root>", ordered=ordered)
    for item in spec:
        if isinstance(item, tuple):
            text, kids = item
            n = root.add(Node(text))
            for k in kids:
                n.add(Node(k))
        else:
            root.add(Node(item))
    return root


def test_lis_indices():
    assert lis_indices([]) == []
    seq = [3, 1, 2, 5, 4, 6]
    idx = lis_indices(seq)
    vals = [seq[i] for i in idx]
    assert vals == sorted(vals) and len(vals) == 4


def test_lis_random_is_increasing_and_maximal():
    rnd = random.Random(7)
    for _ in range(200):
        seq = rnd.sample(range(50), rnd.randint(0, 30))
        idx = lis_indices(seq)
        vals = [seq[i] for i in idx]
        assert vals == sorted(vals) and idx == sorted(idx)
        # brute-force length check
        best = [1] * len(seq)
        for i in range(len(seq)):
            for j in range(i):
                if seq[j] < seq[i]:
                    best[i] = max(best[i], best[j] + 1)
        assert len(vals) == (max(best) if seq else 0)


def test_unordered_add_remove_and_recurse():
    left = tree([("interface A", ["description x", "shutdown"]), "hostname r1"])
    right = tree(["hostname r1", ("interface A", ["shutdown", "mtu 9000"]), "ip routing"])
    changes = Differ().diff(left, right)
    ops = [(c.op, c.path, c.node.text) for c in changes]
    assert ("remove", ("interface A",), "description x") in ops
    assert ("add", ("interface A",), "mtu 9000") in ops
    assert ("add", (), "ip routing") in ops
    assert len(ops) == 3  # reordering of unordered statements is not a change


def test_ordered_move_detection():
    left = tree(["a", "b", "c", "d"], ordered=True)
    right = tree(["d", "a", "b", "c"], ordered=True)
    changes = Differ().diff(left, right)
    assert [(c.op, c.node.text) for c in changes] == [("move", "d")]
    assert changes[0].detail["from"] == 4 and changes[0].detail["to"] == 1
    assert changes[0].detail["before"] == "a"
    assert Differ(ignore_order=True).diff(left, right) == []


def test_ordered_add_records_position_and_tail():
    left = tree(["a", "c"], ordered=True)
    right = tree(["a", "b", "c", "z"], ordered=True)
    adds = [c for c in Differ().diff(left, right) if c.op == "add"]
    assert [(c.node.text, c.detail["position"], c.detail["tail"]) for c in adds] == [
        ("b", 2, False),
        ("z", 4, True),
    ]
    assert adds[0].detail["after"] == "a"


def test_duplicate_keys_match_in_order():
    left = tree(["remark x", "permit a", "remark x"], ordered=True)
    right = tree(["remark x", "permit a"], ordered=True)
    changes = Differ().diff(left, right)
    assert [(c.op, c.node.text, c.detail.get("position")) for c in changes] == [("remove", "remark x", 3)]


def test_modify_by_key_and_members():
    left, right = Node("<root>"), Node("<root>")
    left.add(Node("description a", key="description"))
    right.add(Node("description b", key="description"))
    left.add(Node("set member a b", key="set member", members=("a", "b")))
    right.add(Node("set member b c a", key="set member", members=("b", "c", "a")))
    right.add(Node("set x 1", key="set x"))
    changes = Differ().diff(left, right)
    mods = [c for c in changes if c.op == "modify"]
    assert mods[0].before.text == "description a" and mods[0].after.text == "description b"
    assert mods[1].detail == {"added": ["c"], "removed": []}
    # same members in another order: no change
    left2, right2 = Node("<root>"), Node("<root>")
    left2.add(Node("set m a b", key="set m", members=("a", "b")))
    right2.add(Node("set m b a", key="set m", members=("b", "a")))
    assert Differ().diff(left2, right2) == []


def test_pair_leaves_and_activation():
    left, right = Node("<root>"), Node("<root>")
    left.add(Node("host-name")).add(Node("r1"))
    right.add(Node("host-name")).add(Node("r2"))
    a = left.add(Node("ge-0/0/1", inactive=True))
    b = right.add(Node("ge-0/0/1"))
    a.add(Node("mtu")).add(Node("9000"))
    b.add(Node("mtu")).add(Node("9000"))
    changes = Differ(pair_leaves=True).diff(left, right)
    assert [(c.op, c.path) for c in changes] == [("modify", ("host-name",)), ("activate", ())]
    # without pairing it is a removal plus an addition
    assert [c.op for c in Differ().diff(left, right)][:2] == ["remove", "add"]
    assert summarize(changes)["total"] == 2


def test_prune_and_helpers():
    root = tree([("interface A", ["description x", "ntp clock-period 1"]), "ntp clock-period 2"])
    import re

    assert prune(root, [re.compile(r"^ntp clock-period")]) == 2
    assert [c.text for c in root.children] == ["interface A"]
    assert [c.text for c in root.children[0].children] == ["description x"]
    assert compress_ints([5, 1, 2, 3, 7, 8, 10]) == "1-3,5,7-8,10"
    assert compress_ints([]) == ""
    assert display("a\nb") == "a\\nb"
    assert display("x" * 500).endswith("[500 chars]")
