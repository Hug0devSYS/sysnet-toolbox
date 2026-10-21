import random

import pytest
from conftest import read_fixture

from netcfg_diff import junos
from netcfg_diff.cli import diff_configs
from netcfg_diff.loader import load
from netcfg_diff.model import Node, ParseError
from netcfg_diff.render import junos_commands


def to_set(cfg):
    lines = ["set " + " ".join(p[1:]) for p in cfg.root.leaf_paths() if len(p) > 1]

    def inactive(node, prefix):
        for c in node.children:
            here = prefix + (c.text,)
            if c.inactive:
                lines.append("deactivate " + " ".join(here))
            inactive(c, here)

    inactive(cfg.root, ())
    return "\n".join(lines) + "\n"


def apply(root: Node, commands):
    """Minimal Junos candidate-config simulator for set/delete/insert/(de)activate."""
    for cmd in commands:
        words = [v for k, v, _ in junos.tokenize(cmd) if k == "w"]
        verb, rest = words[0], words[1:]
        if verb == "set":
            node, path = root, []
            for w in rest:
                path.append(w)
                child = node.find(w)
                if child is None:
                    child = node.add(Node(w, ordered=junos._is_ordered(path)))
                node = child
        elif verb == "delete":
            parent = _walk(root, rest[:-1])
            parent.children.remove(parent.find(rest[-1]))
            parent.reindex()
            # Junos removes containers left empty by a delete
            _drop_empty(root)
        elif verb == "insert":
            pos = max(i for i, w in enumerate(rest) if w in ("before", "after"))
            where, ref = rest[pos], rest[-1]
            parent = _walk(root, rest[: pos - 1])
            item = parent.find(rest[pos - 1])
            parent.children.remove(item)
            idx = parent.children.index(parent.find(ref))
            parent.children.insert(idx + (where == "after"), item)
            parent.reindex()
        elif verb in ("activate", "deactivate"):
            _walk(root, rest).inactive = verb == "deactivate"
        else:
            raise AssertionError(cmd)


def _walk(root, words):
    node = root
    for w in words:
        node = node.find(w)
        assert node is not None, words
    return node


def _drop_empty(node):
    for c in list(node.children):
        if c.children or c.key in ("<keep>",):
            _drop_empty(c)
            if not c.children:
                node.children.remove(c)
    node.reindex()


def test_brace_and_set_formats_are_equivalent(masker):
    brace = load(read_fixture("junos_old.conf"), "junos", masker)
    assert brace.meta["format"] == "brace" and brace.meta["version"] == "22.4R3.25"
    as_set = load(to_set(brace), "junos", masker)
    assert as_set.meta["format"] == "set"
    assert diff_configs(brace, as_set) == []


def test_brace_details(masker):
    cfg = load(read_fixture("junos_old.conf"), "junos", masker)
    root = cfg.root
    ge1 = root.find("interfaces").find("ge-0/0/1")
    assert ge1.inactive
    export = root.find("protocols").find("bgp").find("group").find("ISP-A").find("export")
    assert export.ordered and [c.text for c in export.children] == ["EXPORT-ISP", "DEFAULT-DENY"]
    desc = root.find("interfaces").find("ge-0/0/0").find("description")
    assert desc.children[0].text == '"Uplink to ISP A"'
    term = root.find("firewall").find("family").find("inet").find("filter").find("PROTECT-RE").find("term")
    assert term.ordered and [c.text for c in term.children] == ["ssh", "bgp", "icmp", "default-deny"]
    pw = root.find("system").find("root-authentication").find("encrypted-password").children[0].text
    assert pw.startswith("<secret:")
    community = root.find("snmp").find("community").children[0].text
    assert community.startswith("<secret:")


def test_fixture_diff_and_patch_roundtrip(masker):
    old = load(read_fixture("junos_old.conf"), "junos", masker)
    new = load(read_fixture("junos_new.set"), "junos", masker)
    chs = diff_configs(old, new)
    got = {(c.op, " ".join(c.path + (c.node.text,))) for c in chs}
    assert ("modify", "system host-name mx-edge1-new") in got
    assert ("move", "system name-server 192.0.2.54") in got
    assert ("move", "firewall family inet filter PROTECT-RE term icmp") in got
    assert ("add", "firewall family inet filter PROTECT-RE term ntp") in got
    assert ("activate", "interfaces ge-0/0/1") in got
    assert ("remove", "system services telnet") in got
    cmds = junos_commands(chs)
    assert "delete system host-name" in cmds
    assert "insert firewall family inet filter PROTECT-RE term ntp after term bgp" in cmds
    assert "insert protocols bgp group ISP-A export DEFAULT-DENY before EXPORT-ISP" in cmds
    apply(old.root, cmds)
    assert diff_configs(old, new) == []


def _terms_config(terms):
    return (
        "".join(f"set firewall filter F term {t} then accept\n" for t in terms) + "set system host-name r\n"
    )


def test_random_ordered_patch_roundtrip(masker):
    rnd = random.Random(42)
    names = [f"t{i}" for i in range(12)]
    for _ in range(500):
        left = rnd.sample(names, rnd.randint(0, 8))
        right = rnd.sample(names, rnd.randint(1, 8))
        a, b = load(_terms_config(left), "junos", masker), load(_terms_config(right), "junos", masker)
        apply(a.root, junos_commands(diff_configs(a, b)))
        assert diff_configs(a, b) == [], (left, right)
        term = a.root.find("firewall").find("filter").find("F").find("term")
        assert [c.text for c in term.children] == right


def test_comments_lists_and_flags(masker):
    text = """
/* annotation */
system {
    # comment
    host-name "r1"; /* trailing */
    syslog {
        file messages { any notice; }
    }
}
protect: policy-options {
    prefix-list PL { 10.0.0.0/8; 192.168.0.0/16; }
}
routing-options { static { route 0.0.0.0/0 next-hop [ 192.0.2.1 192.0.2.2 ]; } }
"""
    cfg = junos.parse(text, masker=masker)
    paths = {" ".join(p[1:]) for p in cfg.root.leaf_paths()}
    assert "system host-name r1" in paths
    assert "system syslog file messages any notice" in paths
    assert "policy-options prefix-list PL 192.168.0.0/16" in paths
    assert "routing-options static route 0.0.0.0/0 next-hop 192.0.2.2" in paths


@pytest.mark.parametrize(
    "text,line",
    [
        ("system {\n host-name r1;\n", 2),
        ("system {\n host-name r1\n}\n", 3),
        ("}\n", 1),
        ('system { host-name "r1; }\n', 1),
        ("system { foo [ a b ; }\n", 1),
    ],
)
def test_brace_errors(text, line, masker):
    with pytest.raises(ParseError) as exc:
        junos.parse(text, masker=masker)
    assert exc.value.line == line


def test_set_format_errors_and_noise(masker):
    with pytest.raises(ParseError) as exc:
        junos._parse_set(["set system host-name r", "rollback 1"], junos._Builder(masker))
    assert exc.value.line == 2
    cfg = junos.parse(
        "{master}\nuser@r1> show configuration | display set\nset system host-name r1\n", masker=masker
    )
    assert cfg.meta["format"] == "set"


def test_ignore_on_path_drops_emptied_containers(masker):
    import re

    a = load(
        "set system host-name r\nset system ntp server 192.0.2.1\n",
        "junos",
        masker,
        [re.compile(r"^system ntp")],
    )
    assert [c.text for c in a.root.find("system").children] == ["host-name"]
    b = load("set system host-name r\n", "junos", masker)
    assert diff_configs(a, b) == []
