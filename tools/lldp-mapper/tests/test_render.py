from lldp_mapper.model import Device, Endpoint, Link, Node
from lldp_mapper.render import exit_code, render_dot, render_mermaid
from lldp_mapper.topology import Topology


def tricky_topology():
    t = Topology()
    t.nodes["a"] = Node("a", 'sw "core" <1>|x', polled=True, target="10.0.0.1")
    t.nodes["end"] = Node("end", "end", mgmt_addrs=["10.0.0.9"])
    t.links = [Link(Endpoint("a", 'Gi1/0/1 "x"'), Endpoint("end", "eth|0"), ["lldp"], ["a"], ["duplex-mismatch"])]
    t.devices = [Device(target="10.0.0.1")]
    return t


def test_mermaid_escapes_labels_and_reserved_ids():
    m = render_mermaid(tricky_topology())
    assert 'n_a["sw #quot;core#quot; #lt;1#gt;#124;x<br/><small>10.0.0.1</small>"]' in m
    assert "n_end([" in m  # "end" would break Mermaid as a bare node id
    assert '-.-|"Gi1/0/1 #quot;x#quot; — eth#124;0"|' in m
    assert "linkStyle 0 stroke:#d62728" in m


def test_dot_escapes_labels():
    d = render_dot(tricky_topology())
    assert 'label="sw \\"core\\" <1>|x\\n10.0.0.1"' in d
    assert 'taillabel="Gi1/0/1 \\"x\\""' in d and "style=dashed" in d


def test_exit_code_all_failed_is_unknown():
    t = tricky_topology()
    t.devices = [Device(target="x", error="down")]
    assert exit_code(t, []) == 3
