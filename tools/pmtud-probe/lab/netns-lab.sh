#!/usr/bin/env bash
# End-to-end lab for pmtud-probe: builds a three-namespace topology
#
#   cli (10.99.1.2) --1500-- rtr (10.99.1.1 | 10.99.2.1) --MTU-- srv (10.99.2.2)
#
# and runs pmtud-probe from "cli" against "srv" in several scenarios
# (working PMTUD, black hole, MSS clamping, rejected oversize packets,
# local route MTU), asserting on the JSON output and the exit code.
#
# Requires root (ip netns), iproute2, nftables, python3 and Go. It only
# touches the namespaces it creates (prefix "pmtulab-") and removes them on
# exit. Usage: sudo lab/netns-lab.sh   (PMTULAB_SHOW=1 also prints the text reports)
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
ns_cli=pmtulab-cli
ns_rtr=pmtulab-rtr
ns_srv=pmtulab-srv
work="$(mktemp -d)"
srv_pid=""

cleanup() {
	if [ -n "$srv_pid" ]; then kill "$srv_pid" 2>/dev/null || true; fi
	for ns in "$ns_cli" "$ns_rtr" "$ns_srv"; do
		ip netns del "$ns" 2>/dev/null || true
	done
	rm -rf "$work"
}
trap cleanup EXIT

for bin in ip nft python3 go; do
	command -v "$bin" >/dev/null || { echo "missing $bin" >&2; exit 3; }
done
if [ "$(id -u)" -ne 0 ]; then
	echo "run as root (needs ip netns)" >&2
	exit 3
fi

(cd "$here" && go build -o "$work/pmtud-probe" .)

ip netns add "$ns_cli"
ip netns add "$ns_rtr"
ip netns add "$ns_srv"
ip link add c0 netns "$ns_cli" type veth peer name r0 netns "$ns_rtr"
ip link add r1 netns "$ns_rtr" type veth peer name s0 netns "$ns_srv"

in_ns() { local ns="$1"; shift; ip netns exec "$ns" "$@"; }

in_ns "$ns_cli" ip addr add 10.99.1.2/24 dev c0
in_ns "$ns_rtr" ip addr add 10.99.1.1/24 dev r0
in_ns "$ns_rtr" ip addr add 10.99.2.1/24 dev r1
in_ns "$ns_srv" ip addr add 10.99.2.2/24 dev s0
for pair in "$ns_cli:c0" "$ns_rtr:r0" "$ns_rtr:r1" "$ns_srv:s0"; do
	in_ns "${pair%%:*}" ip link set "${pair#*:}" up
	in_ns "${pair%%:*}" ip link set lo up
done
in_ns "$ns_cli" ip route add default via 10.99.1.1
in_ns "$ns_srv" ip route add default via 10.99.2.1
in_ns "$ns_rtr" sysctl -qw net.ipv4.ip_forward=1
# Allow unprivileged ICMP sockets in the client namespace.
in_ns "$ns_cli" sysctl -qw net.ipv4.ping_group_range="0 2147483647"
# Do not let the router rate-limit the ICMP errors the tests depend on.
in_ns "$ns_rtr" sysctl -qw net.ipv4.icmp_ratelimit=0
in_ns "$ns_srv" sysctl -qw net.ipv4.icmp_ratelimit=0

# TCP listener on srv:8443 (accepts and closes).
in_ns "$ns_srv" python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.99.2.2", 8443)); s.listen(16)
while True:
    c, _ = s.accept(); c.close()
' >/dev/null 2>&1 &
srv_pid=$!
sleep 0.5

# The constriction is the router's egress towards srv (think of a tunnel);
# srv keeps a 1500-byte interface, so it advertises a 1460-byte TCP MSS.
set_mtu() {
	in_ns "$ns_rtr" ip link set r1 mtu "$1"
}

rtr_rules() {
	in_ns "$ns_rtr" nft flush ruleset
	if [ -n "$1" ]; then in_ns "$ns_rtr" nft -f - <<<"$1"; fi
}

fails=0
# check NAME EXPECTED_EXIT PYTHON_ASSERTION -- ARGS...
check() {
	local name="$1" want="$2" assertion="$3"
	shift 4
	local rc=0
	# Start every scenario without the PMTU learnt by the previous one.
	in_ns "$ns_cli" ip route flush cache
	in_ns "$ns_cli" "$work/pmtud-probe" --json "$@" >"$work/out.json" 2>"$work/err.txt" || rc=$?
	if [ "$rc" -ne "$want" ]; then
		echo "FAIL $name: exit $rc, want $want"
		cat "$work/out.json" "$work/err.txt"
		fails=$((fails + 1))
		return
	fi
	if ! python3 -c "
import json, sys
r = json.load(open(sys.argv[1]))[0]
codes = {f['code']: f['severity'] for f in r['findings']}
assert $assertion, (r['path_mtu'], r['pmtud'], codes, r.get('tcp'))
" "$work/out.json"; then
		echo "FAIL $name"
		fails=$((fails + 1))
		return
	fi
	echo "ok   $name"
	if [ -n "${PMTULAB_SHOW:-}" ]; then
		in_ns "$ns_cli" ip route flush cache
		in_ns "$ns_cli" "$work/pmtud-probe" --color never "$@" | sed 's/^/     | /' || true
	fi
}

drop_ptb='table inet lab { chain labout { type filter hook output priority 0; icmp type destination-unreachable icmp code frag-needed drop; }; }'
clamp='table inet lab { chain labfwd { type filter hook forward priority 0; tcp flags syn tcp option maxseg size set rt mtu; }; }'
reject='table inet lab { chain labfwd { type filter hook forward priority 0; meta l4proto { icmp, udp } meta length > 1400 reject with icmp type admin-prohibited; }; }'

set_mtu 1500
rtr_rules ""
check "clean path (icmp)" 0 "r['path_mtu'] == 1500 and r['pmtud'] == 'not-needed' and r['method'] == 'icmp'" -- 10.99.2.2
check "clean path (udp)" 0 "r['path_mtu'] == 1500 and r['method'] == 'udp'" -- --method udp 10.99.2.2

set_mtu 1400
check "working PMTUD (icmp)" 0 "r['path_mtu'] == 1400 and r['pmtud'] == 'working' and r['ptb'][0]['from'] == '10.99.1.1'" -- 10.99.2.2
check "working PMTUD (udp)" 0 "r['path_mtu'] == 1400 and r['pmtud'] == 'working'" -- --method udp 10.99.2.2
check "unclamped MSS, PMTUD ok" 1 "codes.get('mss-not-clamped') == 'warning' and r['tcp']['peer_mss'] == 1460" -- --tcp 8443 10.99.2.2

rtr_rules "$drop_ptb"
check "black hole (icmp)" 2 "r['path_mtu'] == 1400 and r['pmtud'] == 'black-hole' and 'ptb' not in r" -- --timeout 300ms 10.99.2.2
check "black hole (udp)" 2 "r['path_mtu'] == 1400 and r['pmtud'] == 'black-hole'" -- --method udp --timeout 300ms 10.99.2.2
check "black hole + unclamped MSS" 2 "codes.get('mss-not-clamped') == 'critical'" -- --tcp 8443 --timeout 300ms 10.99.2.2

rtr_rules "$drop_ptb
$clamp"
check "black hole + clamped MSS" 2 "codes.get('mss-fits') == 'ok' and r['tcp']['peer_mss'] == 1360 and not r['tcp']['peer_mss_lower_bound']" -- --tcp 8443 --timeout 300ms 10.99.2.2

set_mtu 1500
rtr_rules "$reject"
check "oversize rejected" 1 "r['path_mtu'] == 1400 and r['pmtud'] == 'filtered'" -- --method udp 10.99.2.2

rtr_rules ""
check "expect-mtu" 1 "codes.get('unexpected-mtu') == 'warning'" -- --expect-mtu 9000 10.99.2.2
in_ns "$ns_cli" ip route replace 10.99.2.0/24 via 10.99.1.1 mtu lock 1300
check "route MTU reported, bypassed by probes" 0 "r['path_mtu'] == 1500 and r['route']['route_mtu'] == 1300 and codes.get('kernel-pmtu-cache') == 'info'" -- 10.99.2.2
in_ns "$ns_cli" ip route del 10.99.2.0/24

check "--max above the interface MTU" 0 "r['path_mtu'] == 1500 and r['pmtud'] == 'local'" -- --max 9000 10.99.2.2
check "unanswered target" 3 "codes.get('unreachable') == 'unknown'" -- --timeout 200ms --retries 0 10.99.2.99

if [ "$fails" -ne 0 ]; then
	echo "$fails scenario(s) failed"
	exit 1
fi
echo "all scenarios passed"
