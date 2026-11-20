#!/usr/bin/env bash
# Interoperability lab: runs ntp-skew against real chronyd servers on
# loopback addresses. Requires chronyd and libfaketime; never touches the
# system clock (chronyd -x) and binds unprivileged ports.
#
#   127.0.0.1-3  healthy servers (local stratum 2-4)
#   127.0.0.4    falseticker: libfaketime shifts its clock by +1.5s
#   127.0.0.5    rate limiting: drops requests closer than 16s (ratelimit)
#   127.0.0.6    unsynchronised (no reference at all)
#
# Usage: lab/chrony-lab.sh [path/to/ntp-skew]
set -euo pipefail

bin=${1:-}
here=$(cd "$(dirname "$0")/.." && pwd)
if [[ -z $bin ]]; then
	bin=$(mktemp)
	(cd "$here" && go build -o "$bin" .)
fi
command -v chronyd >/dev/null || { echo "chronyd not found" >&2; exit 3; }
faketime_lib=$(find /usr/lib* -name 'libfaketimeMT.so.1' 2>/dev/null | head -n1 || true)
[[ -n $faketime_lib ]] || { echo "libfaketime not found" >&2; exit 3; }

work=$(mktemp -d)
cleanup() {
	for p in "$work"/*.pid; do
		if [[ -f $p ]]; then
			kill "$(cat "$p")" 2>/dev/null || true
		fi
	done
	rm -rf "$work"
}
trap cleanup EXIT

start() { # index extra-config [env...]
	local i=$1 extra=$2
	shift 2
	printf 'port 1112%s\nbindaddress 127.0.0.%s\nallow 127.0.0.0/8\ncmdport 0\npidfile %s/c%s.pid\n%b\n' \
		"$i" "$i" "$work" "$i" "$extra" >"$work/c$i.conf"
	env "$@" chronyd -x -f "$work/c$i.conf" -l "$work/c$i.log"
}

start 1 'local stratum 2'
start 2 'local stratum 3'
start 3 'local stratum 4'
start 4 'local stratum 2' FAKETIME=+1.5 LD_PRELOAD="$faketime_lib"
start 5 'local stratum 2\nratelimit interval 4 burst 1'
start 6 ''
sleep 1

rc=0
"$bin" --samples 3 --interval 300ms \
	127.0.0.1:11121 127.0.0.2:11122 127.0.0.3:11123 127.0.0.4:11124 127.0.0.5:11125 127.0.0.6:11126 || rc=$?
echo "exit code: $rc (expected 2: one falseticker)"
[[ $rc -eq 2 ]]
