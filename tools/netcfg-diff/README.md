# netcfg-diff

Semantic diff of network device configurations — Cisco IOS / IOS-XE, NX-OS,
IOS-XR, Arista EOS, Junos and FortiOS — with no third-party dependencies.

`diff -u` on two `show running-config` backups tells you that line 412 moved.
`netcfg-diff` tells you that *interface Gi0/0/1* got a new description, that
VLAN 33 was added to its trunk, that the ICMP entry of ACL `EDGE-IN` was
moved to the top (which changes what the ACL does), and that nothing else
changed — even though the interfaces were printed in a different order and
the prefix-list was resequenced.

## What makes it semantic

| Behaviour | Details |
|-----------|---------|
| Hierarchical comparison | A statement is identified by its context (`interface X` → `ip address ...`, `config firewall policy` → `edit 5` → `set action`). Changes are reported under their context. |
| Order ignored where the device ignores it | Interfaces, routing-process statements, address objects, Junos hierarchy, FortiOS `set` attributes, ... |
| Order checked where it matters | ACL entries (named, numbered, ASA-style), prefix/as-path/community lists, `policy-map` classes, IOS-XR `route-policy` bodies, banners; Junos firewall filter terms, `policy-statement` terms, security policies, NAT rules, `import`/`export` policy chains, `apply-groups`, `name-server`; FortiOS firewall policy tables (the position of an `edit` block decides which policy matches, not its ID) and router access/prefix-list rules. Reorderings are reported as **moves** (minimal set, computed with a longest-increasing-subsequence over the common entries). |
| Modifications, not remove + add | Single-valued commands (`description`, `ip address`, `mtu`, `switchport access vlan`, `ip access-group ... in`, `neighbor X remote-as`, `username X`, `shutdown` vs `no shutdown`, ...), FortiOS `set <attr>` and Junos leaves (`host-name r1` → `r2`) are reported as one modification. Any `no X` pairs with `X`. |
| Value semantics | `switchport trunk allowed vlan` lines (including `add`, `remove`, `except`, `all`, `none`) are folded into one VLAN set: `10,20` + `add 30-32` equals `10,20,30-32`, and the change says `added: 33`. FortiOS list attributes (`member`, `srcaddr`, `allowaccess`, `service`, ...) are compared as sets and the change lists the added/removed members. |
| Sequence numbers are not significant | NX-OS/IOS-XR `10 permit ...` ACL entries and `ip prefix-list ... seq N` are compared by relative order, so `resequence` is not a change, while a real reordering is. |
| Junos brace ⇔ set | Both formats parse to the same token tree, so a `show configuration` export can be compared with a `display set` export. `inactive:` / `deactivate` are tracked (activate/deactivate changes). |
| Secrets never printed | Password hashes, type-7 strings, SNMP communities and v3 keys, TACACS/RADIUS keys, IKE pre-shared keys, OSPF/BGP/NTP keys, Junos `$9$`/crypt values, FortiOS `ENC` blobs and private keys are masked **at parse time**. See [Security](#security). |
| Noise removed | `Building configuration...`, `Current configuration : N bytes`, comments, `ntp clock-period`, IOS-XR timestamps, CLI prompts, `exit-address-family`, `end-policy`, ... (`--keep-volatile` keeps the volatile ones). Extra noise can be dropped with `--ignore REGEX`. |

## Installation

Python ≥ 3.9, standard library only.

```sh
pipx install "git+https://github.com/Hug0devSYS/sysnet-toolbox.git#subdirectory=tools/netcfg-diff"

# or from a checkout
cd tools/netcfg-diff && pip install .
python -m netcfg_diff --help    # without installing: PYTHONPATH=src
```

## Usage

```
netcfg-diff [options] LEFT RIGHT

  LEFT, RIGHT            files ('-' = stdin for one side, .gz accepted), two directories,
                         or FILE DIR / DIR FILE (compares with DIR/basename(FILE), like diff(1))
  --vendor V             auto (default), ios, nxos, iosxr, eos, junos, fortios
  --format F             text (default), json, summary, set (Junos commands)
  --json                 same as --format json
  --brief                collapse added/removed blocks to one line
  --section REGEX        only report changes whose context path matches (repeatable)
  --ignore REGEX         drop matching statements and their children before comparing (repeatable)
  --ignore-file FILE     one --ignore regex per line, '#' comments
  --keep-volatile        keep ntp clock-period, timestamps, prompts
  --ignore-order         never report order changes
  --secrets MODE         mask (default) | presence | show
  --color WHEN           auto (default, honours NO_COLOR), always, never
  -q, --quiet            no output, exit code only
  --version
```

With `--section` and `--ignore`, Cisco and FortiOS regexes are matched
against the statement text (`^interface Te`); Junos `--ignore` regexes are
matched against the set-style path (`^system syslog`), and `--section`
everywhere against the space-joined context path plus the statement.

### Exit codes

Same convention as `diff(1)`, so it can gate a pipeline:

| Code | Meaning |
|------|---------|
| 0 | No semantic difference |
| 1 | Differences found (or, in directory mode, files present on one side only) |
| 2 | Error: unreadable file, parse error, incompatible dialects, bad option |

### Examples

```sh
# Two backups of the same router
netcfg-diff edge-r1.2026-10-20.cfg edge-r1.2026-10-21.cfg

# Only the interfaces, one line per added/removed interface
netcfg-diff --section '^interface ' --brief old.cfg new.cfg

# Compare a whole backup tree (RANCID / Oxidized style), one summary per device
netcfg-diff --format summary backups/2026-10-20/ backups/2026-10-21/

# Template compliance: ignore what is expected to differ per device
netcfg-diff --ignore '^hostname ' --ignore '^snmp-server location' golden-access.cfg sw-b2-14.cfg

# Junos: brace export vs display-set export, and the commands that turn one into the other
netcfg-diff --format set mx1-before.conf mx1-after.set > review-me.set

# From git history
git difftool -y -x netcfg-diff HEAD~1 -- configs/edge-r1.cfg
git show HEAD~1:configs/edge-r1.cfg | netcfg-diff - configs/edge-r1.cfg

# CI gate on a generated config
netcfg-diff -q rendered/core1.cfg deployed/core1.cfg || echo "drift detected"

# JSON for tooling
netcfg-diff --json old.conf new.conf | jq '.changes[] | select(.op == "move")'
```

### Sample output

Text (`+` added, `-` removed, `-`/`+` pair = modified, `>` moved, `~`
activated/deactivated, unprefixed lines are context; `# ...` are annotations):

```
--- ios_old.cfg (ios)
+++ ios_new.cfg (ios)
- username admin privilege 15 secret 9 <secret:1617c94d>
+ username admin privilege 15 secret 9 <secret:491dcdf9>
  interface GigabitEthernet0/0/1
-   description LAN
+   description LAN-Core
-   switchport trunk allowed vlan 10,20,30-32
+   switchport trunk allowed vlan 10,20,30-33  # added: 33
-   shutdown
+   no shutdown
  interface GigabitEthernet0/0/0
-   ip access-group EDGE-IN in
+   ip access-group EDGE-IN-V2 in
+ interface Vlan40
+   description Guest
+   ip address 10.40.0.1 255.255.255.0
  ip access-list extended EDGE-IN
>   permit icmp any any echo-reply  # moved from position 3 to 1
- snmp-server location DC1 rack 12
+ snmp-server location DC1 rack 14
  line vty 0 4
-   exec-timeout 10 0
+   exec-timeout 5 0
9 change(s): 1 added, 7 modified, 1 moved
```

The two inputs also differed by interface order, OSPF statement order, a
resequenced prefix-list, `switchport trunk allowed vlan add` syntax, the
configuration-size header and `ntp clock-period` — none of which is reported.

FortiOS:

```
  config system interface
    edit "internal"
-     set allowaccess ping https ssh http
+     set allowaccess ping https ssh  # removed: http
  config firewall addrgrp
    edit "dmz-servers"
-     set member "srv-web" "srv-mail"
+     set member "srv-mail" "srv-web" "srv-dns"  # added: srv-dns
  config firewall policy
>   edit 2  # moved from position 2 to 1
    edit 1
+     set logtraffic all
```

Junos (brace file on the left, `display set` file on the right):

```
- set system host-name mx-edge1
+ set system host-name mx-edge1-new
> insert system name-server 192.0.2.54 before 192.0.2.53  # moved from position 2 to 1
- set system services telnet
+ set system services netconf ssh
~ activate interfaces ge-0/0/1
+ set interfaces ge-0/0/2 unit 0 family inet address 10.2.0.1/24
~ deactivate interfaces ge-0/0/2
> insert firewall family inet filter PROTECT-RE term icmp before term ssh  # moved from position 3 to 1
+ set firewall family inet filter PROTECT-RE term ntp from protocol udp  # inserted at position 4
+ set firewall family inet filter PROTECT-RE term ntp from port ntp
+ set firewall family inet filter PROTECT-RE term ntp then accept
> insert protocols bgp group ISP-A export DEFAULT-DENY before EXPORT-ISP  # moved from position 2 to 1
9 change(s): 3 added, 1 removed, 1 modified, 3 moved, 1 activated
```

`--format set` prints the same change as a command list, deletes first,
then sets, inserts and (de)activations:

```
delete system host-name
delete system services telnet
set system host-name mx-edge1-new
set system services netconf ssh
set interfaces ge-0/0/2 unit 0 family inet address 10.2.0.1/24
set firewall family inet filter PROTECT-RE term ntp from protocol udp
...
insert firewall family inet filter PROTECT-RE term icmp before term ssh
insert firewall family inet filter PROTECT-RE term ntp after term bgp
insert protocols bgp group ISP-A export DEFAULT-DENY before EXPORT-ISP
activate interfaces ge-0/0/1
deactivate interfaces ge-0/0/2
```

The test-suite applies generated command lists to the left tree with a
Junos candidate-configuration simulator and checks that the result equals
the right tree (fixtures plus 500 random reorderings).

Summary (`--format summary`):

```
ios_old.cfg -> ios_new.cfg (ios)
  section                              +     -     ~     >
  (global)                             0     0     2     0
  interface GigabitEthernet0/0/1       0     0     3     0
  interface GigabitEthernet0/0/0       0     0     1     0
  interface Vlan40                     1     0     0     0
  ip access-list extended EDGE-IN      0     0     0     1
  line vty 0 4                         0     0     1     0
9 change(s): 1 added, 7 modified, 1 moved
```

JSON (`--json`), one object per change:

```json
{
  "op": "modify",
  "section": "interface GigabitEthernet0/0/1",
  "path": ["interface GigabitEthernet0/0/1"],
  "statement": "switchport trunk allowed vlan 10,20,30-33",
  "before": "switchport trunk allowed vlan 10,20,30-32",
  "after": "switchport trunk allowed vlan 10,20,30-33",
  "detail": { "added": [33], "added_ranges": "33" }
}
```

`op` is one of `add`, `remove`, `modify`, `move`, `activate`, `deactivate`.
`add`/`remove` carry the full block in `lines`; moves carry `from`/`to`
positions and the `after`/`before` anchor; Junos changes carry `commands`.
The document also has `left`/`right` (vendor, detected OS version, input
format, number of ignored statements), `identical` and `summary` counts.
Directory mode returns `pairs`, `only_left`, `only_right`, `errors` and a
global `summary`.

### Directory mode

Files are paired by relative path (hidden files and directories such as
`.git` are skipped). Each pair is detected and compared independently; a
parse error in one file is reported on stderr and in `errors`, and the run
continues (exit code 2 at the end).

## Limitations

- The parsers are syntax-driven, not model-driven: there is no per-platform
  command schema. The list of single-valued commands is curated
  (`KEY_RULES` in `cisco.py`); a single-valued command that is not in it is
  shown as a removal plus an addition, which is still correct, just less
  compact. Unknown sections are compared hierarchically like any other.
- Defaults are not known: `no shutdown` on one side and nothing on the other
  is a difference, even if the platform default is the same. Compare
  configurations produced the same way (both `show running-config`, or both
  `show running-config all`).
- Junos: in `--format set`, a modified single leaf is emitted as
  `delete <leaf>` + `set <leaf> <new value>`; review the output before
  loading it (`load set terminal` / `load set` + `show | compare`). It is a
  review aid, never applied by this tool. `groups` are compared as written,
  not expanded (`| display inheritance` exports work).
- Junos statements are tokens: a value whose keyword is not a single token
  in the tree (for example a changed `description`) is a modification of the
  leaf; a changed identifier (`unit 0` → `unit 1`) is a removal and an
  addition of the whole block.
- Cisco: interface names are compared as written (`Gi0/1` and
  `GigabitEthernet0/1` differ); whitespace inside a line is collapsed; a
  context opened twice in the file is merged. Macro and banner bodies are
  compared line by line.
- FortiOS: list attributes not in `LIST_ATTRS` are compared in order.
  `ENC` values may be re-salted between two exports of an unchanged
  configuration on some releases; use `--secrets presence` if that creates
  noise.
- Inputs above 64 MiB are refused. Files are read as UTF-8 (a BOM is
  skipped); files that are not valid UTF-8 are read as Windows-1252, so a
  legacy-encoded backup compares equal to its UTF-8 re-export.

## Security

- Read-only: the tool only reads the two files or directories; it never
  connects to a device.
- Secrets are replaced while parsing, before any comparison or output, so no
  output format (text, JSON, summary, Junos commands) can contain them. In the
  default `mask` mode a secret becomes `<secret:xxxxxxxx>`, the first 32 bits
  of an HMAC-SHA256 keyed with 32 random bytes generated for each run: two
  equal secrets get the same tag *within* a run (so a password change is
  visible), but tags are not comparable across runs and cannot be used for an
  offline dictionary attack. `--secrets presence` ignores secret values
  entirely; `--secrets show` disables masking and should only be used on a
  trusted terminal. Already-masked values (`<secret:...>`) are left as is,
  so the output can be fed back in.
- The masking rules are pattern based (see `masking.py`). They err on the
  side of masking too much (for example a word following `password` in a
  description). Treat configuration backups themselves as sensitive: masking
  protects the diff output, not the input files.
- Regular expressions given with `--ignore`/`--section` are applied to every
  statement; avoid catastrophic-backtracking patterns on very large inputs.

## Development

```sh
cd tools/netcfg-diff
pip install -e ".[test]" ruff
ruff check . && ruff format --check . && pytest -q
```
