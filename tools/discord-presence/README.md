# sysnet-presence

<img src="../../assets/logo-512.png" alt="sysnet-toolbox logo" width="96" align="right">

Shows the sysnet-toolbox tool you are running as **Discord Rich Presence**
on your profile, with the toolbox logo:

```
Playing sysnet-toolbox
Running netcfg-diff
Network configuration diff
00:42 elapsed                      [ sysnet-toolbox on GitHub ]
```

It is a wrapper: `sysnet-presence -- <command>` starts the command, shows
the presence while it runs, and clears it when it exits. It works with every
tool of the toolbox (Go or Python) and with any other command. Python ≥ 3.9,
standard library only.

## How it works

The Discord desktop client exposes a local IPC endpoint (a Unix socket
`discord-ipc-N` in `$XDG_RUNTIME_DIR`, `$TMPDIR` or `/tmp` on Linux and
macOS, including Flatpak and Snap installs; the named pipe
`\\.\pipe\discord-ipc-N` on Windows). `sysnet-presence` performs the RPC
handshake with your application ID and sends `SET_ACTIVITY`. Nothing is sent
over the network by this tool: Discord itself publishes the presence.

Consequences:

- The Discord **desktop** app must be running on the same computer, logged in,
  with *Settings → Activity Privacy → Share your detected activities* enabled.
  The web client and the mobile app do not expose the IPC endpoint.
- Presence cannot be shown from a server, a container or a cloud job (no
  Discord client there). It is meant for your workstation or jump host.

## One-time setup

1. Open <https://discord.com/developers/applications> → **New Application**,
   name it **`sysnet-toolbox`** (Discord shows "Playing *application name*").
2. In **Rich Presence → Art Assets**, upload
   [`assets/logo-1024.png`](../../assets/logo-1024.png) with the key
   **`logo`** (assets need a few minutes to propagate). Optionally set the
   same image as the application icon.
3. Copy the **Application ID** (General Information) and export it, e.g. in
   `~/.bashrc` or your PowerShell profile:

   ```sh
   export SYSNET_DISCORD_CLIENT_ID=123456789012345678
   ```

   ```powershell
   [Environment]::SetEnvironmentVariable("SYSNET_DISCORD_CLIENT_ID", "123456789012345678", "User")
   ```

   The application ID is public (it is not a secret), but it is yours: it is
   not hard-coded in the tool.
4. Install and test:

   ```sh
   pipx install "git+https://github.com/Hug0devSYS/sysnet-toolbox.git#subdirectory=tools/discord-presence"
   sysnet-presence --check      # shows the presence for 5 seconds
   ```

## Usage

```
sysnet-presence [options] -- COMMAND [ARGS...]
sysnet-presence [options] --hold [--duration D]
sysnet-presence [options] --check

  --client-id ID       application ID (default: $SYSNET_DISCORD_CLIENT_ID)
  --details TEXT       first line (default: "Running <tool>")
  --state TEXT         second line (default: what the tool does)
  --image KEY          large art asset key (default: logo)
  --image-text TEXT    tooltip of the large image (default: sysnet-toolbox)
  --small-image KEY    optional small art asset key
  --no-timer           hide the elapsed time
  --no-button          hide the "sysnet-toolbox on GitHub" button
  --timeout S          IPC timeout in seconds (default 2)
  -v, --verbose        report presence problems on stderr
```

Examples:

```sh
sysnet-presence -- netcfg-diff old.cfg new.cfg
sysnet-presence -- dnsdoctor example.com
sysnet-presence -- tlsaudit -f endpoints.txt --summary

# A longer session without a wrapped command
sysnet-presence --hold --details "Firewall audit" --state "DMZ ruleset review" --duration 2h

# Always on: shell aliases
alias netcfg-diff='sysnet-presence -- netcfg-diff'
alias dnsdoctor='sysnet-presence -- dnsdoctor'
alias tlsaudit='sysnet-presence -- tlsaudit'
alias nftlint='sysnet-presence -- nftlint'
```

Known toolbox tools get a description as second line (`dnsdoctor` → "DNS
zone diagnostics", `netcfg-diff` → "Network configuration diff", ...); any
other command shows "Running <name>".

### Exit codes

When wrapping a command, `sysnet-presence` returns **the command's exit
code** unchanged (126 if it is not executable, 127 if not found, 128+N if it
was killed by signal N), so it can be used in scripts and aliases. With
`--check` / `--hold`: 0 ok, 1 Discord not reachable or refused the request,
2 usage error.

## Behaviour and limits

- The wrapped command is started **before** contacting Discord: a missing,
  slow or misbehaving Discord client never delays or breaks it. Problems are
  silent unless `-v` is given.
- Ctrl-C reaches the wrapped command as usual; the presence is cleared when
  the command exits (Discord also clears it when the process ends).
- Text fields are normalised to Discord's 2–128 character limits.
- Discord shows the activity as "Playing"; the application name, not this
  tool, decides the title.
- Windows named pipes are supported but not exercised by the test-suite
  (tests run against a fake IPC server on a Unix socket).

## Security and privacy

- Only the **tool name** (the basename of the command) and its description
  are shown — never the arguments, so file names, host names, zones and
  addresses you are working on do not appear on your public profile.
  `--details` / `--state` show exactly what you type: keep customer names and
  internal host names out of them.
- No token, no OAuth, no network access: the RPC handshake only uses the
  public application ID, over the local socket owned by your user.
- Frames from Discord are size-limited (1 MiB) and parsed defensively.

## Development

```sh
cd tools/discord-presence
pip install -e ".[test]" ruff
ruff check . && ruff format --check . && pytest -q
```
