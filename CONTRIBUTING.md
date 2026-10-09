# Contributing

Thanks for helping improve sysnet-toolbox.

## Ground rules

- **Defensive scope only**: diagnostics, auditing, administration, automation.
  Pull requests adding offensive capabilities (exploitation, brute force,
  authentication bypass, detection evasion, third-party data collection) will
  be closed.
- Tools are **read-only by default**; state-changing actions need an explicit
  `--apply`-style flag.
- No secrets in code, tests or examples. Use environment variables or files
  referenced by flags.
- All code, comments and documentation are written in English.

## Adding or changing a tool

1. Work in `tools/<tool-name>/` with its own dependency manifest
   (`go.mod`, `pyproject.toml`, ...), a `README.md` (purpose, install, usage,
   sample output, limitations, security) and real unit tests that mock network
   and system calls.
2. Provide `--help`, `--json` and meaningful exit codes.
3. Run the language checks locally before pushing:
   - Go: `gofmt -l .`, `go vet ./...`, `go test -race ./...`
   - Python: `ruff check .`, `ruff format --check .`, `pytest`
   - Bash: `shellcheck *.sh`, `bats tests` (if present)
   - PowerShell: `Invoke-ScriptAnalyzer -Recurse .`, `Invoke-Pester`
4. Update the tool table in `README.md` and add an entry to `CHANGELOG.md`.
5. Use [Conventional Commits](https://www.conventionalcommits.org/):
   `feat(dnsdoctor): ...`, `fix(tlsaudit): ...`, `docs: ...`, `chore: ...`.

Versions follow [SemVer](https://semver.org/) per tool.
