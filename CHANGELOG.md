# Change Log

## Unreleased

- `run` no longer passes `KEEENV_PASSWORD` to the command it executes.
- `run` now passes all arguments after the command through to the child, so flags like `keeenv run curl -H ...` and `keeenv run pytest --strict` work.
- `add` no longer leaves an orphaned KeePass entry when you decline to overwrite an existing `.keeenv` mapping.
- `add` no longer crashes when the `.keeenv` file has no `[env]` section.
- Entry titles and values containing `%` are now stored and read literally instead of raising an interpolation error.
- `eval` no longer fails the whole export when a single placeholder cannot be resolved; unresolvable variables are exported empty with a warning unless `--strict` is set. Genuine database failures still abort.
- `eval` and `list` now reject invalid environment variable names instead of emitting them into shell output, preventing command injection when the output is evaluated.
- Fixed `run` command to fail cleanly with a clear error when the requested command is not found, instead of printing a traceback.

## v0.6.0

- Added `KEEENV_PASSWORD` environment variable support for non-interactive authentication in CI/CD pipelines, Docker containers, and scripted workflows.
- Added `--no-password` option to `init` command to create .kdbx file with keyfile only.
- Added `-y` option to `init` command to auto-accept creation of new .kdbx file.

## v0.5.1

- Fixed `run` command failing when the command is quoted (e.g. `keeenv run "echo hello"`).

## v0.5.0

- Unexpected CLI errors now log details and a traceback to stderr instead of failing silently.
- Fixed `run` command using `shell=True`, which could interpret shell metacharacters in arguments.
- Fixed `add` command not persisting new entries to the config file on disk.
- Fixed `add` command placing entries in the root group even when a group path was specified.
- Fixed `list` command exiting with code 0 on config errors — now exits with code 1.
- Normalized whitespace stripping behavior between interactive and piped secret input.
- Removed warning for world-readable database files since KeepassXC allows this permission.

## v0.4.0

- Removed enforcement of uppercase env vars to support Terraform TF_VAR style env settings.

## v0.3.0

- Added `eval` subcommand to generate the environment variables.
- Default command now just shows the extended help message.
- Added `list` subcommand to list just the configured variable names without evaluating them.
- Added `run` subcommand to execute commands with environment variables present.

## v0.2.0

- Added `init` subcommand to configure the .keeenv file and optionally create a new KeePass kdbx
- Added `add` subcommand to add a new entry in both the KeePass kdbx and the .keeenv config
- Added support for entrys in KeePass groups

## v0.1.0

- Initial version
