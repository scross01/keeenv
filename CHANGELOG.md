# Change Log

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
