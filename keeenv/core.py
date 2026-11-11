#!/usr/bin/env python3
# keeenv.py - A script to export environment variables from a KeePass database

import argparse
import getpass
import logging
import os
import shlex
import subprocess
import sys

from keeenv.config import KeeenvConfig
from keeenv.constants import (
    CONFIG_FILENAME,
    ENV_SECTION,
    KEEPASS_SECTION,
)
from keeenv.exceptions import (
    ConfigError,
    ConfigFileNotFoundError,
    KeePassError,
    SecurityError,
    ValidationError,
)
from keeenv.keepass import KeePassManager
from keeenv.validation import (
    AttributeValidator,
    EntryValidator,
    EnvVarValidator,
    PathValidator,
)


def _handle_error(error) -> None:
    """Handle errors with appropriate messaging. Let the CLI decide exit codes."""
    logger = logging.getLogger(__name__)
    error_type = type(error).__name__
    logger.error("%s Error: %s", error_type, error)
    if hasattr(error, "original_exception") and error.original_exception:
        logger.error("  Original error: %s", error.original_exception)
    # Re-raise to let the CLI layer map to exit codes
    raise error


def _add_global_flags(
    target: argparse.ArgumentParser, *, include_strict: bool = True
) -> None:
    """
    Mirror the global flags onto a subparser so they also work after the verb.

    ``default=argparse.SUPPRESS`` is load-bearing: without it the subparser's
    default would overwrite a value supplied before the subcommand, breaking
    ``keeenv --strict eval``. With SUPPRESS the attribute is only set when the
    flag actually appears after the verb.

    Do NOT apply this to the ``run`` subparser: everything after ``run`` belongs
    to the child process.
    """
    group = target.add_mutually_exclusive_group()
    group.add_argument(
        "--quiet",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Reduce logging output (only errors)",
    )
    group.add_argument(
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Increase logging verbosity (debug details)",
    )
    target.add_argument(
        "--config",
        metavar="PATH",
        default=argparse.SUPPRESS,
        help=f"Path to configuration file (default: {CONFIG_FILENAME})",
    )
    if include_strict:
        target.add_argument(
            "--strict",
            action="store_true",
            default=argparse.SUPPRESS,
            help="Fail if any placeholder cannot be resolved",
        )


def _create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    from . import __version__

    parser = argparse.ArgumentParser(
        prog="keeenv",
        description="Set local environment variables from KeePass database",
        epilog="Example: eval $(keeenv eval)",
    )

    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce logging output (only errors)",
    )
    verbosity.add_argument(
        "--verbose",
        action="store_true",
        help="Increase logging verbosity (debug details)",
    )

    parser.add_argument(
        "--config",
        metavar="PATH",
        default=CONFIG_FILENAME,
        help=f"Path to configuration file (default: {CONFIG_FILENAME})",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if any placeholder cannot be resolved",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show program's version number and exit",
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommands")

    # eval subcommand
    eval_parser = subparsers.add_parser(
        "eval",
        help="Evaluate and export environment variables",
        description="Export environment variables from KeePass database",
    )
    _add_global_flags(eval_parser)

    # list subcommand
    list_parser = subparsers.add_parser(
        "list",
        help="List environment variable names from .keeenv",
        description="List all environment variable names defined in the [env] section of .keeenv",
    )
    _add_global_flags(list_parser, include_strict=False)

    # run subcommand. It deliberately declares no positional: everything after
    # the `run` token is sliced off by _split_run_argv before argparse sees it,
    # so a `command` argument here would always be empty. See main().
    subparsers.add_parser(
        "run",
        help="Run a command with environment variables set from .keeenv",
        description=(
            "Execute a command with environment variables populated from KeePass "
            "database. Everything after 'run' is passed to the child verbatim."
        ),
    )

    # init subcommand
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize a new .keeenv configuration file",
        description="Create or update a .keeenv file with [keepass] entries",
    )
    _add_global_flags(init_parser, include_strict=False)
    init_parser.add_argument(
        "--kdbx",
        metavar="PATH",
        help="Path to an existing KeePass .kdbx database file",
    )
    init_parser.add_argument(
        "--keyfile",
        metavar="PATH",
        help="Optional path to a KeePass key file",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing config without prompting",
    )
    init_parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Confirm creating a new KeePass database (fails if kdbx already exists unless --force)",
    )
    init_parser.add_argument(
        "--no-password",
        action="store_true",
        help="Create a new KeePass database without a master password (requires --keyfile)",
    )

    # add subcommand
    add_parser = subparsers.add_parser(
        "add",
        help="Add a new credential to KeePass and map it in .keeenv",
        description=(
            "Add a new secret to the KeePass database and populate the [env] entry "
            'in the .keeenv file. Example: keeenv add "GEMINI_API_KEY" "xxxx"'
        ),
    )
    _add_global_flags(add_parser, include_strict=False)
    add_parser.add_argument(
        "env_var",
        metavar="ENV_VAR",
        help="Environment variable name to set (case preserved in .keeenv)",
    )
    add_parser.add_argument(
        "secret",
        metavar="SECRET",
        nargs="?",
        help="Secret value. If omitted, you will be prompted to enter it.",
    )
    add_parser.add_argument(
        "-t",
        "--title",
        metavar="TITLE",
        help="KeePass entry title (default: ENV_VAR)",
    )
    add_parser.add_argument(
        "-u",
        "--user",
        metavar="USERNAME",
        help="Optional username to set on the KeePass entry",
    )
    add_parser.add_argument(
        "--url",
        metavar="URL",
        help="Optional URL to set on the KeePass entry",
    )
    add_parser.add_argument(
        "--notes",
        metavar="NOTES",
        help="Optional notes to set on the KeePass entry",
    )
    add_parser.add_argument(
        "-a",
        "--attribute",
        metavar="ATTRIBUTE",
        help='Attribute to store secret in (default: "Password"). For custom attributes, quotes are not required here.',
    )
    add_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing KeePass entry and .keeenv mapping without prompting",
    )
    # Reuse top-level --config for .keeenv path and Keepass connection

    return parser


def _prompt_input(prompt: str) -> str:
    """Prompt user for input (safe for tests)."""
    try:
        return input(prompt)
    except EOFError:
        return ""


def _prompt_secret(prompt: str) -> str:
    """Prompt user for a secret value without echoing (uses getpass).

    Returns empty string if stdin is not a TTY (non-interactive context).
    """
    import os

    if not os.isatty(0):
        return ""
    try:
        return getpass.getpass(prompt)
    except EOFError:
        return ""


def _create_kdbx_database(
    kdbx_path: str,
    password: str | None = None,
    keyfile: str | None = None,
) -> None:
    """Create a new KeePass database at kdbx_path.

    Exactly one of password or keyfile must be provided.
    Raises KeePassError on failure.
    """
    logger = logging.getLogger(__name__)
    os.makedirs(os.path.dirname(kdbx_path) or ".", exist_ok=True)
    try:
        from pykeepass import create_database

        if password is not None:
            create_database(kdbx_path, password=password)
        else:
            create_database(kdbx_path, keyfile=keyfile)
        logger.info(
            "Created new KeePass database at %s%s",
            kdbx_path,
            f" (keyfile={keyfile})" if keyfile else "",
        )
    except Exception as e:
        raise KeePassError("Failed to create KeePass database", e)


def _create_kdbx_with_password_interactive(
    kdbx_path: str,
    no_password: bool = False,
    keyfile: str | None = None,
) -> None:
    """Create a new KeePass database, interactively or via env var.

    If ``no_password`` is True, ``keyfile`` must be provided and the database
    is created without a master password. Otherwise, the master password is
    taken from ``KEEENV_PASSWORD`` (if set) or read from the terminal (twice
    for confirmation).
    """
    if no_password:
        if not keyfile:
            raise ConfigError("--no-password requires --keyfile to be provided.")
        _create_kdbx_database(kdbx_path, keyfile=keyfile)
        return

    env_pw = os.environ.get("KEEENV_PASSWORD")
    if env_pw is not None:
        pw1 = pw2 = env_pw
    else:
        pw1 = _prompt_secret("Create master password: ").strip()
        pw2 = _prompt_secret("Confirm master password: ").strip()
    if not pw1:
        raise ConfigError("Master password cannot be empty.")
    if pw1 != pw2:
        raise ConfigError("Passwords do not match.")
    _create_kdbx_database(kdbx_path, password=pw1)


def _init_config_interactive(
    target_path: str,
    kdbx: str | None,
    keyfile: str | None,
    force: bool,
    yes: bool = False,
    no_password: bool = False,
) -> None:
    """
    Initialize a .keeenv file at target_path with [keepass] entries.

    Behavior:
    - If kdbx/keyfile not provided, prompt user for paths.
    - Validate provided paths; if kdbx or keyfile paths do not exist, abort with error.
    - If config exists: prompt to Update, Overwrite, or Abort (default Abort), unless --force.
    - If --no-password: create new kdbx without a master password (requires --keyfile).
    - If --yes: confirm creating a new kdbx (fails if kdbx already exists unless --force).
    """
    logger = logging.getLogger(__name__)
    target = os.path.expanduser(target_path)

    if no_password and not keyfile:
        raise ConfigError("--no-password requires --keyfile to be provided.")

    # Ensure parent directory exists
    parent_dir = os.path.dirname(target) or "."
    if parent_dir and not os.path.isdir(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)

    def _store_keepass_path(raw_path: str) -> str:
        """
        Convert a user-supplied DB/keyfile path into the form written to config.

        Paths are entered and validated relative to the process CWD, but are
        read back relative to the config file's directory (see
        ``KeeenvConfig._resolve_keepass_path``). Storing the absolute path makes
        both interpretations agree, so a config written from one directory works
        from any other.
        """
        return os.path.abspath(os.path.expanduser(raw_path))

    # Handle existing config
    if os.path.exists(target):
        if not force:
            choice = (
                _prompt_input(
                    f"Config '{target}' already exists. [U]pdate, [O]verwrite, [A]bort (default A): "
                )
                .strip()
                .lower()
            )
            if choice in ("o", "overwrite"):
                pass  # continue to write fresh
            elif choice in ("u", "update"):
                # Read existing config (preserve key case)
                config_manager = KeeenvConfig(target)
                cfg = config_manager._make_case_preserving_config()
                try:
                    cfg.read(target)
                except Exception as e:
                    raise ConfigError(f"Failed to parse existing config: {e}")
                if KEEPASS_SECTION not in cfg:
                    cfg[KEEPASS_SECTION] = {}
                # Determine values (prefer provided args; fall back to existing; then prompt)
                # Existing values are resolved relative to the config file, matching
                # how they are interpreted on read.
                raw_db = cfg[KEEPASS_SECTION].get("database")
                raw_key = cfg[KEEPASS_SECTION].get("keyfile")
                current_db = (
                    config_manager._resolve_keepass_path(raw_db) if raw_db else None
                )
                current_key = (
                    config_manager._resolve_keepass_path(raw_key) if raw_key else None
                )
                if not kdbx:
                    kdbx = (
                        _prompt_input(
                            f"Path to KeePass .kdbx file [{current_db or ''}]: "
                        ).strip()
                        or current_db
                    )
                if not keyfile:
                    keyfile = (
                        _prompt_input(
                            f"Path to key file (optional) [{current_key or ''}]: "
                        ).strip()
                        or current_key
                    )
                # Validate kdbx: must exist; abort if missing
                if not kdbx:
                    raise ConfigError("No database path provided.")
                kdbx_path = os.path.expanduser(kdbx)
                try:
                    PathValidator.validate_file_path(kdbx_path, must_exist=True)
                except ValidationError:
                    raise ConfigError(f"Database '{kdbx_path}' not found. Aborting.")
                # Validate keyfile if provided: must exist; abort if missing
                if keyfile:
                    key_path = os.path.expanduser(keyfile)
                    try:
                        PathValidator.validate_file_path(key_path, must_exist=True)
                    except ValidationError:
                        raise ConfigError(f"Keyfile '{key_path}' not found. Aborting.")
                # Update and write back
                cfg[KEEPASS_SECTION]["database"] = _store_keepass_path(kdbx)
                if keyfile:
                    cfg[KEEPASS_SECTION]["keyfile"] = _store_keepass_path(keyfile)
                elif "keyfile" in cfg[KEEPASS_SECTION]:
                    # Remove keyfile if cleared
                    cfg[KEEPASS_SECTION].pop("keyfile", None)
                # Ensure [env] exists
                if ENV_SECTION not in cfg:
                    cfg[ENV_SECTION] = {}
                with open(target, "w", encoding="utf-8") as f:
                    cfg.write(f)
                logger.info("Updated existing config at %s", target)
                return
            else:
                # default abort
                raise ConfigError("Aborted by user (existing configuration).")
        # --force implies overwrite

    # Fresh or overwrite path
    if not kdbx:
        kdbx = _prompt_input("Path to KeePass .kdbx file: ").strip()
    if not kdbx:
        raise ConfigError("No database path provided.")
    kdbx_path = os.path.expanduser(kdbx)

    # If database does not exist, offer to create a new empty KeePass database
    try:
        # If it validates as existing file, we skip creation prompt
        PathValidator.validate_file_path(kdbx_path, must_exist=True)
        path_exists = True
    except ValidationError:
        path_exists = False

    if not path_exists:
        # -y/--yes: confirm creating a new kdbx without prompting
        if yes:
            _create_kdbx_with_password_interactive(
                kdbx_path, no_password=no_password, keyfile=keyfile
            )
        else:
            choice = (
                _prompt_input(
                    f"Database '{kdbx_path}' not found. Create a new KeePass database here? [y/N]: "
                )
                .strip()
                .lower()
            )
            if choice in ("y", "yes"):
                _create_kdbx_with_password_interactive(
                    kdbx_path, no_password=no_password, keyfile=keyfile
                )
            else:
                raise ConfigError(f"Database '{kdbx_path}' not found. Aborting.")
    elif yes and not force:
        # -y/--yes used but kdbx already exists (and no --force)
        raise ConfigError(
            f"Database '{kdbx_path}' already exists. Use --force to overwrite."
        )

    # Validate (must exist at this point)
    PathValidator.validate_file_path(kdbx_path, must_exist=True)

    if keyfile is None:
        entered = _prompt_input(
            "Path to key file (optional, press Enter to skip): "
        ).strip()
        keyfile = entered or None

    if keyfile:
        key_path = os.path.expanduser(keyfile)
        try:
            PathValidator.validate_file_path(key_path, must_exist=True)
        except ValidationError:
            raise ConfigError(f"Keyfile '{key_path}' not found. Aborting.")

    # Compose config (preserve key case for ENV var names)
    config_manager = KeeenvConfig(target)
    cfg = config_manager._make_case_preserving_config()
    cfg[KEEPASS_SECTION] = {"database": _store_keepass_path(kdbx_path)}
    if keyfile:
        cfg[KEEPASS_SECTION]["keyfile"] = _store_keepass_path(keyfile)
    # Include empty [env] section when creating a new file
    cfg[ENV_SECTION] = {}

    with open(target, "w", encoding="utf-8") as f:
        cfg.write(f)

    logger.info("Created new config at %s", target)


def _cmd_add(
    *,
    config_path: str,
    env_var: str,
    secret: str | None,
    title: str | None,
    username: str | None,
    url: str | None,
    notes: str | None,
    attribute: str | None,
    force: bool = False,
) -> None:
    """
    Implement `keeenv add` to create/update a KeePass entry and map it in .keeenv.

    Behavior:
    - env_var: environment variable name; preserve case in .keeenv [env].
    - secret: if omitted, prompt (without echo). Required after prompting.
    - title: KeePass entry title; default to env_var.
    - username: optional; set Username field if provided.
    - attribute: where to store the secret; default "Password".
      If a standard attribute (password/username/url/notes), populate the standard field.
      Otherwise, create/update a custom property with that name.
    - Updates .keeenv [env] with ENV_VAR = ${"Title".Attribute} (quotes if needed).
    """
    logger = logging.getLogger(__name__)

    # Names are written into `.keeenv` and later rendered into shell `export`
    # lines, so reject invalid shell identifiers before any durable write.
    env_var = EnvVarValidator.validate_env_var_name(env_var)

    # Load/validate config
    config_manager = KeeenvConfig(config_path)
    cfg = config_manager.get_config()

    # Validate keepass connection details
    db_path, keyfile_path = config_manager.validate_keepass_config(cfg)

    # Ensure we have a secret
    if not secret:
        # Support piping secret from stdin, e.g.,: pbpaste | keeenv add MY_API_KEY
        try:
            if not sys.stdin.isatty():
                piped = sys.stdin.read()
                if piped:
                    secret = piped.strip()
        except Exception:
            # Fall back to prompt if stdin handling fails
            pass

    if not secret:
        secret = _prompt_secret(f"Enter secret for {env_var}: ").strip()
    if not secret:
        raise ValidationError("Secret value is required")

    # Determine title default
    eff_title = title if title else env_var
    eff_title = EntryValidator.validate_entry_title(eff_title)

    # Determine attribute default and validation
    eff_attr = attribute if attribute else "password"
    eff_attr_valid = AttributeValidator.validate_attribute(eff_attr)
    attr_lower = eff_attr_valid.lower()

    # Compute the placeholder and resolve mapping conflicts BEFORE any durable
    # write. Both cancel points must precede both stores, otherwise declining
    # the mapping prompt leaves an orphaned KeePass entry behind.
    # Constructing KeePassManager does not open the database.
    kp_manager = KeePassManager(db_path, keyfile_path)
    placeholder = kp_manager.format_placeholder(eff_title, eff_attr_valid)

    if ENV_SECTION not in cfg:
        cfg[ENV_SECTION] = {}

    existing_mapping = cfg[ENV_SECTION].get(env_var)
    if existing_mapping is not None and not force:
        choice = (
            _prompt_input(
                f"Variable '{env_var}' already exists in {config_path}. Overwrite mapping? [y/N]: "
            )
            .strip()
            .lower()
        )
        if choice not in ("y", "yes"):
            raise ValidationError("Add cancelled by user (existing .keeenv mapping).")

    # Use KeePassManager for database operations
    kp_manager.connect_with_password_fallback()

    created_entry = False
    created_uuid = None
    created_title = eff_title
    try:
        # Find or create the entry using KeePassManager
        entry, group_for_entry, final_title = kp_manager.find_entry(
            eff_title, create_if_missing=True
        )

        if entry and not force:
            # Prompt before overwriting existing entry
            choice = (
                _prompt_input(
                    f"Entry '{eff_title}' already exists in KeePass. Overwrite? [y/N]: "
                )
                .strip()
                .lower()
            )
            if choice not in ("y", "yes"):
                raise ValidationError("Add cancelled by user (existing KeePass entry).")
        if not entry:
            # create a new entry; set username only if provided
            entry = kp_manager.create_entry(
                final_title,
                username=username if username else "",
                password="",  # set after based on attribute
                group=group_for_entry,
            )
            created_entry = True
            created_uuid = entry.uuid
            created_title = final_title
        else:
            # update username if requested
            if username is not None:
                kp_manager.update_entry(entry, username=username)

        # Store the secret value into the requested place
        # Note: secret is guaranteed non-empty string above
        kp_manager.set_entry_attribute(
            entry, attr_lower, secret, eff_attr_valid, eff_title
        )

        # Apply optional standard fields supplied via flags (do not override if None)
        if url is not None or notes is not None:
            kp_manager.update_entry(entry, url=url, notes=notes)

        # Save database
        kp_manager.save_database()
    finally:
        # Ensure database connection is closed
        kp_manager.disconnect()

    cfg[ENV_SECTION][env_var] = placeholder

    # Write config back to disk using KeeenvConfig
    try:
        config_manager.save_config(cfg)
    except Exception:
        if created_entry:
            # Delete exactly the entry this run created, identified by UUID:
            # titles are not unique across groups, so a title lookup could
            # match (and destroy) an unrelated entry. An entry we only updated
            # cannot be restored here; KeePass clients keep their own file
            # version history for that case.
            rollback = KeePassManager(db_path, keyfile_path)
            try:
                rollback.connect_with_password_fallback()
                found = (
                    rollback.find_entry_by_uuid(created_uuid)
                    if created_uuid is not None
                    else None
                )
                if found is not None:
                    rollback.delete_entry(found)
                    rollback.save_database()
            except Exception:
                logger.error(
                    "Failed to roll back KeePass entry '%s' after config write "
                    "failure; the entry may remain in the database",
                    created_title,
                )
            finally:
                rollback.disconnect()
        else:
            logger.error(
                "Config write failed after updating existing KeePass entry '%s'; "
                "the previous secret value cannot be restored automatically",
                created_title,
            )
        raise

    logger.info(
        "Added/updated KeePass entry '%s' and mapped %s in %s",
        eff_title,
        env_var,
        config_path,
    )


def _cmd_list(*, config_path: str) -> None:
    """
    Implement `keeenv list` to display environment variable names from .keeenv.

    Behavior:
    - Read the .keeenv configuration file
    - Extract and display all environment variable names from the [env] section
    - No KeePass database connection or value evaluation is performed
    """
    logger = logging.getLogger(__name__)

    # Load configuration file. Exceptions propagate to the dispatch layer in
    # main(), which logs them once — handling them here as well double-logs.
    config_manager = KeeenvConfig(config_path)

    # Get environment variables from [env] section
    env_vars = config_manager.get_env_vars()

    if env_vars:
        # Print each environment variable name on a separate line.
        # Validate first so an invalid name never reaches a shell.
        for var_name in env_vars:
            print(EnvVarValidator.validate_env_var_name(var_name))
        logger.info(
            "Listed %d environment variable(s) from %s",
            len(env_vars),
            config_path,
        )
    else:
        print("No environment variables found in [env] section")
        logger.info("No environment variables found in %s", config_path)


def _cmd_run(*, config_path: str, command: list[str]) -> None:
    """
    Implement `keeenv run` to execute a command with environment variables set from .keeenv.

    Behavior:
    - Load environment variables from KeePass database
    - Execute the specified command in a child process with those environment variables
    - Forward the exit code of the child process
    """
    logger = logging.getLogger(__name__)

    if not command:
        raise ValidationError("No command specified after 'run'")

    # Load and validate configuration
    config_manager = KeeenvConfig(config_path)
    config = config_manager.get_config()

    # Validate environment variable names before touching the database. Names
    # are handed straight to subprocess.run(env=...), which rejects invalid
    # ones with a bare ValueError; validating up front gives a clean domain
    # error (and skips the password prompt), consistent with eval/list.
    env_items = []
    if ENV_SECTION in config:
        for var_name, value_template in config[ENV_SECTION].items():
            env_items.append(
                (EnvVarValidator.validate_env_var_name(var_name), value_template)
            )

    # Validate Keepass configuration and get paths
    validated_db_path, validated_keyfile_path = config_manager.validate_keepass_config(
        config
    )

    # Use KeePassManager for database operations
    kp_manager = KeePassManager(validated_db_path, validated_keyfile_path)
    kp_manager.connect_with_password_fallback()

    try:
        # Process environment variables using KeePassManager
        env_vars = {}
        for validated_name, value_template in env_items:
            # Use strict mode for run command to ensure all placeholders are resolved
            final_value = kp_manager.substitute_placeholders(
                value_template, strict=True
            )
            env_vars[validated_name] = final_value

        # Execute the command with the environment variables
        logger.info("Executing command: %s", " ".join(command))
        # Do not log resolved env vars; values may contain secrets.

        # Create a copy of the current environment and add our variables.
        # The master-password auth variable is an input to keeenv, not part of
        # the child's environment; never forward it to subprocesses.
        full_env = os.environ.copy()
        full_env.pop("KEEENV_PASSWORD", None)
        full_env.update(env_vars)

        # Execute the command (list form, no shell for security)
        # If the user quoted the entire command (e.g., keeenv run "echo hello"),
        # the child argv is a single string. Split it with shlex so subprocess
        # can find the executable.
        if len(command) == 1:
            command = shlex.split(command[0])
        if not command:
            raise ValidationError("No command specified after 'run'")
        try:
            result = subprocess.run(command, env=full_env, shell=False)
        except FileNotFoundError:
            raise ValidationError(f"Command not found: {command[0]}")

        # Forward the exit code
        sys.exit(result.returncode)

    finally:
        # Ensure database connection is closed
        kp_manager.disconnect()


# Options that consume the following token as their value. Used by
# _split_run_argv to tell a real subcommand token apart from an option value
# that happens to spell "run" (e.g. `add KEY secret -t run`).
_VALUE_OPTIONS = frozenset(
    {
        "--config",
        "--kdbx",
        "--keyfile",
        "--title",
        "--user",
        "--url",
        "--notes",
        "--attribute",
        "-t",
        "-u",
        "-a",
    }
)


def _first_positional_index(argv: list[str]) -> int:
    """Return the index of the first positional token, skipping options/values."""
    i = 0
    n = len(argv)
    while i < n:
        token = argv[i]
        if token == "--":
            # Everything after `--` is positional; the subcommand is next.
            return i + 1
        if token.startswith("-") and token != "-":
            # `--opt=value` carries its value inline; a bare value option
            # consumes the next token; a flag consumes nothing.
            i += 1 if "=" in token or token not in _VALUE_OPTIONS else 2
            continue
        return i
    return n


def _split_run_argv(argv: list[str]) -> tuple[list[str], list[str] | None]:
    """
    Split argv into (arguments for argparse, child command or None).

    Everything after the ``run`` subcommand token belongs to the child process,
    verbatim — including tokens that look like keeenv's own options
    (``--strict``, ``-n``, a literal ``--``). argparse's REMAINDER does not do
    this: it still claims tokens matching a known option.

    Only the *subcommand position* (the first positional token) can be ``run``.
    A literal ``run`` used as an option value (``-t run``, ``--kdbx run``) or as
    a later positional is therefore never mistaken for the subcommand.
    """

    index = _first_positional_index(argv)
    if index < len(argv) and argv[index] == "run":
        return argv[: index + 1], argv[index + 1 :]
    return argv, None


def main() -> None:
    """Main function to read config, fetch secrets, and set the environment."""
    # Parse command line arguments. For `run`, everything after the subcommand
    # is the child's argv and must not be interpreted by argparse.
    parser = _create_argument_parser()
    parse_argv, run_command = _split_run_argv(sys.argv[1:])
    args = parser.parse_args(parse_argv)

    # If no arguments provided, show extended help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    # Configure logging level based on verbosity flags
    if getattr(args, "verbose", False):
        logging.basicConfig(level=logging.DEBUG)
    elif getattr(args, "quiet", False):
        logging.basicConfig(level=logging.ERROR)
    else:
        logging.basicConfig(level=logging.WARNING)

    # Handle subcommands
    if getattr(args, "subcommand", None) == "init":
        try:
            _init_config_interactive(
                args.config,
                getattr(args, "kdbx", None),
                getattr(args, "keyfile", None),
                bool(getattr(args, "force", False)),
                yes=bool(getattr(args, "yes", False)),
                no_password=bool(getattr(args, "no_password", False)),
            )
        except (ConfigError, ValidationError) as e:
            _handle_error(e)
        except Exception:
            raise
        return

    if getattr(args, "subcommand", None) == "add":
        try:
            _cmd_add(
                config_path=args.config,
                env_var=args.env_var,
                secret=getattr(args, "secret", None),
                title=getattr(args, "title", None),
                username=getattr(args, "user", None),
                url=getattr(args, "url", None),
                notes=getattr(args, "notes", None),
                attribute=getattr(args, "attribute", None),
                force=bool(getattr(args, "force", False)),
            )
        except (ConfigError, KeePassError, ValidationError, SecurityError) as e:
            _handle_error(e)
        except Exception:
            raise
        return

    if getattr(args, "subcommand", None) == "list":
        try:
            _cmd_list(config_path=args.config)
        except (ConfigError, ConfigFileNotFoundError, ValidationError) as e:
            _handle_error(e)
        except Exception:
            raise
        return

    # Check if args.subcommand is the string "run" (subcommand name)
    if getattr(args, "subcommand", None) == "run":
        try:
            _cmd_run(config_path=args.config, command=run_command or [])
        except (ConfigError, KeePassError, ValidationError, SecurityError) as e:
            _handle_error(e)
        except Exception:
            raise
        return

    # If --version or --help was provided, argparse will handle it and exit
    # So we only continue if no special arguments were provided

    try:
        # Load and validate configuration
        config_manager = KeeenvConfig(args.config)
        config = config_manager.get_config()

        # Validate environment variable names before touching the database:
        # names are rendered into `export` lines the user evaluates in a shell,
        # so a malformed name must fail fast (no password prompt, no exports).
        env_items = []
        if ENV_SECTION in config:
            env_config = config[ENV_SECTION]
            for var_name, value_template in env_config.items():
                env_items.append(
                    (EnvVarValidator.validate_env_var_name(var_name), value_template)
                )

        # Validate Keepass configuration and get paths
        validated_db_path, validated_keyfile_path = (
            config_manager.validate_keepass_config(config)
        )

        # Use KeePassManager for database operations
        kp_manager = KeePassManager(validated_db_path, validated_keyfile_path)
        kp_manager.connect_with_password_fallback()

        try:
            # Process environment variables using KeePassManager
            exports = []
            strict_mode = bool(getattr(args, "strict", False))
            for validated_name, value_template in env_items:
                final_value = kp_manager.substitute_placeholders(
                    value_template, strict=strict_mode
                )
                # Use shlex.quote for safe shell exporting
                exports.append(f"export {validated_name}={shlex.quote(final_value)}")

            # Print export commands
            if exports:
                print("\n".join(exports))
        finally:
            # Ensure database connection is closed
            kp_manager.disconnect()

    except ConfigError as e:
        _handle_error(e)
    except KeePassError as e:
        _handle_error(e)
    except ValidationError as e:
        _handle_error(e)
    except SecurityError as e:
        _handle_error(e)
    except Exception:
        # Bubble unexpected errors to the CLI layer as well
        raise


if __name__ == "__main__":
    main()
