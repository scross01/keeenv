#!/usr/bin/env python3
# keeenv.py - A script to export environment variables from a KeePass database

import argparse
import getpass
import logging
import os
import shlex
import sys

from keeenv.config import KeeenvConfig
from keeenv.constants import (
    ERROR_COULD_NOT_READ_PASSWORD,
    CONFIG_FILENAME,
    KEEPASS_SECTION,
    ENV_SECTION,
)
from keeenv.exceptions import (
    ConfigError,
    KeePassError,
    KeePassCredentialsError,
    ValidationError,
    SecurityError,
)
from keeenv.keepass import KeePassManager
from keeenv.validation import (
    EntryValidator,
    AttributeValidator,
    PathValidator,
)
from typing import Optional


def _get_master_password(db_path: str) -> str:
    """Prompt for and return the master password."""
    try:
        return getpass.getpass(
            f"Enter master password for {os.path.basename(db_path)}: "
        )
    except EOFError:
        raise KeePassCredentialsError(ERROR_COULD_NOT_READ_PASSWORD)


def _handle_error(error) -> None:
    """Handle errors with appropriate messaging. Let the CLI decide exit codes."""
    logger = logging.getLogger(__name__)
    error_type = type(error).__name__
    logger.error("%s Error: %s", error_type, error)
    if hasattr(error, "original_exception") and error.original_exception:
        logger.error("  Original error: %s", error.original_exception)
    # Re-raise to let the CLI layer map to exit codes
    raise error


def _create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    from . import __version__

    parser = argparse.ArgumentParser(
        prog="keeenv",
        description="Set local environment variables from KeePass database",
        epilog="Example: eval $(keeenv)",
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
    subparsers = parser.add_subparsers(dest="command")

    # init subcommand
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize a new .keeenv configuration file",
        description="Create or update a .keeenv file with [keepass] entries",
    )
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

    # add subcommand
    add_parser = subparsers.add_parser(
        "add",
        help="Add a new credential to KeePass and map it in .keeenv",
        description=(
            "Add a new secret to the KeePass database and populate the [env] entry "
            'in the .keeenv file. Example: keeenv add "GEMINI_API_KEY" "xxxx"'
        ),
    )
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
    """Prompt user for a secret value without echoing (uses getpass)."""
    try:
        return getpass.getpass(prompt)
    except EOFError:
        return ""


def _init_config_interactive(
    target_path: str, kdbx: Optional[str], keyfile: Optional[str], force: bool
) -> None:
    """
    Initialize a .keeenv file at target_path with [keepass] entries.

    Behavior:
    - If kdbx/keyfile not provided, prompt user for paths.
    - Validate provided paths; if kdbx or keyfile paths do not exist, abort with error.
    - If config exists: prompt to Update, Overwrite, or Abort (default Abort), unless --force.
    """
    logger = logging.getLogger(__name__)
    target = os.path.expanduser(target_path)

    # Ensure parent directory exists
    parent_dir = os.path.dirname(target) or "."
    if parent_dir and not os.path.isdir(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)

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
                current_db = cfg[KEEPASS_SECTION].get("database")
                current_key = cfg[KEEPASS_SECTION].get("keyfile")
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
                cfg[KEEPASS_SECTION]["database"] = kdbx_path
                if keyfile:
                    cfg[KEEPASS_SECTION]["keyfile"] = os.path.expanduser(keyfile)
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
        choice = (
            _prompt_input(
                f"Database '{kdbx_path}' not found. Create a new KeePass database here? [y/N]: "
            )
            .strip()
            .lower()
        )
        if choice in ("y", "yes"):
            # Prompt for master password (twice) without echo
            pw1 = _prompt_secret("Create master password: ").strip()
            pw2 = _prompt_secret("Confirm master password: ").strip()
            if not pw1:
                raise ConfigError("Master password cannot be empty.")
            if pw1 != pw2:
                raise ConfigError("Passwords do not match.")
            try:
                # Defer import to avoid hard dependency unless needed
                from pykeepass import create_database

                # Ensure directory exists before file creation
                os.makedirs(os.path.dirname(kdbx_path) or ".", exist_ok=True)
                # Create the database file on disk with the provided master password
                create_database(kdbx_path, password=pw1)
                logger.info("Created new KeePass database at %s", kdbx_path)
            except Exception as e:
                raise KeePassError("Failed to create KeePass database", e)
        else:
            raise ConfigError(f"Database '{kdbx_path}' not found. Aborting.")
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
    cfg[KEEPASS_SECTION] = {"database": kdbx_path}
    if keyfile:
        cfg[KEEPASS_SECTION]["keyfile"] = os.path.expanduser(keyfile)
    # Include empty [env] section when creating a new file
    cfg[ENV_SECTION] = {}

    with open(target, "w", encoding="utf-8") as f:
        cfg.write(f)

    logger.info("Created new config at %s", target)


def _cmd_add(
    *,
    config_path: str,
    env_var: str,
    secret: Optional[str],
    title: Optional[str],
    username: Optional[str],
    url: Optional[str],
    notes: Optional[str],
    attribute: Optional[str],
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
                    secret = piped.strip("\n\r")
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

    # Use KeePassManager for database operations
    kp_manager = KeePassManager(db_path, keyfile_path)
    
    # Try to connect without password first, only prompt if needed
    try:
        kp_manager.connect(password=None)
    except KeePassCredentialsError:
        # Database requires password, prompt for it
        password = _get_master_password(db_path)
        kp_manager.connect(password)

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
            )
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

    # Update .keeenv mapping using KeeenvConfig
    # Compute placeholder syntax using KeePassManager
    placeholder = kp_manager.format_placeholder(eff_title, eff_attr_valid)

    # Preserve exact case of env_var when writing
    # If mapping already exists and not forcing, prompt before overwrite
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

    cfg[ENV_SECTION][env_var] = placeholder

    # Write config back to disk using KeeenvConfig
    config_manager.save_config(cfg)

    logger.info(
        "Added/updated KeePass entry '%s' and mapped %s in %s",
        eff_title,
        env_var,
        config_path,
    )


def main() -> None:
    """Main function to read config, fetch secrets, and set the environment."""
    # Parse command line arguments
    parser = _create_argument_parser()
    args = parser.parse_args()

    # Configure logging level based on verbosity flags
    if getattr(args, "verbose", False):
        logging.basicConfig(level=logging.DEBUG)
    elif getattr(args, "quiet", False):
        logging.basicConfig(level=logging.ERROR)
    else:
        logging.basicConfig(level=logging.WARNING)

    # Handle subcommands
    if getattr(args, "command", None) == "init":
        try:
            _init_config_interactive(
                args.config,
                getattr(args, "kdbx", None),
                getattr(args, "keyfile", None),
                bool(getattr(args, "force", False)),
            )
        except (ConfigError, ValidationError) as e:
            _handle_error(e)
        except Exception:
            raise
        return

    if getattr(args, "command", None) == "add":
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

    # If --version or --help was provided, argparse will handle it and exit
    # So we only continue if no special arguments were provided

    try:
        # Load and validate configuration
        config_manager = KeeenvConfig(args.config)
        config = config_manager.get_config()

        # Validate Keepass configuration and get paths
        validated_db_path, validated_keyfile_path = (
            config_manager.validate_keepass_config(config)
        )

        # Use KeePassManager for database operations
        kp_manager = KeePassManager(validated_db_path, validated_keyfile_path)
        
        # Try to connect without password first, only prompt if needed
        try:
            kp_manager.connect(password=None)
        except KeePassCredentialsError:
            # Database requires password, prompt for it
            password = _get_master_password(validated_db_path)
            kp_manager.connect(password)

        try:
            # Process environment variables using KeePassManager
            exports = []
            if ENV_SECTION in config:
                env_config = config[ENV_SECTION]
                for var_name, value_template in env_config.items():
                    strict_mode = bool(getattr(args, "strict", False))
                    final_value = kp_manager.substitute_placeholders(
                        value_template, strict=strict_mode
                    )
                    # Use shlex.quote for safe shell exporting
                    exports.append(
                        f"export {var_name.upper()}={shlex.quote(final_value)}"
                    )

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
