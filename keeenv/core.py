#!/usr/bin/env python3
# keeenv.py - A script to export environment variables from a KeePass database

import argparse
import configparser
import getpass
import os
import re
import shlex
import logging
from typing import Optional, List
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError

from .exceptions import (
    ConfigError,
    ConfigFileNotFoundError,
    ConfigSectionMissingError,
    ConfigKeyMissingError,
    KeePassError,
    KeePassCredentialsError,
    KeePassEntryNotFoundError,
    KeePassAttributeNotFoundError,
    ValidationError,
    SecurityError,
)
from .validation import (
    EntryValidator,
    AttributeValidator,
    SecurityValidator,
    PathValidator,
)

CONFIG_FILENAME = ".keeenv"
KEEPASS_SECTION = "keepass"
ENV_SECTION = "env"

# Regex to find placeholders like ${"Entry Title".Attribute} or ${"Entry Title"."API Key"}
PLACEHOLDER_REGEX = re.compile(
    r"\$\{\s*\"([^\"]+)\"\s*\.\s*(?:\"([^\"]*)\"|(\w+))\s*\}"
)

# Constants for error messages
ERROR_CONFIG_FILE_NOT_FOUND = f"Configuration file '{CONFIG_FILENAME}' not found."
ERROR_SECTION_MISSING = "Section '[{section}]' missing in '{config_file}'"
ERROR_KEY_MISSING = "'{key}' key missing in '[{section}]' section"
ERROR_COULD_NOT_READ_PASSWORD = "Could not read password"
ERROR_INVALID_PASSWORD_OR_KEYFILE = "Invalid master password or key file"
ERROR_DATABASE_OPEN_FAILED = "Failed to open KeePass database"
ERROR_SECTION_MISSING_NO_VARS = (
    "Section '[{section}]' missing in '{config_file}'. No variables to process."
)


def validate_config_file(config_path: str) -> configparser.ConfigParser:
    """
    Validate and parse configuration file.

    Args:
        config_path: Path to configuration file

    Returns:
        Validated ConfigParser object

    Raises:
        ConfigError: If configuration file is invalid
    """
    try:
        # Validate config file path
        validated_path = PathValidator.validate_file_path(config_path, must_exist=True)

        # Use a case-sensitive ConfigParser for keys to preserve ENV var casing
        class CaseSensitiveConfigParser(configparser.ConfigParser):
            def optionxform(self, optionstr: str) -> str:  # type: ignore[override]
                return optionstr

        config = CaseSensitiveConfigParser()
        # Preserve case for section names as well (by default ConfigParser lowercases them on write)
        config._dict = dict  # type: ignore[attr-defined]

        try:
            config.read(validated_path)
        except Exception as e:
            raise ConfigError(f"Failed to parse config file: {str(e)}")

        # Validate required sections
        if "keepass" not in config:
            raise ConfigError("Missing required [keepass] section")

        if "database" not in config["keepass"]:
            raise ConfigError("Missing required 'database' key in [keepass] section")

        return config

    except ValidationError as e:
        raise ConfigError(f"Configuration validation failed: {str(e)}")


def _get_standard_attribute(entry, attribute: str) -> Optional[str]:
    """Get standard attribute from KeePass entry."""
    attribute_lower = attribute.lower()
    if attribute_lower == "password":
        return entry.password  # pyright: ignore[reportAttributeAccessIssue]
    elif attribute_lower == "username":
        return entry.username  # pyright: ignore[reportAttributeAccessIssue]
    elif attribute_lower == "url":
        return entry.url  # pyright: ignore[reportAttributeAccessIssue]
    elif attribute_lower == "notes":
        return entry.notes  # pyright: ignore[reportAttributeAccessIssue]
    return None


def _get_custom_attribute(entry, attribute: str) -> Optional[str]:
    """Get custom attribute from KeePass entry."""
    if (
        hasattr(entry, "custom_properties")
        and isinstance(
            entry.custom_properties, dict
        )  # pyright: ignore[reportAttributeAccessIssue]
        and attribute
        in entry.custom_properties  # pyright: ignore[reportAttributeAccessIssue]
    ):
        return entry.custom_properties[
            attribute
        ]  # pyright: ignore[reportAttributeAccessIssue]
    return None


def get_keepass_secret(kp: PyKeePass, title: str, attribute: str) -> Optional[str]:
    """Fetches a specific attribute from a Keepass entry by title."""
    try:
        # Validate inputs
        validated_title = EntryValidator.validate_entry_title(title)
        validated_attr = AttributeValidator.validate_attribute(attribute)

        entry = kp.find_entries(title=validated_title, first=True)
        if not entry:
            raise KeePassEntryNotFoundError(
                f"Entry with title '{validated_title}' not found"
            )

        # Try standard attributes first
        standard_value = _get_standard_attribute(entry, validated_attr)
        if standard_value is not None:
            return standard_value

        # Try custom attributes
        custom_value = _get_custom_attribute(entry, validated_attr)
        if custom_value is not None:
            return custom_value

        # Attribute not found
        raise KeePassAttributeNotFoundError(
            f"Attribute '{validated_attr}' not found for entry '{validated_title}'"
        )

    except Exception as e:
        if isinstance(e, (KeePassError, ValidationError)):
            raise
        # Use original input 'title' to avoid referencing a possibly unassigned variable
        raise KeePassError(f"Failed to access entry '{title}': {str(e)}")


def substitute_value(kp: PyKeePass, value_template: str, strict: bool = False) -> str:
    """Substitutes placeholders in a string with values from Keepass.

    Uses a single-pass re.sub with a callable to avoid accidental double replacement
    when resolved secrets contain placeholder-like patterns.
    """
    logger = logging.getLogger(__name__)

    def _replace(match: re.Match) -> str:
        placeholder = match.group(0)
        title = match.group(1)
        # Check for quoted attribute first (group 2), then unquoted (group 3)
        attribute = match.group(2) if match.group(2) is not None else match.group(3)

        try:
            secret = get_keepass_secret(kp, title, attribute)
            if secret is not None:
                return secret
            # secret is None → unresolved
            if strict:
                raise ValidationError(f"Unresolved placeholder: {placeholder}")
            logger.warning("Could not resolve placeholder %s", placeholder)
            return ""
        except (KeePassError, ValidationError) as e:
            if strict:
                # Re-raise as ValidationError to enforce strict mode
                raise ValidationError(str(e))
            logger.warning("Failed to resolve placeholder %s: %s", placeholder, str(e))
            return ""

    return PLACEHOLDER_REGEX.sub(_replace, value_template)


def _load_and_validate_config(config_path: str) -> configparser.ConfigParser:
    """Load and validate the configuration file."""
    if not os.path.exists(config_path):
        raise ConfigFileNotFoundError(f"Configuration file '{config_path}' not found.")

    return validate_config_file(config_path)


def _validate_keepass_config(
    config: configparser.ConfigParser,
) -> tuple[str, Optional[str]]:
    """Validate Keepass configuration and return validated paths."""
    if KEEPASS_SECTION not in config:
        raise ConfigSectionMissingError(
            ERROR_SECTION_MISSING.format(
                section=KEEPASS_SECTION, config_file=CONFIG_FILENAME
            )
        )

    keepass_config = config[KEEPASS_SECTION]
    db_path: Optional[str] = keepass_config.get("database")
    keyfile_path: Optional[str] = keepass_config.get("keyfile")

    if not db_path:
        raise ConfigKeyMissingError(
            ERROR_KEY_MISSING.format(key="database", section=KEEPASS_SECTION)
        )

    # Validate database path
    validated_db_path = str(
        PathValidator.validate_file_path(os.path.expanduser(db_path))
    )

    # Validate keyfile path if present
    validated_keyfile_path = None
    if keyfile_path:
        validated_keyfile_path = str(
            PathValidator.validate_file_path(os.path.expanduser(keyfile_path))
        )

    # Validate file security
    SecurityValidator.validate_database_security(
        validated_db_path, validated_keyfile_path
    )

    return validated_db_path, validated_keyfile_path


def _get_master_password(db_path: str) -> str:
    """Prompt for and return the master password."""
    try:
        return getpass.getpass(
            f"Enter master password for {os.path.basename(db_path)}: "
        )
    except EOFError:
        raise KeePassCredentialsError(ERROR_COULD_NOT_READ_PASSWORD)


def _open_keepass_database(
    db_path: str, password: str, keyfile_path: Optional[str]
) -> PyKeePass:
    """Open and return the KeePass database."""
    try:
        return PyKeePass(db_path, password=password, keyfile=keyfile_path)
    except CredentialsError:
        raise KeePassCredentialsError(ERROR_INVALID_PASSWORD_OR_KEYFILE)
    except Exception as e:
        raise KeePassError(f"{ERROR_DATABASE_OPEN_FAILED}: {e}")


def _process_environment_variables(
    config: configparser.ConfigParser, kp: PyKeePass, *, strict: bool = False
) -> List[str]:
    """Process environment variables and return export commands."""
    if ENV_SECTION not in config:
        logging.getLogger(__name__).warning(
            ERROR_SECTION_MISSING_NO_VARS.format(
                section=ENV_SECTION, config_file=CONFIG_FILENAME
            )
        )
        return []

    env_config = config[ENV_SECTION]
    exports: List[str] = []
    for var_name, value_template in env_config.items():
        final_value = substitute_value(kp, value_template, strict=strict)
        # Use shlex.quote for safe shell exporting
        exports.append(f"export {var_name.upper()}={shlex.quote(final_value)}")

    return exports


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
        "--config",
        metavar="PATH",
        default=CONFIG_FILENAME,
        help=f"Target config file path (default: {CONFIG_FILENAME})",
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
            "in the .keeenv file. Example: keeenv add \"GEMINI_API_KEY\" \"xxxx\""
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
                class _CasePreservingConfigParser(configparser.ConfigParser):
                    def optionxform(self, optionstr: str) -> str:  # type: ignore[override]
                        return optionstr
                cfg = _CasePreservingConfigParser()
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
                if not os.path.exists(kdbx_path):
                    raise ConfigError(f"Database '{kdbx_path}' not found. Aborting.")
                # Validate file path
                PathValidator.validate_file_path(kdbx_path, must_exist=True)
                # Validate keyfile if provided: must exist; abort if missing
                if keyfile:
                    key_path = os.path.expanduser(keyfile)
                    if not os.path.exists(key_path):
                        raise ConfigError(f"Keyfile '{key_path}' not found. Aborting.")
                    PathValidator.validate_file_path(key_path, must_exist=True)
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
    # Abort if database does not exist (no creation offer)
    if not os.path.exists(kdbx_path):
        raise ConfigError(f"Database '{kdbx_path}' not found. Aborting.")
    PathValidator.validate_file_path(kdbx_path, must_exist=True)

    if keyfile is None:
        entered = _prompt_input(
            "Path to key file (optional, press Enter to skip): "
        ).strip()
        keyfile = entered or None

    if keyfile:
        key_path = os.path.expanduser(keyfile)
        # Abort if keyfile provided but not found
        if not os.path.exists(key_path):
            raise ConfigError(f"Keyfile '{key_path}' not found. Aborting.")
        PathValidator.validate_file_path(key_path, must_exist=True)

    # Compose config (preserve key case for ENV var names)
    class CaseSensitiveConfigParser(configparser.ConfigParser):
        def optionxform(self, optionstr: str) -> str:  # type: ignore[override]
            return optionstr

    cfg = CaseSensitiveConfigParser()
    cfg._dict = dict  # type: ignore[attr-defined]
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
    cfg = _load_and_validate_config(config_path)

    # Validate keepass connection details
    db_path, keyfile_path = _validate_keepass_config(cfg)

    # Ensure we have a secret
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

    # Open KeePass
    password = _get_master_password(db_path)
    kp = _open_keepass_database(db_path, password, keyfile_path)

    # Create or update entry in the root group (default)
    entry = kp.find_entries(title=eff_title, first=True)
    if entry and not force:
        # Prompt before overwriting existing entry
        choice = _prompt_input(
            f"Entry '{eff_title}' already exists in KeePass. Overwrite? [y/N]: "
        ).strip().lower()
        if choice not in ("y", "yes"):
            raise ValidationError("Add cancelled by user (existing KeePass entry).")
    if not entry:
        # create a new entry; set username only if provided
        entry = kp.add_entry(
            kp.root_group,
            title=eff_title,
            username=username if username else "",
            password=""  # set after based on attribute
        )
    else:
        # update username if requested
        if username is not None:
            entry.username = username  # pyright: ignore[reportAttributeAccessIssue]

    # Store the secret value into the requested place
    if attr_lower == "password":
        entry.password = secret  # pyright: ignore[reportAttributeAccessIssue]
    elif attr_lower == "username":
        entry.username = secret  # pyright: ignore[reportAttributeAccessIssue]
    elif attr_lower == "url":
        entry.url = secret  # pyright: ignore[reportAttributeAccessIssue]
    elif attr_lower == "notes":
        entry.notes = secret  # pyright: ignore[reportAttributeAccessIssue]
    else:
        # custom property
        try:
            # Prefer API method if available; else, fall back to dict-like property.
            if hasattr(entry, "set_custom_property"):  # pyright: ignore[reportAttributeAccessIssue]
                getattr(entry, "set_custom_property")(eff_attr_valid, secret)  # type: ignore[misc]
            else:
                # Ensure custom_properties exists and is a dict
                has_props = hasattr(entry, "custom_properties")  # pyright: ignore[reportAttributeAccessIssue]
                props_is_dict = has_props and isinstance(  # pyright: ignore[reportAttributeAccessIssue]
                    getattr(entry, "custom_properties"), dict
                )
                if not props_is_dict:
                    setattr(entry, "custom_properties", {})  # type: ignore[misc]
                # Now set the value
                entry.custom_properties[eff_attr_valid] = secret  # pyright: ignore[reportAttributeAccessIssue]
        except Exception as e:
            raise KeePassError(
                f"Failed to set custom attribute '{eff_attr_valid}' on '{eff_title}'",
                e,
            )

    # Apply optional standard fields supplied via flags (do not override if None)
    if url is not None:
        entry.url = url  # pyright: ignore[reportAttributeAccessIssue]
    if notes is not None:
        entry.notes = notes  # pyright: ignore[reportAttributeAccessIssue]

    # Save database
    try:
        kp.save()
    except Exception as e:
        raise KeePassError("Failed to save KeePass database", e)

    # Update .keeenv mapping
    if ENV_SECTION not in cfg:
        cfg[ENV_SECTION] = {}

    # Compute placeholder syntax. Always quote the title. Quote attribute if needed.
    def needs_quote_attr(a: str) -> bool:
        return not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", a)

    placeholder_attr = f"\"{eff_attr_valid}\"" if needs_quote_attr(eff_attr_valid) else eff_attr_valid
    placeholder = f'${{"{eff_title}".{placeholder_attr}}}'

    # Preserve exact case of env_var when writing
    # If mapping already exists and not forcing, prompt before overwrite
    existing_mapping = cfg[ENV_SECTION].get(env_var)
    if existing_mapping is not None and not force:
        choice = _prompt_input(
            f"Variable '{env_var}' already exists in {config_path}. Overwrite mapping? [y/N]: "
        ).strip().lower()
        if choice not in ("y", "yes"):
            raise ValidationError("Add cancelled by user (existing .keeenv mapping).")

    cfg[ENV_SECTION][env_var] = placeholder

    # Write config back to disk
    try:
        with open(os.path.expanduser(config_path), "w", encoding="utf-8") as f:
            cfg.write(f)
    except Exception as e:
        raise ConfigError(f"Failed to write configuration file '{config_path}'", e)

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
                getattr(args, "config", CONFIG_FILENAME),
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
                config_path=getattr(args, "config", CONFIG_FILENAME),
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
        config = _load_and_validate_config(args.config)

        # Validate Keepass configuration and get paths
        validated_db_path, validated_keyfile_path = _validate_keepass_config(config)

        # Get master password
        password = _get_master_password(validated_db_path)

        # Open KeePass database
        kp = _open_keepass_database(validated_db_path, password, validated_keyfile_path)

        # Process environment variables
        exports = _process_environment_variables(
            config, kp, strict=bool(getattr(args, "strict", False))
        )

        # Print export commands
        if exports:
            print("\n".join(exports))

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
