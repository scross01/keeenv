#!/usr/bin/env python3
# keeenv.py - A script to export environment variables from a KeePass database

import argparse
import configparser
import getpass
import os
import re
import sys
import shlex
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

        config = configparser.ConfigParser()
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
        raise KeePassError(f"Failed to access entry '{validated_title}': {str(e)}")


def substitute_value(kp: PyKeePass, value_template: str) -> str:
    """Substitutes placeholders in a string with values from Keepass."""
    new_value = value_template
    for match in PLACEHOLDER_REGEX.finditer(value_template):
        placeholder = match.group(0)
        title = match.group(1)
        # Check for quoted attribute first (group 2), then unquoted (group 3)
        attribute = match.group(2) if match.group(2) is not None else match.group(3)

        try:
            secret = get_keepass_secret(kp, title, attribute)
            if secret is not None:
                new_value = new_value.replace(placeholder, secret)
            else:
                # Set to blank if secret retrieval failed
                print(
                    f"Warning: Could not resolve placeholder {placeholder}",
                    file=sys.stderr,
                )
                new_value = new_value.replace(placeholder, "")
        except (KeePassError, ValidationError) as e:
            print(
                f"Warning: Failed to resolve placeholder {placeholder}: {e.message}",
                file=sys.stderr,
            )
            new_value = new_value.replace(placeholder, "")

    return new_value


def _load_and_validate_config() -> configparser.ConfigParser:
    """Load and validate the configuration file."""
    if not os.path.exists(CONFIG_FILENAME):
        raise ConfigFileNotFoundError(ERROR_CONFIG_FILE_NOT_FOUND)

    return validate_config_file(CONFIG_FILENAME)


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
    config: configparser.ConfigParser, kp: PyKeePass
) -> List[str]:
    """Process environment variables and return export commands."""
    if ENV_SECTION not in config:
        print(
            f"Warning: {ERROR_SECTION_MISSING_NO_VARS.format(section=ENV_SECTION, config_file=CONFIG_FILENAME)}",
            file=sys.stderr,
        )
        sys.exit(0)

    env_config = config[ENV_SECTION]
    exports: List[str] = []
    for var_name, value_template in env_config.items():
        final_value = substitute_value(kp, value_template)
        # Use shlex.quote for safe shell exporting
        exports.append(f"export {var_name.upper()}={shlex.quote(final_value)}")

    return exports


def _handle_error(error, exit_code: int) -> None:
    """Handle errors with appropriate messaging and exit codes."""
    error_type = type(error).__name__
    print(f"{error_type} Error: {error}", file=sys.stderr)
    if hasattr(error, "original_exception") and error.original_exception:
        print(f"  Original error: {error.original_exception}", file=sys.stderr)
    sys.exit(exit_code)


def _create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="keeenv",
        description="Set local environment variables from KeePass database",
        epilog="Example: eval $(keeenv)",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
        help="Show program's version number and exit",
    )

    return parser


def main() -> None:
    """Main function to read config, fetch secrets, and set the environment."""
    # Parse command line arguments
    parser = _create_argument_parser()
    parser.parse_args()

    # If --version or --help was provided, argparse will handle it and exit
    # So we only continue if no special arguments were provided

    try:
        # Load and validate configuration
        config = _load_and_validate_config()

        # Validate Keepass configuration and get paths
        validated_db_path, validated_keyfile_path = _validate_keepass_config(config)

        # Get master password
        password = _get_master_password(validated_db_path)

        # Open KeePass database
        kp = _open_keepass_database(validated_db_path, password, validated_keyfile_path)

        # Process environment variables
        exports = _process_environment_variables(config, kp)

        # Print export commands
        if exports:
            print("\n".join(exports))

    except ConfigError as e:
        _handle_error(e, 2)
    except KeePassError as e:
        _handle_error(e, 3)
    except ValidationError as e:
        _handle_error(e, 4)
    except SecurityError as e:
        _handle_error(e, 5)
    except Exception as e:
        print(f"Unexpected Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
