#!/usr/bin/env python3
# keeenv.py - A script to export environment variables from a KeePass database

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
    KeePassError,
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


def get_keepass_secret(kp: PyKeePass, title: str, attribute: str) -> Optional[str]:
    """Fetches a specific attribute from a Keepass entry by title."""
    try:
        # Validate inputs
        validated_title = EntryValidator.validate_entry_title(title)
        validated_attr = AttributeValidator.validate_attribute(attribute)

        entry = kp.find_entries(title=validated_title, first=True)
        if entry:
            # Common attributes
            if validated_attr.lower() == "password":
                return entry.password  # pyright: ignore[reportAttributeAccessIssue]
            elif validated_attr.lower() == "username":
                return entry.username  # pyright: ignore[reportAttributeAccessIssue]
            elif validated_attr.lower() == "url":
                return entry.url  # pyright: ignore[reportAttributeAccessIssue]
            elif validated_attr.lower() == "notes":
                return entry.notes  # pyright: ignore[reportAttributeAccessIssue]
            # Custom string fields
            elif (
                hasattr(entry, "custom_properties")
                and isinstance(
                    entry.custom_properties, dict
                )  # pyright: ignore[reportAttributeAccessIssue]
                and validated_attr
                in entry.custom_properties  # pyright: ignore[reportAttributeAccessIssue]
            ):
                return entry.custom_properties[
                    validated_attr
                ]  # pyright: ignore[reportAttributeAccessIssue]
            else:
                raise KeePassError(
                    f"Attribute '{validated_attr}' not found for entry '{validated_title}'"
                )
        else:
            raise KeePassError(f"Entry with title '{validated_title}' not found")
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


def main() -> None:
    """Main function to read config, fetch secrets, and set the environment."""
    try:
        if not os.path.exists(CONFIG_FILENAME):
            raise ConfigError(f"Configuration file '{CONFIG_FILENAME}' not found.")

        # Use the new configuration validation function
        config = validate_config_file(CONFIG_FILENAME)

        # --- Keepass Configuration ---
        if KEEPASS_SECTION not in config:
            raise ConfigError(
                f"Section '[{KEEPASS_SECTION}]' missing in '{CONFIG_FILENAME}'"
            )

        keepass_config = config[KEEPASS_SECTION]
        db_path: Optional[str] = keepass_config.get("database")
        keyfile_path: Optional[str] = keepass_config.get("keyfile")

        if not db_path:
            raise ConfigError(
                f"'database' key missing in '[{KEEPASS_SECTION}]' section"
            )

        db_path = os.path.expanduser(db_path)  # Expand ~ in path

        # Validate database path
        validated_db_path = str(PathValidator.validate_file_path(db_path))

        if keyfile_path:
            keyfile_path = os.path.expanduser(keyfile_path)
            # Validate keyfile path
            validated_keyfile_path = str(PathValidator.validate_file_path(keyfile_path))

        # Validate file security
        SecurityValidator.validate_database_security(
            validated_db_path, validated_keyfile_path if keyfile_path else None
        )

        # --- Get Master Password ---
        try:
            password = getpass.getpass(
                f"Enter master password for {os.path.basename(db_path)}: "
            )
        except EOFError:
            raise KeePassError("Could not read password")

        # --- Open Keepass Database ---
        try:
            kp: PyKeePass = PyKeePass(db_path, password=password, keyfile=keyfile_path)
        except CredentialsError:
            raise KeePassError("Invalid master password or key file")
        except Exception as e:
            raise KeePassError(f"Failed to open KeePass database: {e}")

        # --- Environment Variable Processing ---
        if ENV_SECTION not in config:
            print(
                f"Warning: Section '[{ENV_SECTION}]' missing in '{CONFIG_FILENAME}'. No variables to process.",
                file=sys.stderr,
            )
            sys.exit(0)

        env_config = config[ENV_SECTION]
        exports: List[str] = []
        for var_name, value_template in env_config.items():
            final_value = substitute_value(kp, value_template)
            # Use shlex.quote for safe shell exporting
            exports.append(f"export {var_name.upper()}={shlex.quote(final_value)}")

        # --- Print Export Commands ---
        if exports:
            print("\n".join(exports))

    except ConfigError as e:
        print(f"Configuration Error: {e.message}", file=sys.stderr)
        if e.original_exception:
            print(f"  Original error: {e.original_exception}", file=sys.stderr)
        sys.exit(2)
    except KeePassError as e:
        print(f"KeePass Error: {e.message}", file=sys.stderr)
        if e.original_exception:
            print(f"  Original error: {e.original_exception}", file=sys.stderr)
        sys.exit(3)
    except ValidationError as e:
        print(f"Validation Error: {e.message}", file=sys.stderr)
        if e.original_exception:
            print(f"  Original error: {e.original_exception}", file=sys.stderr)
        sys.exit(4)
    except SecurityError as e:
        print(f"Security Error: {e.message}", file=sys.stderr)
        if e.original_exception:
            print(f"  Original error: {e.original_exception}", file=sys.stderr)
        sys.exit(5)
    except Exception as e:
        print(f"Unexpected Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
