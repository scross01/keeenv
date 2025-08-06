#!/usr/bin/env python3
# keeenv.py - A script to export environment variables from a KeePass database

import configparser
import getpass
import os
import re
import sys
import shlex
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError

CONFIG_FILENAME = ".keeenv"
KEEPASS_SECTION = "keepass"
ENV_SECTION = "env"

# Regex to find placeholders like ${"Entry Title".Attribute} or ${"Entry Title"."API Key"}
PLACEHOLDER_REGEX = re.compile(
    r"\$\{\s*\"([^\"]+)\"\s*\.\s*(?:\"([^\"]*)\"|(\w+))\s*\}"
)


def get_keepass_secret(kp, title, attribute):
    """Fetches a specific attribute from a Keepass entry by title."""
    try:
        entry = kp.find_entries(title=title, first=True)
        if entry:
            # Common attributes
            if attribute.lower() == "password":
                return entry.password
            elif attribute.lower() == "username":
                return entry.username
            elif attribute.lower() == "url":
                return entry.url
            elif attribute.lower() == "notes":
                return entry.notes
            # Custom string fields
            elif attribute in entry.custom_properties:
                return entry.custom_properties[attribute]
            else:
                print(
                    f"Warning: Attribute '{attribute}' not found for entry '{title}'.",
                    file=sys.stderr,
                )
                return None
        else:
            print(f"Warning: Entry with title '{title}' not found.", file=sys.stderr)
            return None
    except Exception as e:
        print(f"Error accessing entry '{title}': {e}", file=sys.stderr)
        return None


def substitute_value(kp, value_template):
    """Substitutes placeholders in a string with values from Keepass."""
    new_value = value_template
    for match in PLACEHOLDER_REGEX.finditer(value_template):
        placeholder = match.group(0)
        title = match.group(1)
        # Check for quoted attribute first (group 2), then unquoted (group 3)
        attribute = match.group(2) if match.group(2) is not None else match.group(3)

        secret = get_keepass_secret(kp, title, attribute)
        if secret is not None:
            new_value = new_value.replace(placeholder, secret)
        else:
            # Set to blank if secret retrieval failed
            print(
                f"Warning: Could not resolve placeholder {placeholder}", file=sys.stderr
            )
            new_value = new_value.replace(placeholder, "")

    return new_value


def main():
    """Main function to read config, fetch secrets, and set the environment."""
    if not os.path.exists(CONFIG_FILENAME):
        print(
            f"Error: Configuration file '{CONFIG_FILENAME}' not found.", file=sys.stderr
        )
        sys.exit(1)

    config = configparser.ConfigParser()
    try:
        config.read(CONFIG_FILENAME)
    except configparser.Error as e:
        print(
            f"Error parsing configuration file '{CONFIG_FILENAME}': {e}",
            file=sys.stderr,
        )
        sys.exit(1)

    # --- Keepass Configuration ---
    if KEEPASS_SECTION not in config:
        print(
            f"Error: Section '[{KEEPASS_SECTION}]' missing in '{CONFIG_FILENAME}'.",
            file=sys.stderr,
        )
        sys.exit(1)

    keepass_config = config[KEEPASS_SECTION]
    db_path = keepass_config.get("database")
    keyfile_path = keepass_config.get("keyfile")

    if not db_path:
        print(
            f"Error: 'database' key missing in '[{KEEPASS_SECTION}]' section.",
            file=sys.stderr,
        )
        sys.exit(1)

    db_path = os.path.expanduser(db_path)  # Expand ~ in path

    if not os.path.exists(db_path):
        print(f"Error: Keepass database file not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    if keyfile_path:
        keyfile_path = os.path.expanduser(keyfile_path)
        if not os.path.exists(keyfile_path):
            print(f"Error: Keepass key file not found: {keyfile_path}", file=sys.stderr)
            sys.exit(1)

    # --- Get Master Password ---
    try:
        password = getpass.getpass(
            f"Enter master password for {os.path.basename(db_path)}: "
        )
    except EOFError:
        print("\nError: Could not read password.", file=sys.stderr)
        sys.exit(1)

    # --- Open Keepass Database ---
    try:
        kp = PyKeePass(db_path, password=password, keyfile=keyfile_path)
    except CredentialsError:
        print("Error: Invalid master password or key file.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error opening Keepass database: {e}", file=sys.stderr)
        sys.exit(1)

    # --- Environment Variable Processing ---
    if ENV_SECTION not in config:
        print(
            f"Warning: Section '[{ENV_SECTION}]' missing in '{CONFIG_FILENAME}'. No variables to process.",
            file=sys.stderr,
        )
        sys.exit(0)

    env_config = config[ENV_SECTION]
    exports = []
    for var_name, value_template in env_config.items():
        final_value = substitute_value(kp, value_template)
        # Use shlex.quote for safe shell exporting
        exports.append(f"export {var_name.upper()}={shlex.quote(final_value)}")

    # --- Print Export Commands ---
    if exports:
        print("\n".join(exports))


if __name__ == "__main__":
    main()
