#!/usr/bin/env python3
"""
Shared constants and regex patterns used across keeenv modules.

This module contains shared constants, error messages, and regex patterns
to avoid circular imports between modules.
"""

import re

# Standard KeePass attributes
STANDARD_ATTRS = {"password", "username", "url", "notes"}

# Use Regex to find placeholders like ${"Entry Title".Attribute} or ${"Entry Title"."API Key"}
# Unified identifier regex used across placeholder parsing/formatting
IDENT_REGEX = r"[A-Za-z_][A-Za-z0-9_]*"
IDENT_RE = re.compile(rf"^{IDENT_REGEX}$")
PLACEHOLDER_REGEX = re.compile(
    rf"\$\{{\s*\"([^\"]+)\"\s*\.\s*(?:\"([^\"]*)\"|({IDENT_REGEX}))\s*\}}"
)

# Constants for error messages
ERROR_DATABASE_OPEN_FAILED = "Failed to open KeePass database"
ERROR_INVALID_PASSWORD_OR_KEYFILE = "Invalid master password or key file"
ERROR_CONFIG_FILE_NOT_FOUND = "Configuration file '{config_path}' not found."
ERROR_SECTION_MISSING = "Section '[{section}]' missing in '{config_file}'"
ERROR_KEY_MISSING = "'{key}' key missing in '[{section}]' section"
ERROR_COULD_NOT_READ_PASSWORD = "Could not read password"
ERROR_SECTION_MISSING_NO_VARS = (
    "Section '[{section}]' missing in '{config_file}'. No variables to process."
)

# Configuration constants
CONFIG_FILENAME = ".keeenv"
KEEPASS_SECTION = "keepass"
ENV_SECTION = "env"
