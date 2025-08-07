#!/usr/bin/env python3
# keeenv.py - A script to export environment variables from a KeePass database

import argparse
import configparser
import getpass
import os
import re
import shlex
import logging
import sys
from typing import Optional, List
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError
from pykeepass.entry import Entry

from .exceptions import (
    ConfigError,
    ConfigFileNotFoundError,
    ConfigSectionMissingError,
    ConfigKeyMissingError,
    KeePassError,
    KeePassCredentialsError,
    KeePassEntryNotFoundError,
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
STANDARD_ATTRS = {"password", "username", "url", "notes"}


class KeePassManager:
    """
    Comprehensive KeePass database manager that encapsulates all database operations.

    This class provides a unified interface for:
    - Database connection and authentication
    - Entry finding, creation, and modification
    - Attribute retrieval and manipulation
    - Placeholder processing and substitution
    """

    def __init__(self, db_path: str, keyfile_path: Optional[str] = None, pykeepass_class=None):
        """
        Initialize KeePassManager with database configuration.

        Args:
            db_path: Path to the KeePass database file
            keyfile_path: Optional path to the keyfile
            pykeepass_class: Optional PyKeePass class for testing (dependency injection)
        """
        self.db_path = db_path
        self.keyfile_path = keyfile_path
        self.password = ""
        self.kp = None
        self._is_connected = False
        self._pykeepass_class = pykeepass_class or PyKeePass

    def connect(self, password: str) -> None:
        """
        Establish connection to KeePass database.

        Args:
            password: Master password for the database

        Raises:
            KeePassCredentialsError: If credentials are invalid
            KeePassError: If database opening fails
        """
        try:
            self.kp = self._pykeepass_class(
                self.db_path, password=password, keyfile=self.keyfile_path
            )
            self.password = password
            self._is_connected = True
        except CredentialsError:
            raise KeePassCredentialsError(ERROR_INVALID_PASSWORD_OR_KEYFILE)
        except Exception as e:
            raise KeePassError(f"{ERROR_DATABASE_OPEN_FAILED}: {e}")

    def disconnect(self) -> None:
        """Close database connection and clean up resources."""
        if self.kp:
            self.kp = None
        self.password = ""
        self._is_connected = False

    def is_connected(self) -> bool:
        """Check if database connection is active."""
        return self._is_connected

    def find_entry(self, title: str, create_if_missing: bool = False) -> tuple:
        """
        Find a KeePass entry by title, with optional group path support.

        Args:
            title: Entry title, may include group path separated by '/'
            create_if_missing: If True, create missing groups (used in _cmd_add)

        Returns:
            tuple: (entry, group, final_title)

        Raises:
            KeePassEntryNotFoundError: If entry is not found and create_if_missing is False
        """
        if not self._is_connected:
            raise KeePassError("Database not connected. Call connect() first.")

        # Cache capability checks to avoid repeated hasattr and pyright ignores in branches
        has_find_groups = hasattr(self.kp, "find_groups")
        has_find_entries = hasattr(self.kp, "find_entries")

        def _find_subgroup(parent_group, gname):
            if has_find_groups:
                return self.kp.find_groups(name=gname, group=parent_group, first=True)  # type: ignore[misc]
            # Manual scan fallback
            for child in getattr(
                parent_group, "subgroups", []
            ):  # pyright: ignore[reportAttributeAccessIssue]
                if getattr(child, "name", None) == gname:
                    return child
            return None

        def _find_entry_in_group(group, entry_title):
            if has_find_entries:
                return self.kp.find_entries(title=entry_title, group=group, first=True)  # type: ignore[misc]
            for e in getattr(
                group, "entries", []
            ):  # pyright: ignore[reportAttributeAccessIssue]
                if getattr(e, "title", None) == entry_title:
                    return e
            return None

        # Split path into group path and entry title
        parts = [p for p in title.split("/") if p != ""]

        if len(parts) > 1:
            group_names = parts[:-1]
            entry_title = parts[-1]

            current_group = (
                self.kp.root_group if self.kp else None
            )  # pyright: ignore[reportAttributeAccessIssue]
            for gname in group_names:
                next_group = _find_subgroup(current_group, gname)

                if not next_group and create_if_missing:
                    next_group = self.kp.add_group(current_group, gname)  # type: ignore[misc]
                elif not next_group:
                    raise KeePassEntryNotFoundError(
                        f"Group path '{'/'.join(group_names)}' not found for '{title}'"
                    )

                current_group = next_group  # type: ignore[assignment]

            entry = _find_entry_in_group(current_group, entry_title)
            return entry, current_group, entry_title
        else:
            # No group path → search anywhere or in root group
            if has_find_entries:
                entry = self.kp.find_entries(title=title, first=True)  # type: ignore[misc]
            else:
                # Fallback: search in root group entries only
                entry = None
                entries = getattr(self.kp.root_group, "entries", []) if self.kp else []
                for e in entries:  # pyright: ignore[reportAttributeAccessIssue]
                    if getattr(e, "title", None) == title:
                        entry = e
                        break
            return (
                entry,
                self.kp.root_group if self.kp else None,
                title,
            )  # pyright: ignore[reportAttributeAccessIssue]

    def get_secret(self, title: str, attribute: str) -> Optional[str]:
        """
        Fetch a specific attribute from a KeePass entry by title.

        Tries standard attributes first, then custom properties. Behavior preserved.

        Args:
            title: Entry title
            attribute: Attribute name to retrieve

        Returns:
            Attribute value or None if not found

        Raises:
            KeePassError: If entry is not found or access fails
            ValidationError: If title or attribute validation fails
        """
        try:
            validated_title = EntryValidator.validate_entry_title(title)
            validated_attr = AttributeValidator.validate_attribute(attribute)

            entry, _, _ = self.find_entry(validated_title, create_if_missing=False)
            if entry is None:
                raise KeePassError(f"Entry with title '{validated_title}' not found")

            # Try standard attributes first
            standard_value = self._get_standard_attribute(entry, validated_attr)
            if standard_value is not None:
                return standard_value

            # Try custom attributes
            custom_value = self._get_custom_attribute(entry, validated_attr)
            if custom_value is not None:
                return custom_value

            # Attribute not found -> let it fall through to generic wrapper for test expectation
            raise AttributeError(validated_attr)
        except (ValidationError, KeePassCredentialsError, SecurityError, ConfigError):
            # Preserve explicit domain exceptions that should map directly
            raise
        except Exception as e:
            # Minimal context wrapper to match expected message in tests
            raise KeePassError(f"Failed to access entry '{title}': {str(e)}")

    def _get_standard_attribute(self, entry, attribute: str) -> Optional[str]:
        """Get standard attribute from KeePass entry using STANDARD_ATTRS membership."""
        attr_lower = attribute.lower()
        if attr_lower not in STANDARD_ATTRS:
            return None
        # attr_lower is one of the standard names and matches the entry attribute
        return getattr(entry, attr_lower)  # pyright: ignore[reportAttributeAccessIssue]

    def _get_custom_attribute(self, entry, attribute: str) -> Optional[str]:
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

    def set_entry_attribute(
        self, entry, attr: str, value: str, original_attr: str, title: str
    ) -> None:
        """
        Set an attribute on a KeePass entry.

        - Uses STANDARD_ATTRS for standard attributes: password, username, url, notes
        - Falls back to creating/updating a custom property for non-standard attributes
        - original_attr preserves caller's validated attribute (may have case for custom)
        - title is used only for consistent error messages
        """
        try:
            # Standard attributes via membership (attribute name matches entry field)
            attr_lower = attr.lower()
            if attr_lower in STANDARD_ATTRS:
                setattr(
                    entry, attr_lower, value
                )  # pyright: ignore[reportAttributeAccessIssue]
                return

            # custom property path
            if hasattr(
                entry, "set_custom_property"
            ):  # pyright: ignore[reportAttributeAccessIssue]
                getattr(entry, "set_custom_property")(original_attr, value)  # type: ignore[misc]
            else:
                has_props = hasattr(
                    entry, "custom_properties"
                )  # pyright: ignore[reportAttributeAccessIssue]
                props_is_dict = has_props and isinstance(
                    getattr(entry, "custom_properties"), dict
                )  # pyright: ignore[reportAttributeAccessIssue]
                if not props_is_dict:
                    setattr(entry, "custom_properties", {})  # type: ignore[misc]
                entry.custom_properties[original_attr] = (
                    value  # pyright: ignore[reportAttributeAccessIssue]
                )
        except Exception as e:
            raise KeePassError(
                f"Failed to set custom attribute '{original_attr}' on '{title}'",
                e,
            )

    def substitute_placeholders(self, value_template: str, strict: bool = False) -> str:
        """
        Substitutes placeholders in a string with values from KeePass.

        Uses a single-pass re.sub with a callable to avoid accidental double replacement
        when resolved secrets contain placeholder-like patterns.

        Args:
            value_template: String containing placeholders
            strict: If True, raise ValidationError for unresolved placeholders

        Returns:
            String with placeholders replaced by actual values
        """
        logger = logging.getLogger(__name__)

        def _replace(match: re.Match) -> str:
            placeholder = match.group(0)
            title = match.group(1)
            # Check for quoted attribute first (group 2), then unquoted (group 3)
            attribute = match.group(2) if match.group(2) is not None else match.group(3)

            try:
                secret = self.get_secret(title, attribute)
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
                elif isinstance(e, KeePassError):
                    # For KeePassError, always re-raise since it's a connection/configuration issue
                    raise
                else:
                    # For ValidationError, only log in non-strict mode
                    logger.warning(
                        "Failed to resolve placeholder %s: %s", placeholder, str(e)
                    )
                    return ""

        return PLACEHOLDER_REGEX.sub(_replace, value_template)

    def format_placeholder(self, title: str, attr: str) -> str:
        """
        Format a placeholder string ${"Title".Attr} using the same identifier rules
        as the substitution regex. Always quote the title, and quote attribute only
        when it is not a valid identifier ([A-Za-z_][A-Za-z0-9_]*).
        """
        # Attribute needs quotes if not a valid identifier
        needs_quote = not IDENT_RE.match(attr)
        placeholder_attr = f'"{attr}"' if needs_quote else attr
        return f'${{"{title}".{placeholder_attr}}}'

    def save_database(self) -> None:
        """Save changes to KeePass database."""
        if not self._is_connected:
            raise KeePassError("Database not connected. Call connect() first.")

        try:
            self.kp.save() if self.kp else None
        except Exception as e:
            raise KeePassError("Failed to save KeePass database", e)

    def create_entry(
        self,
        title: str,
        username: str = "",
        password: str = "",
        url: str = "",
        notes: str = "",
    ) -> "Entry":  # type: ignore
        """
        Create a new entry in the KeePass database.

        Args:
            title: Entry title
            username: Username field (optional)
            password: Password field (optional)
            url: URL field (optional)
            notes: Notes field (optional)

        Returns:
            Created entry object
        """
        if not self._is_connected:
            raise KeePassError("Database not connected. Call connect() first.")

        validated_title = EntryValidator.validate_entry_title(title)

        if not self.kp:
            raise KeePassError("Database not connected. Call connect() first.")
        entry = self.kp.add_entry(
            self.kp.root_group,  # pyright: ignore[reportAttributeAccessIssue]
            title=validated_title,
            username=username,
            password=password,
        )

        if url:
            entry.url = url  # pyright: ignore[reportAttributeAccessIssue]
        if notes:
            entry.notes = notes  # pyright: ignore[reportAttributeAccessIssue]

        return entry

    def update_entry(
        self,
        entry,
        username: Optional[str] = None,
        url: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> None:
        """
        Update an existing entry in the KeePass database.

        Args:
            entry: Entry object to update
            username: New username value (optional)
            url: New URL value (optional)
            notes: New notes value (optional)
        """
        if not self._is_connected:
            raise KeePassError("Database not connected. Call connect() first.")

        if username is not None:
            entry.username = username  # pyright: ignore[reportAttributeAccessIssue]
        if url is not None:
            entry.url = url  # pyright: ignore[reportAttributeAccessIssue]
        if notes is not None:
            entry.notes = notes  # pyright: ignore[reportAttributeAccessIssue]


# Backward compatibility functions - delegate to KeePassManager
def get_keepass_secret(kp: PyKeePass, title: str, attribute: str) -> Optional[str]:
    """
    Legacy function - delegates to KeePassManager.

    This function is kept for backward compatibility. New code should use
    KeePassManager.get_secret() instead.
    """
    import warnings

    warnings.warn(
        "get_keepass_secret() is deprecated. Use KeePassManager.get_secret() instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    # Create a KeePassManager with the provided PyKeePass instance and connect it
    manager = KeePassManager("", "", pykeepass_class=lambda *args, **kwargs: kp)
    manager.connect("")  # Use empty password for mock
    try:
        return manager.get_secret(title, attribute)
    except KeePassError as e:
        # Only catch connection errors, not entry/attribute not found errors
        if "Database not connected" in str(e):
            return None
        else:
            raise  # Re-raise other KeePassErrors
    finally:
        manager.disconnect()


def substitute_value(kp: PyKeePass, value_template: str, strict: bool = False) -> str:
    """
    Legacy function - delegates to KeePassManager.

    This function is kept for backward compatibility. New code should use
    KeePassManager.substitute_placeholders() instead.
    """
    import warnings

    warnings.warn(
        "substitute_value() is deprecated. Use KeePassManager.substitute_placeholders() instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    # Create a KeePassManager with the provided PyKeePass instance and connect it
    manager = KeePassManager("", "", pykeepass_class=lambda *args, **kwargs: kp)
    manager.connect("")  # Use empty password for mock
    try:
        result = manager.substitute_placeholders(value_template, strict)
        return result
    except Exception:
        # For backward compatibility, remove unresolved placeholders instead of raising errors
        # This preserves the legacy behavior where unresolved placeholders are silently removed
        import re
        # Remove all placeholders that couldn't be resolved
        return re.sub(r'\$\{[^}]+\}', '', value_template)
    finally:
        manager.disconnect()


# Use Regex to find placeholders like ${"Entry Title".Attribute} or ${"Entry Title"."API Key"}
# Unified identifier regex used across placeholder parsing/formatting
IDENT_REGEX = r"[A-Za-z_][A-Za-z0-9_]*"
IDENT_RE = re.compile(rf"^{IDENT_REGEX}$")
PLACEHOLDER_REGEX = re.compile(
    rf"\$\{{\s*\"([^\"]+)\"\s*\.\s*(?:\"([^\"]*)\"|({IDENT_REGEX}))\s*\}}"
)

# Constants for error messages
ERROR_CONFIG_FILE_NOT_FOUND = "Configuration file '{config_path}' not found."
ERROR_SECTION_MISSING = "Section '[{section}]' missing in '{config_file}'"
ERROR_KEY_MISSING = "'{key}' key missing in '[{section}]' section"
ERROR_COULD_NOT_READ_PASSWORD = "Could not read password"
ERROR_INVALID_PASSWORD_OR_KEYFILE = "Invalid master password or key file"
ERROR_DATABASE_OPEN_FAILED = "Failed to open KeePass database"
ERROR_SECTION_MISSING_NO_VARS = (
    "Section '[{section}]' missing in '{config_file}'. No variables to process."
)


def _find_keepass_entry(kp, title, create_if_missing=False):
    """
    Find a KeePass entry by title, with optional group path support.

    Args:
        kp: PyKeePass instance
        title: Entry title, may include group path separated by '/'
        create_if_missing: If True, create missing groups (used in _cmd_add)

    Returns:
        tuple: (entry, group, final_title)
    """
    # Cache capability checks to avoid repeated hasattr and pyright ignores in branches
    has_find_groups = hasattr(kp, "find_groups")
    has_find_entries = hasattr(kp, "find_entries")

    def _find_subgroup(parent_group, gname):
        if has_find_groups:
            return kp.find_groups(name=gname, group=parent_group, first=True)  # type: ignore[misc]
        # Manual scan fallback
        for child in getattr(
            parent_group, "subgroups", []
        ):  # pyright: ignore[reportAttributeAccessIssue]
            if getattr(child, "name", None) == gname:
                return child
        return None

    def _find_entry_in_group(group, entry_title):
        if has_find_entries:
            return kp.find_entries(title=entry_title, group=group, first=True)  # type: ignore[misc]
        for e in getattr(
            group, "entries", []
        ):  # pyright: ignore[reportAttributeAccessIssue]
            if getattr(e, "title", None) == entry_title:
                return e
        return None

    # Split path into group path and entry title
    parts = [p for p in title.split("/") if p != ""]

    if len(parts) > 1:
        group_names = parts[:-1]
        entry_title = parts[-1]

        current_group = kp.root_group  # pyright: ignore[reportAttributeAccessIssue]
        for gname in group_names:
            next_group = _find_subgroup(current_group, gname)

            if not next_group and create_if_missing:
                next_group = kp.add_group(current_group, gname)  # type: ignore[misc]
            elif not next_group:
                raise KeePassEntryNotFoundError(
                    f"Group path '{'/'.join(group_names)}' not found for '{title}'"
                )

            current_group = next_group  # type: ignore[assignment]

        entry = _find_entry_in_group(current_group, entry_title)
        return entry, current_group, entry_title
    else:
        # No group path → search anywhere or in root group
        if has_find_entries:
            entry = kp.find_entries(title=title, first=True)  # type: ignore[misc]
        else:
            # Fallback: search in root group entries only
            entry = None
            for e in getattr(
                kp.root_group, "entries", []
            ):  # pyright: ignore[reportAttributeAccessIssue]
                if getattr(e, "title", None) == title:
                    entry = e
                    break
        return (
            entry,
            kp.root_group,
            title,
        )  # pyright: ignore[reportAttributeAccessIssue]


def make_case_preserving_config() -> configparser.ConfigParser:
    """
    Create a ConfigParser that preserves case for options and section names.

    - optionxform is disabled so option/ENV var case is preserved on read/write
    - _dict is set to builtin dict so section case is preserved on write
    """

    class _CasePreservingConfig(configparser.ConfigParser):
        def optionxform(self, optionstr: str) -> str:  # type: ignore[override]
            return optionstr

    cfg = _CasePreservingConfig()
    # Preserve section case on write (ConfigParser may lowercase without this)
    cfg._dict = dict  # type: ignore[attr-defined]
    return cfg


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

        # Use a case-preserving ConfigParser
        config = make_case_preserving_config()

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
    """Get standard attribute from KeePass entry using STANDARD_ATTRS membership."""
    attr_lower = attribute.lower()
    if attr_lower not in STANDARD_ATTRS:
        return None
    # attr_lower is one of the standard names and matches the entry attribute
    return getattr(entry, attr_lower)  # pyright: ignore[reportAttributeAccessIssue]


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


def _load_and_validate_config(config_path: str) -> configparser.ConfigParser:
    """Load and validate the configuration file."""
    if not os.path.exists(config_path):
        raise ConfigFileNotFoundError(
            ERROR_CONFIG_FILE_NOT_FOUND.format(config_path=config_path)
        )
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


def _format_placeholder(title: str, attr: str) -> str:
    """
    Format a placeholder string ${"Title".Attr} using the same identifier rules
    as the substitution regex. Always quote the title, and quote attribute only
    when it is not a valid identifier ([A-Za-z_][A-Za-z0-9_]*).
    """
    # Attribute needs quotes if not a valid identifier
    needs_quote = not IDENT_RE.match(attr)
    placeholder_attr = f'"{attr}"' if needs_quote else attr
    return f'${{"{title}".{placeholder_attr}}}'


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
                cfg = make_case_preserving_config()
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
    cfg = make_case_preserving_config()
    cfg[KEEPASS_SECTION] = {"database": kdbx_path}
    if keyfile:
        cfg[KEEPASS_SECTION]["keyfile"] = os.path.expanduser(keyfile)
    # Include empty [env] section when creating a new file
    cfg[ENV_SECTION] = {}

    with open(target, "w", encoding="utf-8") as f:
        cfg.write(f)

    logger.info("Created new config at %s", target)


def _set_entry_attribute(
    entry, attr_lower: str, value: str, original_attr_name: str, title_for_error: str
) -> None:
    """
    Set an attribute on a KeePass entry.

    - Uses STANDARD_ATTRS for standard attributes: password, username, url, notes
    - Falls back to creating/updating a custom property for non-standard attributes
    - original_attr_name preserves caller's validated attribute (may have case for custom)
    - title_for_error is used only for consistent error messages
    """
    try:
        # Standard attributes via membership (attribute name matches entry field)
        if attr_lower in STANDARD_ATTRS:
            setattr(
                entry, attr_lower, value
            )  # pyright: ignore[reportAttributeAccessIssue]
            return

        # custom property path
        if hasattr(
            entry, "set_custom_property"
        ):  # pyright: ignore[reportAttributeAccessIssue]
            getattr(entry, "set_custom_property")(original_attr_name, value)  # type: ignore[misc]
        else:
            has_props = hasattr(
                entry, "custom_properties"
            )  # pyright: ignore[reportAttributeAccessIssue]
            props_is_dict = (
                has_props
                and isinstance(  # pyright: ignore[reportAttributeAccessIssue]
                    getattr(entry, "custom_properties"), dict
                )
            )
            if not props_is_dict:
                setattr(entry, "custom_properties", {})  # type: ignore[misc]
            entry.custom_properties[original_attr_name] = (
                value  # pyright: ignore[reportAttributeAccessIssue]
            )
    except Exception as e:
        raise KeePassError(
            f"Failed to set custom attribute '{original_attr_name}' on '{title_for_error}'",
            e,
        )


# Ensure two blank lines before top-level defs for flake8/PEP8


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

    # Update .keeenv mapping
    if ENV_SECTION not in cfg:
        cfg[ENV_SECTION] = {}

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

        # Use KeePassManager for database operations
        kp_manager = KeePassManager(validated_db_path, validated_keyfile_path)
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
