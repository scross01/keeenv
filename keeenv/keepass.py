import logging
import re

from keeenv.constants import (
    ERROR_DATABASE_OPEN_FAILED,
    ERROR_INVALID_PASSWORD_OR_KEYFILE,
    IDENT_RE,
    PLACEHOLDER_REGEX,
    STANDARD_ATTRS,
)
from keeenv.exceptions import (
    ConfigError,
    KeePassCredentialsError,
    KeePassEntryNotFoundError,
    KeePassError,
    SecurityError,
    ValidationError,
)
from keeenv.validation import AttributeValidator, EntryValidator
from pykeepass import PyKeePass
from pykeepass.entry import Entry
from pykeepass.exceptions import CredentialsError
from typing import Optional


class KeePassManager:
    """
    Comprehensive KeePass database manager that encapsulates all database operations.

    This class provides a unified interface for:
    - Database connection and authentication
    - Entry finding, creation, and modification
    - Attribute retrieval and manipulation
    - Placeholder processing and substitution
    """

    def __init__(
        self, db_path: str, keyfile_path: Optional[str] = None, pykeepass_class=None
    ):
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

    def connect(self, password: Optional[str] = None) -> None:
        """
        Establish connection to KeePass database.

        Args:
            password: Master password for the database (optional). If None,
                     attempts to connect without password.

        Raises:
            KeePassCredentialsError: If credentials are invalid
            KeePassError: If database opening fails
        """
        try:
            # Try to connect without password first if none provided
            if password is None:
                self.kp = self._pykeepass_class(
                    self.db_path, password=None, keyfile=self.keyfile_path
                )
                self.password = ""
                self._is_connected = True
            else:
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
