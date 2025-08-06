"""
Input validation for keeenv - Populate environment variables from Keepass
"""

import os
import re
from pathlib import Path
from typing import Optional
from .exceptions import ValidationError


class PathValidator:
    """Validates file paths with security checks."""

    @staticmethod
    def validate_file_path(path: Optional[str], must_exist: bool = True) -> Path:
        """
        Validate file path with security checks.

        Args:
            path: File path to validate
            must_exist: Whether the file must exist

        Returns:
            Validated Path object

        Raises:
            ValidationError: If path is invalid or file doesn't exist when required
        """
        if not path or not isinstance(path, str):
            raise ValidationError("Path must be a non-empty string")

        # Prevent directory traversal
        if ".." in path or path.startswith("~"):
            raise ValidationError("Invalid path format")

        try:
            expanded_path = Path(path).expanduser().resolve()
        except (OSError, RuntimeError) as e:
            raise ValidationError(f"Invalid path: {e}")

        if must_exist and not expanded_path.exists():
            raise ValidationError(f"File not found: {expanded_path}")

        if must_exist and not expanded_path.is_file():
            raise ValidationError(f"Path is not a file: {expanded_path}")

        return expanded_path


class EntryValidator:
    """Validates KeePass entry titles."""

    @staticmethod
    def validate_entry_title(title: Optional[str]) -> str:
        """
        Validate KeePass entry title.

        Args:
            title: Entry title to validate

        Returns:
            Validated and stripped title

        Raises:
            ValidationError: If title is invalid
        """
        if not title or not isinstance(title, str):
            raise ValidationError("Entry title must be a non-empty string")

        if len(title) > 255:
            raise ValidationError("Entry title too long (max 255 characters)")

        # Basic sanitization
        if any(ord(char) < 32 or ord(char) > 126 for char in title):
            raise ValidationError("Entry title contains invalid characters")

        return title.strip()


class AttributeValidator:
    """Validates KeePass attribute names."""

    SUPPORTED_ATTRIBUTES = {"username", "password", "url", "notes"}

    @staticmethod
    def validate_attribute(attribute: Optional[str]) -> str:
        """
        Validate KeePass attribute name.

        Args:
            attribute: Attribute name to validate

        Returns:
            Validated attribute name

        Raises:
            ValidationError: If attribute name is invalid
        """
        if not attribute or not isinstance(attribute, str):
            raise ValidationError("Attribute must be a non-empty string")

        # Check for quoted attributes (custom properties)
        if attribute.startswith('"') and attribute.endswith('"'):
            attribute = attribute[1:-1]

        if attribute.lower() in AttributeValidator.SUPPORTED_ATTRIBUTES:
            return attribute.lower()

        # Validate custom property names
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_ ]*$", attribute):
            raise ValidationError(f"Invalid attribute name: {attribute}")

        return attribute


class SecurityValidator:
    """Validates security aspects of KeePass files."""

    @staticmethod
    def validate_database_security(
        db_path: str, keyfile_path: Optional[str] = None
    ) -> None:
        """
        Validate file permissions and security.

        Args:
            db_path: Path to KeePass database
            keyfile_path: Optional path to keyfile

        Raises:
            ValidationError: If security checks fail
        """
        try:
            db_stat = os.stat(db_path)
        except OSError as e:
            raise ValidationError(f"Cannot access database file: {e}")

        # Check if database is world-readable
        if db_stat.st_mode & 0o044:
            raise ValidationError(
                f"Database file {db_path} is world-readable. "
                "Please restrict permissions to owner only."
            )

        # Check keyfile permissions if present
        if keyfile_path:
            try:
                key_stat = os.stat(keyfile_path)
                if key_stat.st_mode & 0o044:
                    raise ValidationError(
                        f"Keyfile {keyfile_path} is world-readable. "
                        "Please restrict permissions to owner only."
                    )
            except OSError as e:
                raise ValidationError(f"Cannot access keyfile: {e}")
