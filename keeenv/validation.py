"""
Input validation for keeenv - Populate environment variables from Keepass
"""

import os
import re
import logging
from pathlib import Path
from typing import Optional
from .exceptions import (
    ValidationError,
    PathValidationError,
    AttributeValidationError,
    DatabaseSecurityError,
    KeyfileSecurityError,
)

logger = logging.getLogger(__name__)

# Constants for validation limits
MAX_TITLE_LENGTH = 255
MIN_ASCII_VALUE = 32
MAX_ASCII_VALUE = 126

# Constants for regex patterns
CUSTOM_PROPERTY_PATTERN = r"^[a-zA-Z_][a-zA-Z0-9_ ]*$"

# Constants for error messages
ERROR_TITLE_TOO_LONG = f"Entry title too long (max {MAX_TITLE_LENGTH} characters)"
ERROR_TITLE_INVALID_CHARS = "Entry title contains invalid characters"
ERROR_PATH_INVALID_FORMAT = "Invalid path format"
ERROR_ATTR_INVALID_NAME = "Invalid attribute name"
ERROR_KEYFILE_WORLD_READABLE = (
    "Keyfile is world-readable. Please restrict permissions to owner only."
)
ERROR_DATABASE_WORLD_READABLE = (
    "Database file is world-readable. Please restrict permissions to owner only."
)
ERROR_PATH_MUST_BE_STRING = "Path must be a non-empty string"
ERROR_TITLE_MUST_BE_STRING = "Entry title must be a non-empty string"
ERROR_ATTR_MUST_BE_STRING = "Attribute must be a non-empty string"
ERROR_FILE_NOT_FOUND = "File not found: {path}"
ERROR_PATH_NOT_FILE = "Path is not a file: {path}"
ERROR_INVALID_PATH = "Invalid path: {error}"
ERROR_CANNOT_ACCESS_DB = "Cannot access database file: {error}"
ERROR_CANNOT_ACCESS_KEYFILE = "Cannot access keyfile: {error}"


class BaseValidator:
    """Base class for validators with common validation logic."""

    @staticmethod
    def validate_non_empty_string(value: Optional[str], field_name: str) -> str:
        """Validate that a value is a non-empty string."""
        if not value or not isinstance(value, str):
            raise ValidationError(f"{field_name} must be a non-empty string")
        return value

    @staticmethod
    def validate_string_length(value: str, max_length: int, field_name: str) -> str:
        """Validate that a string does not exceed maximum length."""
        if len(value) > max_length:
            raise ValidationError(
                f"{field_name} too long (max {max_length} characters)"
            )
        return value

    @staticmethod
    def validate_ascii_chars(value: str, field_name: str) -> str:
        """Validate that a string contains only ASCII printable characters."""
        if any(
            ord(char) < MIN_ASCII_VALUE or ord(char) > MAX_ASCII_VALUE for char in value
        ):
            raise ValidationError(f"{field_name} contains invalid characters")
        return value


class PathValidator(BaseValidator):
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
            PathValidationError: If path is invalid or file doesn't exist when required
        """
        # Validate basic string requirements
        validated_path = BaseValidator.validate_non_empty_string(path, "Path")

        # Prevent directory traversal
        if ".." in validated_path:
            raise PathValidationError(ERROR_PATH_INVALID_FORMAT)

        try:
            expanded_path = Path(validated_path).expanduser().resolve()
        except (OSError, RuntimeError) as e:
            raise PathValidationError(ERROR_INVALID_PATH.format(error=e))

        if must_exist and not expanded_path.exists():
            raise PathValidationError(ERROR_FILE_NOT_FOUND.format(path=expanded_path))

        if must_exist and not expanded_path.is_file():
            raise PathValidationError(ERROR_PATH_NOT_FILE.format(path=expanded_path))

        return expanded_path


class EntryValidator(BaseValidator):
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
            EntryTitleValidationError: If title is invalid
        """
        # Validate basic string requirements
        validated_title = BaseValidator.validate_non_empty_string(title, "Entry title")

        # Validate length
        validated_title = BaseValidator.validate_string_length(
            validated_title, MAX_TITLE_LENGTH, "Entry title"
        )

        # Validate character set
        validated_title = BaseValidator.validate_ascii_chars(
            validated_title, "Entry title"
        )

        return validated_title.strip()


class AttributeValidator(BaseValidator):
    """Validates KeePass attribute names."""

    # Single source of truth imported lazily to avoid circular imports at module load time.
    # We derive the supported attribute names from core.STANDARD_ATTRS keys.
    @staticmethod
    def _get_supported_attributes() -> set[str]:
        from .core import STANDARD_ATTRS  # late import to avoid circular dependency

        return STANDARD_ATTRS

    @staticmethod
    def is_standard_attr(name: Optional[str]) -> bool:
        """
        Return True if the provided attribute name is a supported standard field.
        Accepts None (returns False) and is case-insensitive.
        """
        if not name or not isinstance(name, str):
            return False
        return name.lower() in AttributeValidator._get_supported_attributes()

    @staticmethod
    def validate_attribute(attribute: Optional[str]) -> str:
        """
        Validate KeePass attribute name.

        Args:
            attribute: Attribute name to validate

        Returns:
            Validated attribute name

        Raises:
            AttributeValidationError: If attribute name is invalid
        """
        # Validate basic string requirements
        validated_attr = BaseValidator.validate_non_empty_string(attribute, "Attribute")

        # Check for quoted attributes (custom properties)
        if validated_attr.startswith('"') and validated_attr.endswith('"'):
            validated_attr = validated_attr[1:-1]

        if AttributeValidator.is_standard_attr(validated_attr):
            return validated_attr.lower()

        # Validate custom property names
        if not re.match(CUSTOM_PROPERTY_PATTERN, validated_attr):
            raise AttributeValidationError(
                f"{ERROR_ATTR_INVALID_NAME}: {validated_attr}"
            )

        return validated_attr


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
            DatabaseSecurityError: If database security checks fail
            KeyfileSecurityError: If keyfile security checks fail
        """
        try:
            db_stat = os.stat(db_path)
        except OSError as e:
            # Log an error before raising to satisfy tests expecting ERROR-level log
            logger.error("%s %s", ERROR_CANNOT_ACCESS_DB.format(error=e), db_path)
            raise DatabaseSecurityError(ERROR_CANNOT_ACCESS_DB.format(error=e))

        # Only perform POSIX permission checks on POSIX systems
        if os.name == "posix":
            # Check if database is world-readable
            if db_stat.st_mode & 0o044:
                # Downgrade to warning (respect --quiet/--verbose)
                logger.warning("%s %s", ERROR_DATABASE_WORLD_READABLE, db_path)

            # Check keyfile permissions if present
            if keyfile_path:
                try:
                    key_stat = os.stat(keyfile_path)
                    if key_stat.st_mode & 0o044:
                        logger.warning(
                            "%s %s", ERROR_KEYFILE_WORLD_READABLE, keyfile_path
                        )
                except OSError as e:
                    logger.error(
                        "%s %s",
                        ERROR_CANNOT_ACCESS_KEYFILE.format(error=e),
                        keyfile_path,
                    )
                    raise KeyfileSecurityError(
                        ERROR_CANNOT_ACCESS_KEYFILE.format(error=e)
                    )
        else:
            # On non-POSIX systems, skip mode-bit checks
            if keyfile_path:
                try:
                    # Still attempt to access keyfile to surface access errors
                    os.stat(keyfile_path)
                except OSError as e:
                    logger.error(
                        "%s %s",
                        ERROR_CANNOT_ACCESS_KEYFILE.format(error=e),
                        keyfile_path,
                    )
                    raise KeyfileSecurityError(
                        ERROR_CANNOT_ACCESS_KEYFILE.format(error=e)
                    )
