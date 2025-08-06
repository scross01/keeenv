"""
Custom exceptions for keeenv - Populate environment variables from Keepass
"""

from typing import Optional


class KeeenvError(Exception):
    """Base exception for keeenv errors."""

    def __init__(self, message: str, original_exception: Optional[Exception] = None):
        """
        Initialize keeenv error.

        Args:
            message: Error message
            original_exception: Original exception that caused this error
        """
        self.message = message
        self.original_exception = original_exception
        super().__init__(self.message)


class ConfigError(KeeenvError):
    """Configuration-related errors."""

    def __init__(self, message: str, original_exception: Optional[Exception] = None):
        """
        Initialize configuration error.

        Args:
            message: Error message
            original_exception: Original exception that caused this error
        """
        super().__init__(message, original_exception)


class ConfigFileNotFoundError(ConfigError):
    """Raised when configuration file is not found."""
    pass


class ConfigSectionMissingError(ConfigError):
    """Raised when required configuration section is missing."""
    pass


class ConfigKeyMissingError(ConfigError):
    """Raised when required configuration key is missing."""
    pass


class KeePassError(KeeenvError):
    """KeePass-related errors."""

    def __init__(self, message: str, original_exception: Optional[Exception] = None):
        """
        Initialize KeePass error.

        Args:
            message: Error message
            original_exception: Original exception that caused this error
        """
        super().__init__(message, original_exception)


class KeePassCredentialsError(KeePassError):
    """Raised when KeePass credentials are invalid."""
    pass


class KeePassEntryNotFoundError(KeePassError):
    """Raised when KeePass entry is not found."""
    pass


class KeePassAttributeNotFoundError(KeePassError):
    """Raised when KeePass attribute is not found."""
    pass


class ValidationError(KeeenvError):
    """Input validation errors."""

    def __init__(self, message: str, original_exception: Optional[Exception] = None):
        """
        Initialize validation error.

        Args:
            message: Error message
            original_exception: Original exception that caused this error
        """
        super().__init__(message, original_exception)


class PathValidationError(ValidationError):
    """Raised when path validation fails."""
    pass


class EntryTitleValidationError(ValidationError):
    """Raised when entry title validation fails."""
    pass


class AttributeValidationError(ValidationError):
    """Raised when attribute validation fails."""
    pass


class SecurityError(KeeenvError):
    """Security-related errors."""

    def __init__(self, message: str, original_exception: Optional[Exception] = None):
        """
        Initialize security error.

        Args:
            message: Error message
            original_exception: Original exception that caused this error
        """
        super().__init__(message, original_exception)


class DatabaseSecurityError(SecurityError):
    """Raised when database security validation fails."""
    pass


class KeyfileSecurityError(SecurityError):
    """Raised when keyfile security validation fails."""
    pass
