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
