"""
Tests for validation module
"""

import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch

from keeenv.validation import (
    PathValidator,
    EntryValidator,
    AttributeValidator,
    SecurityValidator,
)
from keeenv.exceptions import ValidationError


class TestPathValidator:
    """Test PathValidator class"""

    def test_validate_file_path_valid(self):
        """Test valid file path validation"""
        with tempfile.NamedTemporaryFile() as tmp:
            result = PathValidator.validate_file_path(tmp.name)
            assert isinstance(result, Path)
            assert str(result) == Path(tmp.name).resolve().as_posix()

    def test_validate_file_path_not_exists(self):
        """Test validation when file doesn't exist"""
        with pytest.raises(ValidationError, match="File not found"):
            PathValidator.validate_file_path("/nonexistent/path")

    def test_validate_file_path_empty(self):
        """Test validation with empty path"""
        with pytest.raises(ValidationError, match="Path must be a non-empty string"):
            PathValidator.validate_file_path("")

    def test_validate_file_path_none(self):
        """Test validation with None path"""
        with pytest.raises(ValidationError, match="Path must be a non-empty string"):
            PathValidator.validate_file_path(None)

    def test_validate_file_path_directory_traversal(self):
        """Test validation prevents directory traversal"""
        with pytest.raises(ValidationError, match="Invalid path format"):
            PathValidator.validate_file_path("../../etc/passwd")

        with pytest.raises(ValidationError, match="Invalid path format"):
            PathValidator.validate_file_path("~/malicious")

    def test_validate_file_path_not_file(self):
        """Test validation when path is not a file"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            with pytest.raises(ValidationError, match="Path is not a file"):
                PathValidator.validate_file_path(tmp_dir)

    def test_validate_file_path_not_required(self):
        """Test validation when file doesn't need to exist"""
        result = PathValidator.validate_file_path("/nonexistent/path", must_exist=False)
        assert isinstance(result, Path)
        assert str(result) == "/nonexistent/path"


class TestEntryValidator:
    """Test EntryValidator class"""

    def test_validate_entry_title_valid(self):
        """Test valid entry title validation"""
        result = EntryValidator.validate_entry_title("My Entry")
        assert result == "My Entry"

    def test_validate_entry_title_whitespace(self):
        """Test entry title with whitespace"""
        result = EntryValidator.validate_entry_title("  My Entry  ")
        assert result == "My Entry"

    def test_validate_entry_title_empty(self):
        """Test validation with empty title"""
        with pytest.raises(
            ValidationError, match="Entry title must be a non-empty string"
        ):
            EntryValidator.validate_entry_title("")

    def test_validate_entry_title_none(self):
        """Test validation with None title"""
        with pytest.raises(
            ValidationError, match="Entry title must be a non-empty string"
        ):
            EntryValidator.validate_entry_title(None)

    def test_validate_entry_title_too_long(self):
        """Test validation with title too long"""
        long_title = "a" * 256
        with pytest.raises(ValidationError, match="Entry title too long"):
            EntryValidator.validate_entry_title(long_title)

    def test_validate_entry_title_invalid_chars(self):
        """Test validation with invalid characters"""
        with pytest.raises(
            ValidationError, match="Entry title contains invalid characters"
        ):
            EntryValidator.validate_entry_title("Invalid\x00Title")

    def test_validate_entry_title_printable_chars(self):
        """Test validation with printable characters"""
        result = EntryValidator.validate_entry_title("Entry with spaces!@#$%^&*()")
        assert result == "Entry with spaces!@#$%^&*()"


class TestAttributeValidator:
    """Test AttributeValidator class"""

    def test_validate_attribute_standard(self):
        """Test validation of standard attributes"""
        assert AttributeValidator.validate_attribute("password") == "password"
        assert AttributeValidator.validate_attribute("PASSWORD") == "password"
        assert AttributeValidator.validate_attribute("username") == "username"
        assert AttributeValidator.validate_attribute("URL") == "url"
        assert AttributeValidator.validate_attribute("notes") == "notes"

    def test_validate_attribute_custom_quoted(self):
        """Test validation of custom quoted attributes"""
        result = AttributeValidator.validate_attribute('"API Key"')
        assert result == "API Key"

    def test_validate_attribute_custom_unquoted(self):
        """Test validation of custom unquoted attributes"""
        result = AttributeValidator.validate_attribute("Custom Field")
        assert result == "Custom Field"

    def test_validate_attribute_empty(self):
        """Test validation with empty attribute"""
        with pytest.raises(
            ValidationError, match="Attribute must be a non-empty string"
        ):
            AttributeValidator.validate_attribute("")

    def test_validate_attribute_none(self):
        """Test validation with None attribute"""
        with pytest.raises(
            ValidationError, match="Attribute must be a non-empty string"
        ):
            AttributeValidator.validate_attribute(None)

    def test_validate_attribute_invalid_name(self):
        """Test validation with invalid attribute name"""
        with pytest.raises(ValidationError, match="Invalid attribute name"):
            AttributeValidator.validate_attribute("123Invalid")

        with pytest.raises(ValidationError, match="Invalid attribute name"):
            AttributeValidator.validate_attribute("Invalid@Name")

    def test_validate_attribute_valid_custom(self):
        """Test validation of valid custom attribute names"""
        valid_names = [
            "CustomField",
            "Custom Field",
            "field_with_underscores",
            "Field123",
            "API Key",
        ]
        for name in valid_names:
            result = AttributeValidator.validate_attribute(name)
            assert result == name


class TestSecurityValidator:
    """Test SecurityValidator class"""

    def test_validate_database_security_valid(self):
        """Test security validation with valid permissions"""
        with tempfile.NamedTemporaryFile(mode="w") as tmp:
            # Set secure permissions (owner read/write only)
            os.chmod(tmp.name, 0o600)
            SecurityValidator.validate_database_security(tmp.name)

    def test_validate_database_security_world_readable(self):
        """Test security validation with world-readable file"""
        with tempfile.NamedTemporaryFile(mode="w") as tmp:
            # Set world-readable permissions
            os.chmod(tmp.name, 0o644)
            with pytest.raises(ValidationError, match="world-readable"):
                SecurityValidator.validate_database_security(tmp.name)

    def test_validate_database_security_with_keyfile(self):
        """Test security validation with keyfile"""
        with tempfile.NamedTemporaryFile(mode="w") as db_file:
            with tempfile.NamedTemporaryFile(mode="w") as key_file:
                # Set secure permissions
                os.chmod(db_file.name, 0o600)
                os.chmod(key_file.name, 0o600)

                SecurityValidator.validate_database_security(
                    db_file.name, key_file.name
                )

    def test_validate_database_security_keyfile_world_readable(self):
        """Test security validation with world-readable keyfile"""
        with tempfile.NamedTemporaryFile(mode="w") as db_file:
            with tempfile.NamedTemporaryFile(mode="w") as key_file:
                # Set secure database but world-readable keyfile
                os.chmod(db_file.name, 0o600)
                os.chmod(key_file.name, 0o644)

                with pytest.raises(ValidationError, match="world-readable"):
                    SecurityValidator.validate_database_security(
                        db_file.name, key_file.name
                    )

    @patch("os.stat")
    def test_validate_database_security_access_error(self, mock_stat):
        """Test security validation with file access error"""
        mock_stat.side_effect = OSError("Permission denied")

        with pytest.raises(ValidationError, match="Cannot access database file"):
            SecurityValidator.validate_database_security("/nonexistent/path")

    def test_validate_database_security_keyfile_none(self):
        """Test security validation with None keyfile"""
        with tempfile.NamedTemporaryFile(mode="w") as db_file:
            os.chmod(db_file.name, 0o600)
            SecurityValidator.validate_database_security(db_file.name, None)
