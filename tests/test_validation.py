"""
Tests for validation module
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from keeenv.exceptions import DatabaseSecurityError, ValidationError
from keeenv.validation import (
    AttributeValidator,
    EntryValidator,
    EnvVarValidator,
    PathValidator,
    SecurityValidator,
)


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

    def test_validate_file_path_allows_parent_relative(self):
        """A legitimate `..` path resolves instead of being rejected."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            sub = Path(tmp_dir) / "sub"
            sub.mkdir()
            target = sub / "file.txt"
            target.write_text("x")
            result = PathValidator.validate_file_path(
                str(sub / ".." / "sub" / "file.txt")
            )
            assert result == target.resolve()

    def test_validate_file_path_parent_relative_missing(self):
        """A missing `..` path reports File not found, not a format error."""
        with pytest.raises(ValidationError, match=r"File not found:"):
            PathValidator.validate_file_path("/nonexistent/../nope/file.txt")

    def test_validate_file_path_tilde_expands_and_must_exist(self):
        """Tilde expands to home; a missing target reports File not found."""
        with pytest.raises(ValidationError, match=r"File not found:"):
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

    def test_validate_entry_title_rejects_double_quote(self):
        """A double quote cannot be represented in placeholder syntax."""
        with pytest.raises(ValidationError, match="double quotes"):
            EntryValidator.validate_entry_title('He said "hi"')

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


class TestEnvVarValidator:
    """Test EnvVarValidator class"""

    @pytest.mark.parametrize(
        "name", ["FOO", "TF_VAR_api_key", "_private", "a1", "A_B_C"]
    )
    def test_validate_env_var_name_valid(self, name):
        """Test valid environment variable names are accepted unchanged"""
        assert EnvVarValidator.validate_env_var_name(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "",
            None,
            "1BAD",
            "has space",
            "X; rm -rf /",
            "$(id)",
            "with-dash",
            " leading",
            "trailing ",
            "A=B",
        ],
    )
    def test_validate_env_var_name_invalid(self, name):
        """Test invalid environment variable names are rejected"""
        with pytest.raises(ValidationError):
            EnvVarValidator.validate_env_var_name(name)

    def test_validate_env_var_name_rejects_shell_metacharacters(self):
        """Names are rendered into `export` lines, so metacharacters must fail"""
        for name in ["X; touch /tmp/pwned", "A`id`", "B&&id", "C|id"]:
            with pytest.raises(ValidationError, match="Invalid environment variable"):
                EnvVarValidator.validate_env_var_name(name)


class TestSecurityValidator:
    """Test SecurityValidator class"""

    def test_validate_database_security_valid(self):
        """Test security validation with valid permissions"""
        with tempfile.NamedTemporaryFile(mode="w") as tmp:
            # Set secure permissions (owner read/write only)
            os.chmod(tmp.name, 0o600)
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

    def test_validate_database_security_keyfile_world_readable(self, caplog):
        """Test security validation with world-readable keyfile - logs a warning, no exception"""
        with tempfile.NamedTemporaryFile(mode="w") as db_file:
            with tempfile.NamedTemporaryFile(mode="w") as key_file:
                # Set secure database but world-readable keyfile
                os.chmod(db_file.name, 0o600)
                os.chmod(key_file.name, 0o644)

                # Run and validate that a warning about world-readable keyfile is logged
                with caplog.at_level("WARNING"):
                    SecurityValidator.validate_database_security(
                        db_file.name, key_file.name
                    )
                    assert any(
                        "Keyfile is world-readable" in rec.message
                        for rec in caplog.records
                    )

    @patch("os.stat")
    def test_validate_database_security_access_error(self, mock_stat, caplog):
        """Test security validation with file access error and validate logger output"""
        mock_stat.side_effect = OSError("Permission denied")

        # Capture logs specifically from keeenv.validation logger at ERROR level
        with caplog.at_level("ERROR", logger="keeenv.validation"):
            with pytest.raises(
                DatabaseSecurityError, match="Cannot access database file"
            ):
                SecurityValidator.validate_database_security("/nonexistent/path")

        # Validate that an error-level log was produced for access failure
        assert any(
            "Cannot access database file" in rec.message and rec.levelname == "ERROR"
            for rec in caplog.records
        )

    def test_validate_database_security_keyfile_none(self):
        """Test security validation with None keyfile"""
        with tempfile.NamedTemporaryFile(mode="w") as db_file:
            os.chmod(db_file.name, 0o600)
            SecurityValidator.validate_database_security(db_file.name, None)
