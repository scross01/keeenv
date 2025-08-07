"""
Tests for core functionality
"""

import pytest
import tempfile
import configparser
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from keeenv.core import (
    get_keepass_secret,
    substitute_value,
    validate_config_file,
    main,
)
from keeenv.exceptions import (
    KeePassError,
    ValidationError,
    ConfigError,
)


class TestGetKeepassSecret:
    """Test get_keepass_secret function"""

    def test_get_keepass_secret_password(self):
        """Test getting password from KeePass entry"""
        mock_entry = Mock()
        mock_entry.password = "secret123"
        mock_entry.username = "user"
        mock_entry.url = "https://example.com"
        mock_entry.notes = "Test notes"
        mock_entry.custom_properties = {"API Key": "key123"}
        mock_entry.find_entries.return_value = mock_entry

        result = get_keepass_secret(mock_entry, "Test Entry", "password")
        assert result == "secret123"
        mock_entry.find_entries.assert_called_once_with(title="Test Entry", first=True)

    def test_get_keepass_secret_username(self):
        """Test getting username from KeePass entry"""
        mock_entry = Mock()
        mock_entry.password = "secret123"
        mock_entry.username = "testuser"
        mock_entry.find_entries.return_value = mock_entry

        result = get_keepass_secret(mock_entry, "Test Entry", "username")
        assert result == "testuser"

    def test_get_keepass_secret_custom_property(self):
        """Test getting custom property from KeePass entry"""
        mock_entry = Mock()
        mock_entry.custom_properties = {"API Key": "key123"}
        mock_entry.find_entries.return_value = mock_entry

        result = get_keepass_secret(mock_entry, "Test Entry", "API Key")
        assert result == "key123"

    def test_get_keepass_secret_entry_not_found(self):
        """Test handling when entry is not found"""
        mock_entry = Mock()
        mock_entry.find_entries.return_value = None

        with pytest.raises(
            KeePassError, match="Entry with title 'Test Entry' not found"
        ):
            get_keepass_secret(mock_entry, "Test Entry", "password")

    def test_get_keepass_secret_attribute_not_found(self):
        """Test handling when attribute is not found"""
        mock_entry = Mock()
        mock_entry.password = "secret123"
        del mock_entry.username  # Remove username attribute
        mock_entry.find_entries.return_value = mock_entry

        with pytest.raises(
            KeePassError, match="Failed to access entry 'Test Entry': username"
        ):
            get_keepass_secret(mock_entry, "Test Entry", "username")

    def test_get_keepass_secret_case_insensitive(self):
        """Test that attribute names are case insensitive"""
        mock_entry = Mock()
        mock_entry.password = "secret123"
        mock_entry.find_entries.return_value = mock_entry

        result = get_keepass_secret(mock_entry, "Test Entry", "PASSWORD")
        assert result == "secret123"

    def test_get_keepass_secret_validation_error(self):
        """Test validation errors are properly handled"""
        mock_entry = Mock()

        with pytest.raises(ValidationError):
            get_keepass_secret(mock_entry, "", "password")

        with pytest.raises(ValidationError):
            get_keepass_secret(mock_entry, "Test Entry", "")

        with pytest.raises(ValidationError):
            get_keepass_secret(mock_entry, "Test Entry", "123invalid")


class TestSubstituteValue:
    """Test substitute_value function"""

    def test_substitute_value_simple(self):
        """Test simple value substitution"""
        mock_entry = Mock()
        mock_entry.find_entries.return_value = Mock(password="secret123")

        template = 'My password is ${"Test Entry".Password}'
        result = substitute_value(mock_entry, template)
        assert result == "My password is secret123"

    def test_substitute_value_multiple(self):
        """Test substitution with multiple placeholders"""
        mock_entry = Mock()
        mock_entry.password = "pass123"
        mock_entry.username = "user123"
        mock_entry.find_entries.return_value = mock_entry

        template = 'User: ${"Test Entry".Username}, Pass: ${"Test Entry".Password}'
        result = substitute_value(mock_entry, template)
        assert result == "User: user123, Pass: pass123"

    def test_substitute_value_custom_property(self):
        """Test substitution with custom properties"""
        mock_entry = Mock()
        mock_entry.custom_properties = {"API Key": "key123"}
        mock_entry.find_entries.return_value = mock_entry

        template = 'API Key: ${"Test Entry"."API Key"}'
        result = substitute_value(mock_entry, template)
        assert result == "API Key: key123"

    def test_substitute_value_not_found(self):
        """Test handling when placeholder cannot be resolved"""
        mock_entry = Mock()
        mock_entry.find_entries.return_value = None

        template = 'Password: ${"Test Entry".Password}'
        # stderr output is not guaranteed; only assert on the returned value
        result = substitute_value(mock_entry, template)
        assert result == "Password: "

    def test_substitute_value_error_handling(self):
        """Test error handling during substitution"""
        mock_entry = Mock()
        mock_entry.find_entries.side_effect = Exception("Database error")

        template = 'Password: ${"Test Entry".Password}'
        # stderr output is not guaranteed; only assert on the returned value
        result = substitute_value(mock_entry, template)
        assert result == "Password: "


class TestValidateConfigFile:
    """Test validate_config_file function"""

    def test_validate_config_file_valid(self):
        """Test validation of valid config file"""
        config_content = """
[keepass]
database = tests/secrets.kdbx

[env]
SECRET_PASSWORD = ${"My Secret".Password}
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as tmp:
            tmp.write(config_content)
            tmp_path = tmp.name

        try:
            result = validate_config_file(tmp_path)
            assert isinstance(result, configparser.ConfigParser)
            assert "keepass" in result
            assert "env" in result
            assert result["keepass"]["database"] == "tests/secrets.kdbx"
        finally:
            Path(tmp_path).unlink()

    def test_validate_config_file_missing_sections(self):
        """Test validation fails for missing required sections"""
        config_content = """
[other]
value = test
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as tmp:
            tmp.write(config_content)
            tmp_path = tmp.name

        try:
            with pytest.raises(
                ConfigError, match="Missing required \\[keepass\\] section"
            ):
                validate_config_file(tmp_path)
        finally:
            Path(tmp_path).unlink()

    def test_validate_config_file_missing_database(self):
        """Test validation fails for missing database key"""
        config_content = """
[keepass]
keyfile = key.key

[env]
SECRET = value
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as tmp:
            tmp.write(config_content)
            tmp_path = tmp.name

        try:
            with pytest.raises(ConfigError, match="Missing required 'database' key"):
                validate_config_file(tmp_path)
        finally:
            Path(tmp_path).unlink()

    def test_validate_config_file_parse_error(self):
        """Test validation fails for malformed config"""
        config_content = """
[keepass
database = tests/secrets.kdbx
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as tmp:
            tmp.write(config_content)
            tmp_path = tmp.name

        try:
            with pytest.raises(ConfigError, match="Failed to parse config file"):
                validate_config_file(tmp_path)
        finally:
            Path(tmp_path).unlink()

    def test_validate_config_file_not_found(self):
        """Test validation fails for non-existent file"""
        with pytest.raises(ConfigError, match="Configuration validation failed"):
            validate_config_file("/nonexistent/config.toml")


class TestMainFunction:
    """Test main function"""

    @patch("keeenv.core.validate_config_file")
    @patch("keeenv.core.PathValidator.validate_file_path")
    @patch("keeenv.core.SecurityValidator.validate_database_security")
    @patch("keeenv.core.getpass.getpass")
    @patch("keeenv.core.PyKeePass")
    @patch("sys.argv", ["keeenv"])
    def test_main_success(
        self,
        mock_pykeepass,
        mock_getpass,
        mock_security,
        mock_path_validator,
        mock_validate_config,
    ):
        """Test successful main function execution"""
        # Setup mocks
        mock_config = configparser.ConfigParser()
        mock_config["keepass"] = {"database": "tests/secrets.kdbx"}
        mock_config["env"] = {"SECRET": '${"Test".Password}'}
        mock_validate_config.return_value = mock_config

        mock_path_validator.return_value = Path("tests/secrets.kdbx")
        mock_getpass.return_value = "password"
        mock_entry = Mock()
        mock_entry.find_entries.return_value = Mock(password="secret123")
        mock_pykeepass.return_value = mock_entry

        # Capture stdout
        with patch("sys.stdout", new_callable=lambda: MagicMock()) as mock_stdout:
            main()

            # Check that export commands were printed
            mock_stdout.write.assert_called()
            calls = mock_stdout.write.call_args_list
            export_calls = [call for call in calls if "export" in str(call)]
            assert len(export_calls) > 0

    @patch("keeenv.core.validate_config_file")
    @patch("sys.argv", ["keeenv"])
    def test_main_config_error(self, mock_validate_config):
        """Test main function with config error (updated for new CLI behavior)"""
        # Use an instance as side_effect so the code path that catches by type can run
        mock_validate_config.side_effect = ConfigError("Test config error")

        # core.main re-raises ConfigError via _handle_error before sys.exit is invoked in keeenv.main
        with pytest.raises(ConfigError, match="Test config error"):
            main()

    @patch("keeenv.core.validate_config_file")
    @patch("keeenv.core.PathValidator.validate_file_path")
    @patch("keeenv.core.SecurityValidator.validate_database_security")
    @patch("keeenv.core.getpass.getpass")
    @patch("keeenv.core.PyKeePass")
    @patch("sys.argv", ["keeenv"])
    def test_main_keepass_error(
        self,
        mock_pykeepass,
        mock_getpass,
        mock_security,
        mock_path_validator,
        mock_validate_config,
    ):
        """Test main function with KeePass error"""
        # Setup mocks
        mock_config = configparser.ConfigParser()
        mock_config["keepass"] = {"database": "tests/secrets.kdbx"}
        mock_config["env"] = {"SECRET": '${"Test".Password}'}
        mock_validate_config.return_value = mock_config

        mock_path_validator.return_value = Path("tests/secrets.kdbx")
        mock_getpass.return_value = "invalid"
        mock_pykeepass.side_effect = Exception("Failed to open KeePass database: Invalid credentials")

        # core.main re-raises the original exception via _handle_error; the wrapper keeenv.main handles exit codes.
        with pytest.raises(Exception, match="Failed to open KeePass database: Invalid credentials"):
            main()
