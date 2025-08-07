"""
Tests for core functionality
"""

import pytest
import tempfile
import configparser
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from keeenv.core import (
    main,
    KeeenvConfig,
)
from keeenv.exceptions import (
    ConfigError,
)


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
            config_manager = KeeenvConfig()
            result = config_manager.validate_config_file(tmp_path)
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
                config_manager = KeeenvConfig()
                config_manager.validate_config_file(tmp_path)
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
                config_manager = KeeenvConfig()
                config_manager.validate_config_file(tmp_path)
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
                config_manager = KeeenvConfig()
                config_manager.validate_config_file(tmp_path)
        finally:
            Path(tmp_path).unlink()

    def test_validate_config_file_not_found(self):
        """Test validation fails for non-existent file"""
        with pytest.raises(ConfigError, match="Configuration validation failed"):
            config_manager = KeeenvConfig()
            config_manager.validate_config_file("/nonexistent/config.toml")


class TestMainFunction:
    """Test main function"""

    @patch("keeenv.core.KeeenvConfig")
    @patch("keeenv.core.PathValidator.validate_file_path")
    @patch("keeenv.core.SecurityValidator.validate_database_security")
    @patch("keeenv.core.getpass.getpass")
    @patch("sys.argv", ["keeenv"])
    def test_main_success(
        self,
        mock_getpass,
        mock_security,
        mock_path_validator,
        mock_config_class,
    ):
        """Test successful main function execution using KeePassManager"""
        from keeenv.keepass import KeePassManager

        # Setup mocks
        mock_config = configparser.ConfigParser()
        mock_config["keepass"] = {"database": "tests/secrets.kdbx"}
        mock_config["env"] = {"SECRET": '${"Test".Password}'}
        
        # Mock the KeeenvConfig instance and its methods
        mock_config_instance = Mock()
        mock_config_instance.get_config.return_value = mock_config
        mock_config_instance.validate_keepass_config.return_value = ("tests/secrets.kdbx", None)
        mock_config_class.return_value = mock_config_instance

        mock_path_validator.return_value = Path("tests/secrets.kdbx")
        mock_getpass.return_value = "password"

        # Mock KeePassManager and its methods
        mock_kp_manager = Mock(spec=KeePassManager)
        mock_kp_manager.substitute_placeholders.return_value = "secret123"

        # Mock the KeePassManager constructor and connect method
        with patch(
            "keeenv.core.KeePassManager", return_value=mock_kp_manager
        ) as mock_kp_manager_class:
            # Mock the connect method
            mock_kp_manager.connect = Mock()

            # Capture stdout
            with patch("sys.stdout", new_callable=lambda: MagicMock()) as mock_stdout:
                main()

                # Verify KeePassManager was created and used correctly
                mock_kp_manager_class.assert_called_once_with(
                    "tests/secrets.kdbx", None
                )
                mock_kp_manager.connect.assert_called_once_with("password")
                mock_kp_manager.substitute_placeholders.assert_called_once_with(
                    '${"Test".Password}', strict=False
                )

                # Check that export commands were printed
                mock_stdout.write.assert_called()
                calls = mock_stdout.write.call_args_list
                export_calls = [call for call in calls if "export" in str(call)]
                assert len(export_calls) > 0

    @patch("keeenv.core.KeeenvConfig")
    @patch("sys.argv", ["keeenv"])
    def test_main_config_error(self, mock_config_class):
        """Test main function with config error (updated for new CLI behavior)"""
        # Mock the KeeenvConfig instance to raise a ConfigError
        mock_config_instance = Mock()
        mock_config_instance.get_config.side_effect = ConfigError("Test config error")
        mock_config_class.return_value = mock_config_instance

        # core.main re-raises ConfigError via _handle_error before sys.exit is invoked in keeenv.main
        with pytest.raises(ConfigError, match="Test config error"):
            main()
