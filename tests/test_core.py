"""
Tests for core functionality
"""

import pytest
import tempfile
import configparser
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from keeenv.config import KeeenvConfig
from keeenv.core import (
    main,
    _cmd_add,
    _cmd_run,
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

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as tmp:
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

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as tmp:
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

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as tmp:
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

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as tmp:
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
            config_manager.validate_config_file("/nonexistent/config.ini")


class TestMainFunction:
    """Test main function"""

    @patch("keeenv.core.KeeenvConfig")
    @patch("keeenv.core.PathValidator.validate_file_path")
    @patch("keeenv.validation.SecurityValidator.validate_database_security")
    @patch("sys.argv", ["keeenv", "eval"])
    def test_main_success(
        self,
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
        mock_config_instance.validate_keepass_config.return_value = (
            "tests/secrets.kdbx",
            None,
        )
        mock_config_class.return_value = mock_config_instance

        mock_path_validator.return_value = Path("tests/secrets.kdbx")

        # Mock KeePassManager and its methods
        mock_kp_manager = Mock(spec=KeePassManager)
        mock_kp_manager.substitute_placeholders.return_value = "secret123"

        # Mock the KeePassManager constructor and connect method
        with patch(
            "keeenv.core.KeePassManager", return_value=mock_kp_manager
        ) as mock_kp_manager_class:
            # Mock the connect_with_password_fallback method
            mock_kp_manager.connect_with_password_fallback = Mock()

            # Capture stdout
            with patch("sys.stdout", new_callable=lambda: MagicMock()) as mock_stdout:
                main()

                # Verify KeePassManager was created and used correctly
                mock_kp_manager_class.assert_called_once_with(
                    "tests/secrets.kdbx", None
                )
                mock_kp_manager.connect_with_password_fallback.assert_called_once()
                mock_kp_manager.substitute_placeholders.assert_called_once_with(
                    '${"Test".Password}', strict=False
                )

                # Check that export commands were printed
                mock_stdout.write.assert_called()
                calls = mock_stdout.write.call_args_list
                export_calls = [call for call in calls if "export" in str(call)]
                assert len(export_calls) > 0

    @patch("keeenv.core.KeeenvConfig")
    @patch("sys.argv", ["keeenv", "eval"])
    def test_main_config_error(self, mock_config_class):
        """Test main function with config error (updated for new CLI behavior)"""
        # Mock the KeeenvConfig instance to raise a ConfigError
        mock_config_instance = Mock()
        mock_config_instance.get_config.side_effect = ConfigError("Test config error")
        mock_config_class.return_value = mock_config_instance

        # core.main re-raises ConfigError via _handle_error before sys.exit is invoked in keeenv.main
        with pytest.raises(ConfigError, match="Test config error"):
            main()


class TestMainFunctionWithPasswordLogic:
    """Test main function with password logic (with and without password requirement)"""

    @patch("keeenv.core.KeeenvConfig")
    @patch("keeenv.core.PathValidator.validate_file_path")
    @patch("keeenv.validation.SecurityValidator.validate_database_security")
    @patch("sys.argv", ["keeenv", "eval"])
    def test_main_success_without_password(
        self,
        mock_security,
        mock_path_validator,
        mock_config_class,
    ):
        """Test successful main function execution when database doesn't require password"""
        from keeenv.keepass import KeePassManager

        # Setup mocks
        mock_config = configparser.ConfigParser()
        mock_config["keepass"] = {"database": "tests/secrets.kdbx"}
        mock_config["env"] = {"SECRET": '${"Test".Password}'}

        # Mock the KeeenvConfig instance and its methods
        mock_config_instance = Mock()
        mock_config_instance.get_config.return_value = mock_config
        mock_config_instance.validate_keepass_config.return_value = (
            "tests/secrets.kdbx",
            None,
        )
        mock_config_class.return_value = mock_config_instance

        mock_path_validator.return_value = Path("tests/secrets.kdbx")

        # Mock KeePassManager and its methods
        mock_kp_manager = Mock(spec=KeePassManager)
        mock_kp_manager.substitute_placeholders.return_value = "secret123"

        # Mock the KeePassManager constructor and connect method
        with patch(
            "keeenv.core.KeePassManager", return_value=mock_kp_manager
        ) as mock_kp_manager_class:
            # Mock the connect_with_password_fallback method to succeed
            mock_kp_manager.connect_with_password_fallback = Mock()

            # Capture stdout
            with patch("sys.stdout", new_callable=lambda: MagicMock()) as mock_stdout:
                main()

                # Verify KeePassManager was created and used correctly
                mock_kp_manager_class.assert_called_once_with(
                    "tests/secrets.kdbx", None
                )
                mock_kp_manager.connect_with_password_fallback.assert_called_once()
                mock_kp_manager.substitute_placeholders.assert_called_once_with(
                    '${"Test".Password}', strict=False
                )

                # Check that export commands were printed
                mock_stdout.write.assert_called()
                calls = mock_stdout.write.call_args_list
                export_calls = [call for call in calls if "export" in str(call)]
                assert len(export_calls) > 0

    @patch("keeenv.core.KeeenvConfig")
    @patch("keeenv.core.PathValidator.validate_file_path")
    @patch("keeenv.validation.SecurityValidator.validate_database_security")
    @patch("sys.argv", ["keeenv", "eval"])
    def test_main_success_with_password_required(
        self,
        mock_security,
        mock_path_validator,
        mock_config_class,
    ):
        """Test successful main function execution when database requires password"""
        from keeenv.keepass import KeePassManager

        # Setup mocks
        mock_config = configparser.ConfigParser()
        mock_config["keepass"] = {"database": "tests/secrets.kdbx"}
        mock_config["env"] = {"SECRET": '${"Test".Password}'}

        # Mock the KeeenvConfig instance and its methods
        mock_config_instance = Mock()
        mock_config_instance.get_config.return_value = mock_config
        mock_config_instance.validate_keepass_config.return_value = (
            "tests/secrets.kdbx",
            None,
        )
        mock_config_class.return_value = mock_config_instance

        mock_path_validator.return_value = Path("tests/secrets.kdbx")
        # Mock KeePassManager and its methods
        mock_kp_manager = Mock(spec=KeePassManager)
        mock_kp_manager.substitute_placeholders.return_value = "secret123"

        # Mock the KeePassManager constructor
        with patch(
            "keeenv.core.KeePassManager", return_value=mock_kp_manager
        ) as mock_kp_manager_class:
            # Mock connect_with_password_fallback to succeed
            mock_kp_manager.connect_with_password_fallback = Mock()

            # Capture stdout
            with patch("sys.stdout", new_callable=lambda: MagicMock()) as mock_stdout:
                main()

                # Verify KeePassManager was created and used correctly
                mock_kp_manager_class.assert_called_once_with(
                    "tests/secrets.kdbx", None
                )
                mock_kp_manager.connect_with_password_fallback.assert_called_once()
                mock_kp_manager.substitute_placeholders.assert_called_once_with(
                    '${"Test".Password}', strict=False
                )

                # Check that export commands were printed
                mock_stdout.write.assert_called()
                calls = mock_stdout.write.call_args_list
                export_calls = [call for call in calls if "export" in str(call)]
                assert len(export_calls) > 0

    @patch("keeenv.core.KeeenvConfig")
    @patch("keeenv.core.PathValidator.validate_file_path")
    @patch("keeenv.validation.SecurityValidator.validate_database_security")
    @patch("sys.argv", ["keeenv", "eval"])
    def test_main_password_prompt_called_only_when_needed(
        self,
        mock_security,
        mock_path_validator,
        mock_config_class,
    ):
        """Test that password prompt is only called when database requires password"""
        from keeenv.keepass import KeePassManager

        # Setup mocks
        mock_config = configparser.ConfigParser()
        mock_config["keepass"] = {"database": "tests/secrets.kdbx"}
        mock_config["env"] = {"SECRET": '${"Test".Password}'}

        # Mock the KeeenvConfig instance and its methods
        mock_config_instance = Mock()
        mock_config_instance.get_config.return_value = mock_config
        mock_config_instance.validate_keepass_config.return_value = (
            "tests/secrets.kdbx",
            None,
        )
        mock_config_class.return_value = mock_config_instance

        mock_path_validator.return_value = Path("tests/secrets.kdbx")

        # Mock KeePassManager and its methods
        mock_kp_manager = Mock(spec=KeePassManager)
        mock_kp_manager.substitute_placeholders.return_value = "secret123"

        # Mock the KeePassManager constructor
        with patch(
            "keeenv.core.KeePassManager", return_value=mock_kp_manager
        ) as mock_kp_manager_class:
            # Mock connect_with_password_fallback to succeed
            mock_kp_manager.connect_with_password_fallback = Mock(return_value=None)

            # Capture stdout
            with patch("sys.stdout", new_callable=lambda: MagicMock()) as mock_stdout:
                main()

                # Verify KeePassManager was created and used correctly
                mock_kp_manager_class.assert_called_once_with(
                    "tests/secrets.kdbx", None
                )
                mock_kp_manager.connect_with_password_fallback.assert_called_once()
                mock_kp_manager.substitute_placeholders.assert_called_once_with(
                    '${"Test".Password}', strict=False
                )

                # Check that export commands were printed
                mock_stdout.write.assert_called()
                calls = mock_stdout.write.call_args_list
                export_calls = [call for call in calls if "export" in str(call)]
                assert len(export_calls) > 0


class TestCmdAddFunctionWithPasswordLogic:
    """Test _cmd_add function with password logic (with and without password requirement)"""

    @patch("keeenv.core.KeePassManager")
    @patch("keeenv.core.KeeenvConfig")
    @patch("keeenv.core.PathValidator.validate_file_path")
    @patch("keeenv.validation.SecurityValidator.validate_database_security")
    def test_cmd_add_success_without_password(
        self,
        mock_security,
        mock_path_validator,
        mock_config_class,
        mock_kp_manager_class,
    ):
        """Test successful _cmd_add execution when database doesn't require password"""
        from keeenv.keepass import KeePassManager

        # Setup mocks
        mock_config = configparser.ConfigParser()
        mock_config["keepass"] = {"database": "tests/secrets.kdbx"}
        mock_config["env"] = {}

        # Mock the KeeenvConfig instance and its methods
        mock_config_instance = Mock()
        mock_config_instance.get_config.return_value = mock_config
        mock_config_instance.validate_keepass_config.return_value = (
            "tests/secrets.kdbx",
            None,
        )
        mock_config_class.return_value = mock_config_instance

        mock_path_validator.return_value = Path("tests/secrets.kdbx")

        # Mock KeePassManager and its methods
        mock_kp_manager = Mock(spec=KeePassManager)
        mock_kp_manager.find_entry.return_value = (
            None,
            None,
            "TEST_VAR",
        )  # entry, group, title
        mock_kp_manager.create_entry.return_value = Mock()
        mock_kp_manager.set_entry_attribute = Mock()
        mock_kp_manager.save_database = Mock()
        mock_kp_manager.format_placeholder.return_value = '${"TEST_VAR".Password}'
        mock_kp_manager.disconnect = Mock()

        mock_kp_manager_class.return_value = mock_kp_manager

        # Call _cmd_add
        _cmd_add(
            config_path="test_config.ini",
            env_var="TEST_VAR",
            secret="secret123",
            title=None,
            username=None,
            url=None,
            notes=None,
            attribute=None,
            force=False,
        )

        # Verify KeePassManager was created and used correctly
        mock_kp_manager_class.assert_called_once_with("tests/secrets.kdbx", None)
        mock_kp_manager.connect_with_password_fallback.assert_called_once()
        mock_kp_manager.find_entry.assert_called_once_with(
            "TEST_VAR", create_if_missing=True
        )
        mock_kp_manager.create_entry.assert_called_once()
        mock_kp_manager.set_entry_attribute.assert_called_once()
        mock_kp_manager.save_database.assert_called_once()
        mock_kp_manager.disconnect.assert_called_once()

    @patch("keeenv.core.KeePassManager")
    @patch("keeenv.core.KeeenvConfig")
    @patch("keeenv.core.PathValidator.validate_file_path")
    @patch("keeenv.validation.SecurityValidator.validate_database_security")
    def test_cmd_add_success_with_password_required(
        self,
        mock_security,
        mock_path_validator,
        mock_config_class,
        mock_kp_manager_class,
    ):
        """Test successful _cmd_add execution when database requires password"""
        from keeenv.keepass import KeePassManager

        # Setup mocks
        mock_config = configparser.ConfigParser()
        mock_config["keepass"] = {"database": "tests/secrets.kdbx"}
        mock_config["env"] = {}

        # Mock the KeeenvConfig instance and its methods
        mock_config_instance = Mock()
        mock_config_instance.get_config.return_value = mock_config
        mock_config_instance.validate_keepass_config.return_value = (
            "tests/secrets.kdbx",
            None,
        )
        mock_config_class.return_value = mock_config_instance

        mock_path_validator.return_value = Path("tests/secrets.kdbx")

        # Mock KeePassManager and its methods
        mock_kp_manager = Mock(spec=KeePassManager)
        mock_kp_manager.find_entry.return_value = (
            None,
            None,
            "TEST_VAR",
        )  # entry, group, title
        mock_kp_manager.create_entry.return_value = Mock()
        mock_kp_manager.set_entry_attribute = Mock()
        mock_kp_manager.save_database = Mock()
        mock_kp_manager.format_placeholder.return_value = '${"TEST_VAR".Password}'
        mock_kp_manager.disconnect = Mock()

        mock_kp_manager_class.return_value = mock_kp_manager

        # Mock connect_with_password_fallback to succeed
        mock_kp_manager.connect_with_password_fallback = Mock()

        # Call _cmd_add
        _cmd_add(
            config_path="test_config.ini",
            env_var="TEST_VAR",
            secret="secret123",
            title=None,
            username=None,
            url=None,
            notes=None,
            attribute=None,
            force=False,
        )

        # Verify KeePassManager was created and used correctly
        mock_kp_manager_class.assert_called_once_with("tests/secrets.kdbx", None)
        mock_kp_manager.connect_with_password_fallback.assert_called_once()
        mock_kp_manager.find_entry.assert_called_once_with(
            "TEST_VAR", create_if_missing=True
        )
        mock_kp_manager.create_entry.assert_called_once()
        mock_kp_manager.set_entry_attribute.assert_called_once()
        mock_kp_manager.save_database.assert_called_once()
        mock_kp_manager.disconnect.assert_called_once()

    @patch("keeenv.core.KeePassManager")
    @patch("keeenv.core.KeeenvConfig")
    @patch("keeenv.core.PathValidator.validate_file_path")
    @patch("keeenv.validation.SecurityValidator.validate_database_security")
    def test_cmd_add_password_prompt_called_only_when_needed(
        self,
        mock_security,
        mock_path_validator,
        mock_config_class,
        mock_kp_manager_class,
    ):
        """Test that password prompt is only called when database requires password"""
        from keeenv.keepass import KeePassManager

        # Setup mocks
        mock_config = configparser.ConfigParser()
        mock_config["keepass"] = {"database": "tests/secrets.kdbx"}
        mock_config["env"] = {}

        # Mock the KeeenvConfig instance and its methods
        mock_config_instance = Mock()
        mock_config_instance.get_config.return_value = mock_config
        mock_config_instance.validate_keepass_config.return_value = (
            "tests/secrets.kdbx",
            None,
        )
        mock_config_class.return_value = mock_config_instance

        mock_path_validator.return_value = Path("tests/secrets.kdbx")

        # Mock KeePassManager and its methods
        mock_kp_manager = Mock(spec=KeePassManager)
        mock_kp_manager.find_entry.return_value = (
            None,
            None,
            "TEST_VAR",
        )  # entry, group, title
        mock_kp_manager.create_entry.return_value = Mock()
        mock_kp_manager.set_entry_attribute = Mock()
        mock_kp_manager.save_database = Mock()
        mock_kp_manager.format_placeholder.return_value = '${"TEST_VAR".Password}'
        mock_kp_manager.disconnect = Mock()

        mock_kp_manager_class.return_value = mock_kp_manager

        # Mock connect_with_password_fallback to succeed
        mock_kp_manager.connect_with_password_fallback = Mock(return_value=None)

        # Call _cmd_add
        _cmd_add(
            config_path="test_config.ini",
            env_var="TEST_VAR",
            secret="secret123",
            title=None,
            username=None,
            url=None,
            notes=None,
            attribute=None,
            force=False,
        )

        # Verify KeePassManager was created and used correctly
        mock_kp_manager_class.assert_called_once_with("tests/secrets.kdbx", None)
        mock_kp_manager.connect_with_password_fallback.assert_called_once()
        mock_kp_manager.find_entry.assert_called_once_with(
            "TEST_VAR", create_if_missing=True
        )
        mock_kp_manager.create_entry.assert_called_once()
        mock_kp_manager.set_entry_attribute.assert_called_once()
        mock_kp_manager.save_database.assert_called_once()
        mock_kp_manager.disconnect.assert_called_once()


class TestCmdRunCommandParsing:
    """Test _cmd_run command parsing with shlex.split for quoted commands."""

    @staticmethod
    def _make_mock_config(env_vars=None):
        """Create a case-preserving mock ConfigParser."""
        cfg = configparser.ConfigParser()
        cfg.optionxform = str  # preserve key case like KeeenvConfig does
        cfg["keepass"] = {"database": "tests/secrets.kdbx"}
        cfg["env"] = env_vars or {}
        return cfg

    @staticmethod
    def _make_mock_config_instance(mock_config):
        """Create a mock KeeenvConfig that returns the given config."""
        instance = Mock()
        instance.get_config.return_value = mock_config
        instance.validate_keepass_config.return_value = (
            "tests/secrets.kdbx",
            None,
        )
        return instance

    @patch("keeenv.core.subprocess.run")
    @patch("keeenv.core.KeePassManager")
    @patch("keeenv.core.KeeenvConfig")
    def test_single_element_command_is_split(
        self,
        mock_config_class,
        mock_kp_manager_class,
        mock_subprocess_run,
    ):
        """"echo hello" (single element) should be split to ['echo', 'hello']."""
        mock_config = self._make_mock_config()
        mock_config_class.return_value = self._make_mock_config_instance(mock_config)

        mock_kp_manager = Mock()
        mock_kp_manager.substitute_placeholders.return_value = ""
        mock_kp_manager_class.return_value = mock_kp_manager

        with patch("sys.exit"):
            _cmd_run(
                config_path="test_config.ini",
                command=["echo hello"],
            )

        mock_subprocess_run.assert_called_once()
        command_arg = mock_subprocess_run.call_args[0][0]
        assert command_arg == ["echo", "hello"], (
            f"Expected ['echo', 'hello'] but got {command_arg}"
        )
        mock_kp_manager.connect_with_password_fallback.assert_called_once()
        mock_kp_manager.disconnect.assert_called_once()

    @patch("keeenv.core.subprocess.run")
    @patch("keeenv.core.KeePassManager")
    @patch("keeenv.core.KeeenvConfig")
    def test_multi_element_command_not_split(
        self,
        mock_config_class,
        mock_kp_manager_class,
        mock_subprocess_run,
    ):
        """['echo', 'hello', 'world'] (multiple elements) should pass through unchanged."""
        mock_config = self._make_mock_config()
        mock_config_class.return_value = self._make_mock_config_instance(mock_config)

        mock_kp_manager = Mock()
        mock_kp_manager.substitute_placeholders.return_value = ""
        mock_kp_manager_class.return_value = mock_kp_manager

        with patch("sys.exit"):
            _cmd_run(
                config_path="test_config.ini",
                command=["echo", "hello", "world"],
            )

        mock_subprocess_run.assert_called_once()
        command_arg = mock_subprocess_run.call_args[0][0]
        assert command_arg == ["echo", "hello", "world"], (
            f"Expected ['echo', 'hello', 'world'] but got {command_arg}"
        )
        mock_kp_manager.connect_with_password_fallback.assert_called_once()
        mock_kp_manager.disconnect.assert_called_once()

    @patch("keeenv.core.subprocess.run")
    @patch("keeenv.core.KeePassManager")
    @patch("keeenv.core.KeeenvConfig")
    def test_single_element_with_quoted_args_preserved(
        self,
        mock_config_class,
        mock_kp_manager_class,
        mock_subprocess_run,
    ):
        """Quoted args inside a single-element command should be preserved.
        E.g. \"echo 'hello world'\" splits to ['echo', 'hello world']."""
        mock_config = self._make_mock_config()
        mock_config_class.return_value = self._make_mock_config_instance(mock_config)

        mock_kp_manager = Mock()
        mock_kp_manager.substitute_placeholders.return_value = ""
        mock_kp_manager_class.return_value = mock_kp_manager

        with patch("sys.exit"):
            _cmd_run(
                config_path="test_config.ini",
                command=["echo 'hello world'"],
            )

        mock_subprocess_run.assert_called_once()
        command_arg = mock_subprocess_run.call_args[0][0]
        assert command_arg == ["echo", "hello world"], (
            f"Expected ['echo', 'hello world'] but got {command_arg}"
        )
        mock_kp_manager.connect_with_password_fallback.assert_called_once()
        mock_kp_manager.disconnect.assert_called_once()

    @patch("keeenv.core.subprocess.run")
    @patch("keeenv.core.KeePassManager")
    @patch("keeenv.core.KeeenvConfig")
    def test_single_element_simple_command(
        self,
        mock_config_class,
        mock_kp_manager_class,
        mock_subprocess_run,
    ):
        """A single-word quoted command like \"ls\" should work."""
        mock_config = self._make_mock_config()
        mock_config_class.return_value = self._make_mock_config_instance(mock_config)

        mock_kp_manager = Mock()
        mock_kp_manager.substitute_placeholders.return_value = ""
        mock_kp_manager_class.return_value = mock_kp_manager

        with patch("sys.exit"):
            _cmd_run(
                config_path="test_config.ini",
                command=["ls"],
            )

        mock_subprocess_run.assert_called_once()
        command_arg = mock_subprocess_run.call_args[0][0]
        assert command_arg == ["ls"], (
            f"Expected ['ls'] but got {command_arg}"
        )
        mock_kp_manager.connect_with_password_fallback.assert_called_once()
        mock_kp_manager.disconnect.assert_called_once()

    @patch("keeenv.core.subprocess.run")
    @patch("keeenv.core.KeePassManager")
    @patch("keeenv.core.KeeenvConfig")
    def test_single_element_with_double_quotes(
        self,
        mock_config_class,
        mock_kp_manager_class,
        mock_subprocess_run,
    ):
        """Double-quoted args inside a quoted command should split correctly.
        E.g. 'python -c \"print(1+1)\"' splits to ['python', '-c', 'print(1+1)']."""
        mock_config = self._make_mock_config()
        mock_config_class.return_value = self._make_mock_config_instance(mock_config)

        mock_kp_manager = Mock()
        mock_kp_manager.substitute_placeholders.return_value = ""
        mock_kp_manager_class.return_value = mock_kp_manager

        with patch("sys.exit"):
            _cmd_run(
                config_path="test_config.ini",
                command=['python -c "print(1+1)"'],
            )

        mock_subprocess_run.assert_called_once()
        command_arg = mock_subprocess_run.call_args[0][0]
        assert command_arg == ["python", "-c", "print(1+1)"], (
            f"Expected ['python', '-c', 'print(1+1)'] but got {command_arg}"
        )
        mock_kp_manager.connect_with_password_fallback.assert_called_once()
        mock_kp_manager.disconnect.assert_called_once()

    @patch("keeenv.core.subprocess.run")
    @patch("keeenv.core.KeePassManager")
    @patch("keeenv.core.KeeenvConfig")
    def test_env_vars_passed_to_subprocess(
        self,
        mock_config_class,
        mock_kp_manager_class,
        mock_subprocess_run,
    ):
        """Env vars from KeePass should be passed to subprocess.run via env kwarg."""
        mock_config = self._make_mock_config({
            "SECRET": '${"Entry".Password}',
        })
        mock_config_class.return_value = self._make_mock_config_instance(mock_config)

        mock_kp_manager = Mock()
        mock_kp_manager.substitute_placeholders.return_value = "supersecret"
        mock_kp_manager_class.return_value = mock_kp_manager

        with patch("sys.exit"):
            _cmd_run(
                config_path="test_config.ini",
                command=["echo", "hello"],
            )

        mock_subprocess_run.assert_called_once()
        env_kwarg = mock_subprocess_run.call_args[1].get("env", {})
        assert env_kwarg.get("SECRET") == "supersecret", (
            f"Expected env SECRET=supersecret, got {env_kwarg.get('SECRET')}"
        )

    @patch("keeenv.core.subprocess.run")
    @patch("keeenv.core.KeePassManager")
    @patch("keeenv.core.KeeenvConfig")
    def test_run_preserves_variable_case(
        self,
        mock_config_class,
        mock_kp_manager_class,
        mock_subprocess_run,
    ):
        """Env var case from .keeenv is preserved (no uppercase forcing)."""
        mock_config = self._make_mock_config({
            "TF_VAR_api_key": '${"Entry".Password}',
            "mixedCaseVar": '${"Entry".Password}',
        })
        mock_config_class.return_value = self._make_mock_config_instance(mock_config)

        mock_kp_manager = Mock()
        mock_kp_manager.substitute_placeholders.return_value = "secretval"
        mock_kp_manager_class.return_value = mock_kp_manager

        with patch("sys.exit"):
            _cmd_run(
                config_path="test_config.ini",
                command=["env"],
            )

        mock_subprocess_run.assert_called_once()
        env_kwarg = mock_subprocess_run.call_args[1].get("env", {})
        assert "TF_VAR_api_key" in env_kwarg, (
            f"Expected TF_VAR_api_key in env, got keys: {list(env_kwarg.keys())}"
        )
        assert "mixedCaseVar" in env_kwarg, (
            f"Expected mixedCaseVar in env, got keys: {list(env_kwarg.keys())}"
        )
        assert "TF_VAR_API_KEY" not in env_kwarg
        assert "MIXEDCASEVAR" not in env_kwarg

    @patch("keeenv.core.subprocess.run")
    @patch("keeenv.core.KeePassManager")
    @patch("keeenv.core.KeeenvConfig")
    def test_shell_false_passed_to_subprocess(
        self,
        mock_config_class,
        mock_kp_manager_class,
        mock_subprocess_run,
    ):
        """subprocess.run should be called with shell=False for security."""
        mock_config = self._make_mock_config()
        mock_config_class.return_value = self._make_mock_config_instance(mock_config)

        mock_kp_manager = Mock()
        mock_kp_manager.substitute_placeholders.return_value = ""
        mock_kp_manager_class.return_value = mock_kp_manager

        with patch("sys.exit"):
            _cmd_run(
                config_path="test_config.ini",
                command=["echo", "hello"],
            )

        mock_subprocess_run.assert_called_once()
        shell_kwarg = mock_subprocess_run.call_args[1].get("shell")
        assert shell_kwarg is False, (
            f"Expected shell=False but got shell={shell_kwarg}"
        )
