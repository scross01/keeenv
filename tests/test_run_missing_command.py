"""Tests for clean error handling when running a missing command."""

import configparser
from unittest.mock import Mock, patch

import pytest

from keeenv.core import _cmd_run
from keeenv.exceptions import ValidationError


class TestRunMissingCommand:
    """Test that `keeenv run` fails cleanly when the command is missing."""

    @staticmethod
    def _make_mock_config(env_vars=None):
        cfg = configparser.ConfigParser()
        cfg.optionxform = str
        cfg["keepass"] = {"database": "tests/secrets.kdbx"}
        cfg["env"] = env_vars or {}
        return cfg

    @staticmethod
    def _make_mock_config_instance(mock_config):
        instance = Mock()
        instance.get_config.return_value = mock_config
        instance.validate_keepass_config.return_value = (
            "tests/secrets.kdbx",
            None,
        )
        return instance

    @patch("keeenv.core.subprocess.run", side_effect=FileNotFoundError())
    @patch("keeenv.core.KeePassManager")
    @patch("keeenv.core.KeeenvConfig")
    def test_missing_command_raises_validation_error(
        self,
        mock_config_class,
        mock_kp_manager_class,
        mock_subprocess_run,
    ):
        mock_config = self._make_mock_config()
        mock_config_class.return_value = self._make_mock_config_instance(mock_config)

        mock_kp_manager = Mock()
        mock_kp_manager_class.return_value = mock_kp_manager

        with pytest.raises(ValidationError, match=r"Command not found: nosuchcmd"):
            _cmd_run(
                config_path="test_config.ini",
                command=["nosuchcmd", "--flag"],
            )

        mock_kp_manager.connect_with_password_fallback.assert_called_once()
        mock_kp_manager.disconnect.assert_called_once()

    @patch("keeenv.core.subprocess.run", side_effect=FileNotFoundError())
    @patch("keeenv.core.KeePassManager")
    @patch("keeenv.core.KeeenvConfig")
    def test_missing_command_from_quoted_string_raises_validation_error(
        self,
        mock_config_class,
        mock_kp_manager_class,
        mock_subprocess_run,
    ):
        mock_config = self._make_mock_config()
        mock_config_class.return_value = self._make_mock_config_instance(mock_config)

        mock_kp_manager = Mock()
        mock_kp_manager_class.return_value = mock_kp_manager

        with pytest.raises(ValidationError, match=r"Command not found: nosuchcmd"):
            _cmd_run(
                config_path="test_config.ini",
                command=["nosuchcmd --flag"],
            )

        mock_kp_manager.disconnect.assert_called_once()
