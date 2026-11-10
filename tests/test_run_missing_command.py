"""`keeenv run` with a nonexistent executable must fail with a clean error."""

import configparser
from unittest.mock import Mock, patch

import pytest

from keeenv.core import _cmd_run
from keeenv.exceptions import ValidationError


def _make_config():
    cfg = configparser.ConfigParser()
    cfg.optionxform = str  # preserve key case like KeeenvConfig does
    cfg["keepass"] = {"database": "tests/secrets.kdbx"}
    cfg["env"] = {}
    return cfg


@patch("keeenv.core.subprocess.run")
@patch("keeenv.core.KeePassManager")
@patch("keeenv.core.KeeenvConfig")
def test_run_missing_command_raises_clean_error(
    mock_config_class, mock_kp_manager_class, mock_subprocess_run
):
    """A command that does not exist must raise ValidationError, not traceback."""
    instance = Mock()
    instance.get_config.return_value = _make_config()
    instance.validate_keepass_config.return_value = ("tests/secrets.kdbx", None)
    mock_config_class.return_value = instance
    mock_kp_manager_class.return_value = Mock()
    mock_subprocess_run.side_effect = FileNotFoundError(2, "No such file or directory")

    with pytest.raises(ValidationError, match="Command not found"):
        _cmd_run(
            config_path="test_config.ini",
            command=["definitely-not-a-real-cmd-xyz"],
        )
