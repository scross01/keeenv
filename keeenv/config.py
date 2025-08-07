import configparser
import os

from keeenv.constants import (
    CONFIG_FILENAME,
    ENV_SECTION,
    ERROR_CONFIG_FILE_NOT_FOUND,
    ERROR_KEY_MISSING,
    ERROR_SECTION_MISSING,
    KEEPASS_SECTION,
)
from keeenv.exceptions import (
    ConfigError,
    ConfigFileNotFoundError,
    ConfigKeyMissingError,
    ConfigSectionMissingError,
    ValidationError,
)
from keeenv.validation import PathValidator, SecurityValidator
from typing import Optional


class KeeenvConfig:
    """Class to manage .keeenv configuration file operations."""

    def __init__(self, config_path: str = CONFIG_FILENAME):
        """Initialize with configuration file path."""
        self.config_path = config_path
        self._config: Optional[configparser.ConfigParser] = None

    def _make_case_preserving_config(self) -> configparser.ConfigParser:
        """
        Create a ConfigParser that preserves case for options and section names.

        - optionxform is disabled so option/ENV var case is preserved on read/write
        - _dict is set to builtin dict so section case is preserved on write
        """

        class _CasePreservingConfig(configparser.ConfigParser):
            def optionxform(self, optionstr: str) -> str:  # type: ignore[override]
                return optionstr

        cfg = _CasePreservingConfig()
        # Preserve section case on write (ConfigParser may lowercase without this)
        cfg._dict = dict  # type: ignore[attr-defined]
        return cfg

    def validate_config_file(self, config_path: str) -> configparser.ConfigParser:
        """
        Validate and parse configuration file.

        Args:
            config_path: Path to configuration file

        Returns:
            Validated ConfigParser object

        Raises:
            ConfigError: If configuration file is invalid
        """
        try:
            # Validate config file path
            validated_path = PathValidator.validate_file_path(
                config_path, must_exist=True
            )

            # Use a case-preserving ConfigParser
            config = self._make_case_preserving_config()

            try:
                config.read(validated_path)
            except Exception as e:
                raise ConfigError(f"Failed to parse config file: {str(e)}")

            # Validate required sections
            if "keepass" not in config:
                raise ConfigError("Missing required [keepass] section")

            if "database" not in config["keepass"]:
                raise ConfigError(
                    "Missing required 'database' key in [keepass] section"
                )

            return config

        except ValidationError as e:
            raise ConfigError(f"Configuration validation failed: {str(e)}")

    def load_and_validate_config(self, config_path: str) -> configparser.ConfigParser:
        """Load and validate the configuration file."""
        if not os.path.exists(config_path):
            raise ConfigFileNotFoundError(
                ERROR_CONFIG_FILE_NOT_FOUND.format(config_path=config_path)
            )
        return self.validate_config_file(config_path)

    def validate_keepass_config(
        self,
        config: configparser.ConfigParser,
    ) -> tuple[str, Optional[str]]:
        """Validate Keepass configuration and return validated paths."""
        if KEEPASS_SECTION not in config:
            raise ConfigSectionMissingError(
                ERROR_SECTION_MISSING.format(
                    section=KEEPASS_SECTION, config_file=CONFIG_FILENAME
                )
            )

        keepass_config = config[KEEPASS_SECTION]
        db_path: Optional[str] = keepass_config.get("database")
        keyfile_path: Optional[str] = keepass_config.get("keyfile")

        if not db_path:
            raise ConfigKeyMissingError(
                ERROR_KEY_MISSING.format(key="database", section=KEEPASS_SECTION)
            )

        # Validate database path
        validated_db_path = str(
            PathValidator.validate_file_path(os.path.expanduser(db_path))
        )

        # Validate keyfile path if present
        validated_keyfile_path = None
        if keyfile_path:
            validated_keyfile_path = str(
                PathValidator.validate_file_path(os.path.expanduser(keyfile_path))
            )

        # Validate file security
        SecurityValidator.validate_database_security(
            validated_db_path, validated_keyfile_path
        )

        return validated_db_path, validated_keyfile_path

    def get_config(self) -> configparser.ConfigParser:
        """Get the loaded configuration, loading it if necessary."""
        if self._config is None:
            self._config = self.load_and_validate_config(self.config_path)
        return self._config

    def save_config(self, config: Optional[configparser.ConfigParser] = None) -> None:
        """Save configuration to file."""
        config_to_save = config or self._config
        if config_to_save is None:
            raise ConfigError("No configuration to save")

        try:
            with open(os.path.expanduser(self.config_path), "w", encoding="utf-8") as f:
                config_to_save.write(f)
        except Exception as e:
            raise ConfigError(
                f"Failed to write configuration file '{self.config_path}'", e
            )

    def get_env_section(self) -> configparser.SectionProxy:
        """Get the [env] section from configuration."""
        config = self.get_config()
        if ENV_SECTION not in config:
            config[ENV_SECTION] = {}
            self._config = config  # Update cached config
        return config[ENV_SECTION]

    def set_env_var(self, var_name: str, value: str) -> None:
        """Set an environment variable in the [env] section."""
        env_section = self.get_env_section()
        env_section[var_name] = value
        self._config = self.get_config()  # Update cached config

    def get_env_vars(self) -> dict[str, str]:
        """Get all environment variables from the [env] section."""
        env_section = self.get_env_section()
        return dict(env_section)
