"""
Unit tests for KeePassManager class (pytest style).
"""

from unittest.mock import Mock, patch

import pytest
from pykeepass.exceptions import CredentialsError as PyKPCredentialsError

from keeenv.keepass import KeePassManager
from keeenv.exceptions import KeePassError


@pytest.fixture
def manager():
    """Create a KeePassManager instance for testing."""
    return KeePassManager("/tmp/test.kdbx", "/tmp/test.key")


@pytest.fixture
def mock_pykeepass_class():
    """Create a mock PyKeePass class."""
    return Mock()


@pytest.fixture
def connected_manager(mock_pykeepass_class):
    """Create a connected KeePassManager instance."""
    mock_kp = Mock()
    mock_kp.root_group = Mock()
    mock_pykeepass_class.return_value = mock_kp
    mgr = KeePassManager(
        "/tmp/test.kdbx",
        "/tmp/test.key",
        pykeepass_class=mock_pykeepass_class,
    )
    mgr.connect("test_password")
    return mgr


class TestInit:
    """Tests for KeePassManager initialization."""

    def test_init(self, manager):
        """Test KeePassManager initialization."""
        assert manager.db_path == "/tmp/test.kdbx"
        assert manager.keyfile_path == "/tmp/test.key"
        assert manager.password == ""
        assert manager.kp is None
        assert manager._is_connected is False


class TestConnect:
    """Tests for connect method."""

    def test_connect_success(self, mock_pykeepass_class):
        """Test successful database connection."""
        mock_kp = Mock()
        mock_pykeepass_class.return_value = mock_kp

        mgr = KeePassManager(
            "/tmp/test.kdbx",
            "/tmp/test.key",
            pykeepass_class=mock_pykeepass_class,
        )
        mgr.connect("test_password")
        assert mgr._is_connected is True
        assert mgr.password == "test_password"
        mock_pykeepass_class.assert_called_once_with(
            "/tmp/test.kdbx",
            password="test_password",
            keyfile="/tmp/test.key",
        )

    def test_connect_failure(self, mock_pykeepass_class):
        """Test database connection failure."""
        mock_pykeepass_class.side_effect = Exception("Connection failed")

        mgr = KeePassManager(
            "/tmp/test.kdbx",
            "/tmp/test.key",
            pykeepass_class=mock_pykeepass_class,
        )
        with pytest.raises(KeePassError):
            mgr.connect("wrong_password")

    def test_connect_with_password_fallback_no_password_needed(
        self, mock_pykeepass_class
    ):
        """Test connect_with_password_fallback when no password is needed."""
        mock_kp = Mock()
        mock_pykeepass_class.return_value = mock_kp

        mgr = KeePassManager(
            "/tmp/test.kdbx",
            "/tmp/test.key",
            pykeepass_class=mock_pykeepass_class,
        )
        mgr.connect_with_password_fallback()
        assert mgr._is_connected is True
        mock_pykeepass_class.assert_called_once_with(
            "/tmp/test.kdbx",
            password=None,
            keyfile="/tmp/test.key",
        )

    @patch("getpass.getpass")
    def test_connect_with_password_fallback_prompts_on_credentials_error(
        self, mock_getpass, mock_pykeepass_class
    ):
        """Test connect_with_password_fallback prompts for password on failure."""
        mock_getpass.return_value = "prompted_password"
        mock_kp = Mock()
        # First call raises pykeepass CredentialsError, second call succeeds
        mock_pykeepass_class.side_effect = [
            PyKPCredentialsError("Invalid password"),
            mock_kp,
        ]

        mgr = KeePassManager(
            "/tmp/test.kdbx",
            "/tmp/test.key",
            pykeepass_class=mock_pykeepass_class,
        )
        mgr.connect_with_password_fallback()
        assert mgr._is_connected is True
        assert mock_pykeepass_class.call_count == 2
        # Verify first call was without password
        mock_pykeepass_class.assert_any_call(
            "/tmp/test.kdbx",
            password=None,
            keyfile="/tmp/test.key",
        )
        # Verify second call was with prompted password
        mock_pykeepass_class.assert_any_call(
            "/tmp/test.kdbx",
            password="prompted_password",
            keyfile="/tmp/test.key",
        )
        mock_getpass.assert_called_once()


class TestDisconnect:
    """Tests for disconnect method."""

    def test_disconnect(self, manager):
        """Test database disconnection."""
        manager.kp = Mock()
        manager._is_connected = True
        manager.disconnect()
        assert manager._is_connected is False
        assert manager.password == ""
        assert manager.kp is None


class TestIsConnected:
    """Tests for is_connected."""

    def test_is_connected_false_by_default(self, manager):
        """Test is_connected returns False by default."""
        assert manager.is_connected() is False

    def test_is_connected_true_when_set(self, manager):
        """Test is_connected returns True when connected."""
        manager._is_connected = True
        assert manager.is_connected() is True


class TestFindEntry:
    """Tests for find_entry method."""

    def test_find_entry_not_connected(self, manager):
        """Test finding entry when not connected."""
        with pytest.raises(KeePassError):
            manager.find_entry("test_entry")

    def test_find_entry_success(self, connected_manager):
        """Test successful entry finding."""
        mock_entry = Mock()
        connected_manager.kp.find_entries.return_value = mock_entry

        entry, group, title = connected_manager.find_entry("test_entry")

        assert entry == mock_entry
        assert group == connected_manager.kp.root_group
        assert title == "test_entry"
        connected_manager.kp.find_entries.assert_called_once_with(
            title="test_entry", first=True
        )


class TestGetSecret:
    """Tests for get_secret method."""

    def test_get_secret_not_connected(self, manager):
        """Test getting secret when not connected."""
        with pytest.raises(KeePassError):
            manager.get_secret("test_entry", "password")

    def test_get_secret_success(self, connected_manager):
        """Test successful secret retrieval."""
        mock_entry = Mock()
        mock_entry.password = "secret123"
        connected_manager.kp.find_entries.return_value = mock_entry

        secret = connected_manager.get_secret("test_entry", "password")

        assert secret == "secret123"


class TestSubstitutePlaceholders:
    """Tests for substitute_placeholders method."""

    def test_substitute_placeholders_not_connected(self, manager):
        """Test substituting placeholders when not connected."""
        manager.disconnect()
        with pytest.raises(KeePassError):
            manager.substitute_placeholders('${"test"."password"}')

    def test_substitute_placeholders_success(self, connected_manager):
        """Test successful placeholder substitution."""
        connected_manager.get_secret = Mock(return_value="secret123")

        result = connected_manager.substitute_placeholders('${"test"."password"}')

        assert result == "secret123"
        connected_manager.get_secret.assert_called_once_with("test", "password")


class TestFormatPlaceholder:
    """Tests for format_placeholder method."""

    def test_format_placeholder_standard_attr(self, manager):
        """Test placeholder formatting with standard attribute."""
        result = manager.format_placeholder("test_entry", "password")
        assert result == '${"test_entry".password}'

    def test_format_placeholder_custom_attr(self, manager):
        """Test placeholder formatting with custom attribute."""
        result = manager.format_placeholder("test_entry", "API Key")
        assert result == '${"test_entry"."API Key"}'


class TestSaveDatabase:
    """Tests for save_database method."""

    def test_save_database_not_connected(self, manager):
        """Test saving database when not connected."""
        with pytest.raises(KeePassError):
            manager.save_database()

    def test_save_database_success(self, manager):
        """Test successful database save."""
        mock_kp = Mock()
        manager.kp = mock_kp
        manager._is_connected = True
        manager.save_database()
        mock_kp.save.assert_called_once()


class TestCreateEntry:
    """Tests for create_entry method."""

    def test_create_entry_not_connected(self, manager):
        """Test creating entry when not connected."""
        with pytest.raises(KeePassError):
            manager.create_entry("test_entry")

    def test_create_entry_success(self, connected_manager):
        """Test successful entry creation."""
        mock_entry = Mock()
        connected_manager.kp.add_entry.return_value = mock_entry

        entry = connected_manager.create_entry("test_entry", username="testuser")

        assert entry == mock_entry
        connected_manager.kp.add_entry.assert_called_once_with(
            connected_manager.kp.root_group,
            title="test_entry",
            username="testuser",
            password="",
        )

    def test_create_entry_with_specific_group(self, connected_manager):
        """Test entry creation in a specific group (not root)."""
        mock_group = Mock()
        mock_entry = Mock()
        connected_manager.kp.add_entry.return_value = mock_entry

        entry = connected_manager.create_entry(
            "test_entry", username="testuser", group=mock_group
        )

        assert entry == mock_entry
        connected_manager.kp.add_entry.assert_called_once_with(
            mock_group,
            title="test_entry",
            username="testuser",
            password="",
        )


class TestUpdateEntry:
    """Tests for update_entry method."""

    def test_update_entry_not_connected(self, manager):
        """Test updating entry when not connected."""
        mock_entry = Mock()
        with pytest.raises(KeePassError):
            manager.update_entry(mock_entry, username="newuser")

    def test_update_entry_success(self, connected_manager):
        """Test successful entry update."""
        mock_entry = Mock()
        mock_entry.username = "olduser"
        mock_entry.url = "http://old.com"
        mock_entry.notes = "old notes"

        connected_manager.update_entry(
            mock_entry, username="newuser", url="https://example.com"
        )

        assert mock_entry.username == "newuser"
        assert mock_entry.url == "https://example.com"
        assert mock_entry.notes == "old notes"  # Should remain unchanged
