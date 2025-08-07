"""
Unit tests for KeePassManager class.
"""

import unittest
from unittest.mock import Mock


from keeenv.core import KeePassManager
from keeenv.exceptions import KeePassError


class TestKeePassManager(unittest.TestCase):
    """Test cases for KeePassManager class."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_db_path = "/tmp/test.kdbx"
        self.test_keyfile_path = "/tmp/test.key"
        self.manager = KeePassManager(self.test_db_path, self.test_keyfile_path)

    def test_init(self):
        """Test KeePassManager initialization."""
        self.assertEqual(self.manager.db_path, self.test_db_path)
        self.assertEqual(self.manager.keyfile_path, self.test_keyfile_path)
        self.assertEqual(self.manager.password, "")
        self.assertIsNone(self.manager.kp)
        self.assertFalse(self.manager._is_connected)

    def test_connect_success(self):
        """Test successful database connection."""
        # Create a mock that will be used as the PyKeePass class
        mock_pykeepass_class = Mock()
        mock_kp = Mock()
        mock_pykeepass_class.return_value = mock_kp
        
        # Use dependency injection
        manager = KeePassManager(
            self.test_db_path,
            self.test_keyfile_path,
            pykeepass_class=mock_pykeepass_class
        )
        manager.connect("test_password")
        self.assertTrue(manager._is_connected)
        self.assertEqual(manager.password, "test_password")
        mock_pykeepass_class.assert_called_once_with(
            self.test_db_path,
            password="test_password",
            keyfile=self.test_keyfile_path,
        )

    def test_connect_failure(self):
        """Test database connection failure."""
        # Create a mock that will raise an exception
        mock_pykeepass_class = Mock(side_effect=Exception("Connection failed"))
        
        # Use dependency injection
        manager = KeePassManager(
            self.test_db_path,
            self.test_keyfile_path,
            pykeepass_class=mock_pykeepass_class
        )
        with self.assertRaises(KeePassError):
            manager.connect("wrong_password")

    def test_disconnect(self):
        """Test database disconnection."""
        self.manager.kp = Mock()
        self.manager._is_connected = True
        self.manager.disconnect()
        self.assertFalse(self.manager._is_connected)
        self.assertEqual(self.manager.password, "")
        self.assertIsNone(self.manager.kp)

    def test_is_connected(self):
        """Test connection status check."""
        self.assertFalse(self.manager.is_connected())

        self.manager._is_connected = True
        self.assertTrue(self.manager.is_connected())

    def test_find_entry_not_connected(self):
        """Test finding entry when not connected."""
        with self.assertRaises(KeePassError):
            self.manager.find_entry("test_entry")

    def test_find_entry_success(self):
        """Test successful entry finding."""
        # Mock the PyKeePass instance
        mock_kp = Mock()
        mock_entry = Mock()
        mock_kp.find_entries.return_value = mock_entry
        mock_kp.root_group = Mock()
        self.manager.kp = mock_kp
        self.manager._is_connected = True

        entry, group, title = self.manager.find_entry("test_entry")

        self.assertEqual(entry, mock_entry)
        self.assertEqual(group, mock_kp.root_group)
        self.assertEqual(title, "test_entry")
        mock_kp.find_entries.assert_called_once_with(title="test_entry", first=True)

    def test_get_secret_not_connected(self):
        """Test getting secret when not connected."""
        with self.assertRaises(KeePassError):
            self.manager.get_secret("test_entry", "password")

    def test_get_secret_success(self):
        """Test successful secret retrieval."""
        # Mock the PyKeePass instance and entry
        mock_kp = Mock()
        mock_entry = Mock()
        mock_entry.password = "secret123"
        mock_kp.find_entries.return_value = mock_entry
        mock_kp.root_group = Mock()
        self.manager.kp = mock_kp
        self.manager._is_connected = True

        secret = self.manager.get_secret("test_entry", "password")

        self.assertEqual(secret, "secret123")

    def test_substitute_placeholders_not_connected(self):
        """Test substituting placeholders when not connected."""
        # Ensure manager is not connected
        self.manager.disconnect()
        with self.assertRaises(KeePassError):
            self.manager.substitute_placeholders('${"test"."password"}')

    def test_substitute_placeholders_success(self):
        """Test successful placeholder substitution."""
        # Mock the get_secret method to return a specific value
        self.manager.get_secret = Mock(return_value="secret123")
        self.manager._is_connected = True

        result = self.manager.substitute_placeholders('${"test"."password"}')

        self.assertEqual(result, "secret123")
        self.manager.get_secret.assert_called_once_with("test", "password")

    def test_format_placeholder(self):
        """Test placeholder formatting."""
        result = self.manager.format_placeholder("test_entry", "password")
        self.assertEqual(result, '${"test_entry".password}')

        # Test with attribute that needs quotes
        result = self.manager.format_placeholder("test_entry", "API Key")
        self.assertEqual(result, '${"test_entry"."API Key"}')

    def test_save_database_not_connected(self):
        """Test saving database when not connected."""
        with self.assertRaises(KeePassError):
            self.manager.save_database()

    def test_save_database_success(self):
        """Test successful database save."""
        mock_kp = Mock()
        self.manager.kp = mock_kp
        self.manager._is_connected = True

        self.manager.save_database()

        mock_kp.save.assert_called_once()

    def test_create_entry_not_connected(self):
        """Test creating entry when not connected."""
        with self.assertRaises(KeePassError):
            self.manager.create_entry("test_entry")

    def test_create_entry_success(self):
        """Test successful entry creation."""
        mock_kp = Mock()
        mock_entry = Mock()
        mock_kp.add_entry.return_value = mock_entry
        mock_kp.root_group = Mock()
        self.manager.kp = mock_kp
        self.manager._is_connected = True

        entry = self.manager.create_entry("test_entry", username="testuser")

        self.assertEqual(entry, mock_entry)
        mock_kp.add_entry.assert_called_once_with(
            mock_kp.root_group, title="test_entry", username="testuser", password=""
        )

    def test_update_entry_not_connected(self):
        """Test updating entry when not connected."""
        mock_entry = Mock()
        with self.assertRaises(KeePassError):
            self.manager.update_entry(mock_entry, username="newuser")

    def test_update_entry_success(self):
        """Test successful entry update."""
        mock_kp = Mock()
        # Create a mock entry that has username and url attributes
        mock_entry = Mock()
        mock_entry.username = "olduser"  # Set initial values
        mock_entry.url = "http://old.com"
        mock_entry.notes = "old notes"
        self.manager.kp = mock_kp
        self.manager._is_connected = True

        self.manager.update_entry(
            mock_entry, username="newuser", url="https://example.com"
        )

        # Verify the attributes were set correctly
        self.assertEqual(mock_entry.username, "newuser")
        self.assertEqual(mock_entry.url, "https://example.com")
        self.assertEqual(mock_entry.notes, "old notes")  # Should remain unchanged


if __name__ == "__main__":
    unittest.main()
