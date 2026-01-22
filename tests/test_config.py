"""
Tests for config module
"""
import os
import unittest
from falcon.config import FalconConfig
from falcon.exceptions import FalconConfigurationError


class TestFalconConfig(unittest.TestCase):
    """Tests for FalconConfig class"""

    def test_config_with_explicit_credentials(self):
        """Test creating config with explicit credentials"""
        config = FalconConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            base_url="https://api.crowdstrike.com"
        )
        self.assertEqual(config.client_id, "test_client_id")
        self.assertEqual(config.client_secret, "test_client_secret")
        self.assertEqual(config.base_url, "https://api.crowdstrike.com")

    def test_config_with_default_base_url(self):
        """Test creating config with default base_url"""
        config = FalconConfig(
            client_id="test_client_id",
            client_secret="test_client_secret"
        )
        self.assertEqual(config.client_id, "test_client_id")
        self.assertEqual(config.client_secret, "test_client_secret")
        self.assertEqual(config.base_url, "auto")

    def test_to_dict(self):
        """Test converting config to dictionary"""
        config = FalconConfig(
            client_id="test_id",
            client_secret="test_secret",
            base_url="https://api.crowdstrike.com"
        )
        
        config_dict = config.to_dict()
        self.assertEqual(config_dict, {
            "client_id": "test_id",
            "client_secret": "test_secret",
            "base_url": "https://api.crowdstrike.com"
        })


if __name__ == '__main__':
    unittest.main()
