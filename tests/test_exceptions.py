"""
Tests for exceptions module
"""
import unittest
from falcon.exceptions import (
    FalconSearchError,
    FalconAPIError,
    FalconAuthenticationError,
    FalconConfigurationError,
    FalconEventSearchError,
    FalconAlertSearchError,
    FalconResourceNotFoundError
)


class TestFalconExceptions(unittest.TestCase):
    """Tests for Falcon exception classes"""

    def test_falcon_search_error_creation(self):
        """Test creating FalconSearchError"""
        error = FalconSearchError("Test error")
        self.assertEqual(str(error), "Test error")
        self.assertIsInstance(error, Exception)

    def test_falcon_api_error_basic(self):
        """Test creating FalconAPIError with just a message"""
        error = FalconAPIError("API error occurred")
        self.assertEqual(str(error), "API error occurred")
        self.assertIsInstance(error, FalconSearchError)

    def test_falcon_authentication_error(self):
        """Test creating FalconAuthenticationError"""
        error = FalconAuthenticationError("Authentication failed")
        self.assertEqual(str(error), "Authentication failed")
        self.assertIsInstance(error, FalconSearchError)

    def test_falcon_configuration_error(self):
        """Test creating FalconConfigurationError"""
        error = FalconConfigurationError("Configuration invalid")
        self.assertEqual(str(error), "Configuration invalid")
        self.assertIsInstance(error, FalconSearchError)


if __name__ == '__main__':
    unittest.main()
