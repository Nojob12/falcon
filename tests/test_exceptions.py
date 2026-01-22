"""
Tests for exceptions module
"""
import pytest
from falcon.exceptions import (
    FalconSearchError,
    FalconAPIError,
    FalconAuthenticationError,
    FalconConfigurationError,
    FalconEventSearchError,
    FalconAlertSearchError,
    FalconResourceNotFoundError
)


class TestFalconSearchError:
    """Tests for FalconSearchError base exception"""

    def test_falcon_search_error_creation(self):
        """Test creating FalconSearchError"""
        error = FalconSearchError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)

    def test_falcon_search_error_inheritance(self):
        """Test that all custom exceptions inherit from FalconSearchError"""
        assert issubclass(FalconAPIError, FalconSearchError)
        assert issubclass(FalconAuthenticationError, FalconSearchError)
        assert issubclass(FalconConfigurationError, FalconSearchError)
        assert issubclass(FalconEventSearchError, FalconSearchError)
        assert issubclass(FalconAlertSearchError, FalconSearchError)
        assert issubclass(FalconResourceNotFoundError, FalconSearchError)


class TestFalconAPIError:
    """Tests for FalconAPIError"""

    def test_falcon_api_error_basic(self):
        """Test creating FalconAPIError with just a message"""
        error = FalconAPIError("API error occurred")
        assert str(error) == "API error occurred"
        assert error.status_code is None
        assert error.response is None

    def test_falcon_api_error_with_status_code(self):
        """Test creating FalconAPIError with status code"""
        error = FalconAPIError("API error", status_code=404)
        assert str(error) == "API error"
        assert error.status_code == 404
        assert error.response is None

    def test_falcon_api_error_with_response(self):
        """Test creating FalconAPIError with response"""
        response = {"body": {"errors": ["Not found"]}}
        error = FalconAPIError("API error", status_code=404, response=response)
        assert str(error) == "API error"
        assert error.status_code == 404
        assert error.response == response


class TestFalconAuthenticationError:
    """Tests for FalconAuthenticationError"""

    def test_falcon_authentication_error(self):
        """Test creating FalconAuthenticationError"""
        error = FalconAuthenticationError("Authentication failed")
        assert str(error) == "Authentication failed"
        assert isinstance(error, FalconSearchError)


class TestFalconConfigurationError:
    """Tests for FalconConfigurationError"""

    def test_falcon_configuration_error(self):
        """Test creating FalconConfigurationError"""
        error = FalconConfigurationError("Configuration invalid")
        assert str(error) == "Configuration invalid"
        assert isinstance(error, FalconSearchError)


class TestFalconEventSearchError:
    """Tests for FalconEventSearchError"""

    def test_falcon_event_search_error(self):
        """Test creating FalconEventSearchError"""
        error = FalconEventSearchError("Event search failed")
        assert str(error) == "Event search failed"
        assert isinstance(error, FalconSearchError)


class TestFalconAlertSearchError:
    """Tests for FalconAlertSearchError"""

    def test_falcon_alert_search_error(self):
        """Test creating FalconAlertSearchError"""
        error = FalconAlertSearchError("Alert search failed")
        assert str(error) == "Alert search failed"
        assert isinstance(error, FalconSearchError)


class TestFalconResourceNotFoundError:
    """Tests for FalconResourceNotFoundError"""

    def test_falcon_resource_not_found_error(self):
        """Test creating FalconResourceNotFoundError"""
        error = FalconResourceNotFoundError("Resource not found")
        assert str(error) == "Resource not found"
        assert isinstance(error, FalconSearchError)
