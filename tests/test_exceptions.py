"""
Tests for custom exception classes
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


class TestExceptions:
    """Test custom exception classes"""

    def test_falcon_search_error_is_base_exception(self):
        """Test that FalconSearchError is the base exception"""
        error = FalconSearchError("Test error")
        assert isinstance(error, Exception)
        assert str(error) == "Test error"

    def test_falcon_api_error_basic(self):
        """Test FalconAPIError with basic message"""
        error = FalconAPIError("API error occurred")
        assert isinstance(error, FalconSearchError)
        assert str(error) == "API error occurred"
        assert error.status_code is None
        assert error.response is None

    def test_falcon_api_error_with_status_code(self):
        """Test FalconAPIError with status code"""
        error = FalconAPIError("API error", status_code=404)
        assert error.status_code == 404
        assert str(error) == "API error"

    def test_falcon_api_error_with_response(self):
        """Test FalconAPIError with response data"""
        response_data = {"errors": [{"message": "Not found"}]}
        error = FalconAPIError("API error", status_code=404, response=response_data)
        assert error.status_code == 404
        assert error.response == response_data

    def test_falcon_authentication_error(self):
        """Test FalconAuthenticationError"""
        error = FalconAuthenticationError("Authentication failed")
        assert isinstance(error, FalconSearchError)
        assert str(error) == "Authentication failed"

    def test_falcon_configuration_error(self):
        """Test FalconConfigurationError"""
        error = FalconConfigurationError("Configuration invalid")
        assert isinstance(error, FalconSearchError)
        assert str(error) == "Configuration invalid"

    def test_falcon_event_search_error(self):
        """Test FalconEventSearchError"""
        error = FalconEventSearchError("Event search failed")
        assert isinstance(error, FalconSearchError)
        assert str(error) == "Event search failed"

    def test_falcon_alert_search_error(self):
        """Test FalconAlertSearchError"""
        error = FalconAlertSearchError("Alert search failed")
        assert isinstance(error, FalconSearchError)
        assert str(error) == "Alert search failed"

    def test_falcon_resource_not_found_error(self):
        """Test FalconResourceNotFoundError"""
        error = FalconResourceNotFoundError("Resource not found")
        assert isinstance(error, FalconSearchError)
        assert str(error) == "Resource not found"

    def test_exception_inheritance_chain(self):
        """Test that all custom exceptions inherit from FalconSearchError"""
        exceptions_to_test = [
            FalconAPIError("test"),
            FalconAuthenticationError("test"),
            FalconConfigurationError("test"),
            FalconEventSearchError("test"),
            FalconAlertSearchError("test"),
            FalconResourceNotFoundError("test")
        ]
        
        for exc in exceptions_to_test:
            assert isinstance(exc, FalconSearchError)
            assert isinstance(exc, Exception)
