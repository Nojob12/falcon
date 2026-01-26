"""
Pytest configuration and fixtures
"""
import pytest
from unittest.mock import Mock, MagicMock
from falcon.config import FalconConfig


@pytest.fixture
def mock_config():
    """Create a mock FalconConfig object"""
    config = Mock(spec=FalconConfig)
    config.client_id = "test_client_id"
    config.client_secret = "test_client_secret"
    config.base_url = "auto"
    return config


@pytest.fixture
def valid_credentials():
    """Return valid test credentials"""
    return {
        "client_id": "test_client_id_123",
        "client_secret": "test_client_secret_456"
    }


@pytest.fixture
def mock_ngsiem_client():
    """Create a mock NGSIEM client"""
    mock_client = MagicMock()
    return mock_client


@pytest.fixture
def mock_alerts_client():
    """Create a mock Alerts client"""
    mock_client = MagicMock()
    return mock_client


@pytest.fixture
def sample_event_data():
    """Sample event data for testing"""
    return [
        {
            "event_simpleName": "ProcessRollup2",
            "timestamp": "2024-01-01T00:00:00Z",
            "ComputerName": "test-host-1",
            "ProcessId": "12345"
        },
        {
            "event_simpleName": "ProcessRollup2",
            "timestamp": "2024-01-01T01:00:00Z",
            "ComputerName": "test-host-2",
            "ProcessId": "67890"
        }
    ]


@pytest.fixture
def sample_alert_data():
    """Sample alert data for testing"""
    return [
        {
            "composite_id": "alert_id_1",
            "severity": "high",
            "status": "new",
            "created_timestamp": "2024-01-01T00:00:00Z"
        },
        {
            "composite_id": "alert_id_2",
            "severity": "medium",
            "status": "in_progress",
            "created_timestamp": "2024-01-01T01:00:00Z"
        }
    ]
