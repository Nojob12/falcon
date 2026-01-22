"""
Tests for client module
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from falcon.config import FalconConfig
from falcon.client import FalconSearchClient
from falcon.exceptions import FalconSearchError


@pytest.fixture
def mock_config():
    """Fixture for mock FalconConfig"""
    return FalconConfig(
        client_id="test_client_id",
        client_secret="test_client_secret",
        base_url="https://api.crowdstrike.com"
    )


class TestFalconSearchClientInit:
    """Tests for FalconSearchClient initialization"""

    @patch('falcon.client.FalconEventSearch')
    @patch('falcon.client.FalconAlertSearch')
    def test_init_with_config(self, mock_alert_search, mock_event_search, mock_config):
        """Test initialization with config object"""
        client = FalconSearchClient(config=mock_config)
        
        assert client.config == mock_config
        mock_event_search.assert_called_once_with(mock_config)
        mock_alert_search.assert_called_once_with(mock_config)

    @patch('falcon.client.FalconEventSearch')
    @patch('falcon.client.FalconAlertSearch')
    def test_init_with_credentials(self, mock_alert_search, mock_event_search):
        """Test initialization with client_id and client_secret"""
        client = FalconSearchClient(
            client_id="test_id",
            client_secret="test_secret",
            base_url="https://api.crowdstrike.com"
        )
        
        assert client.config is not None
        assert client.config.client_id == "test_id"
        assert client.config.client_secret == "test_secret"
        assert client.config.base_url == "https://api.crowdstrike.com"

    @patch('falcon.client.FalconEventSearch')
    @patch('falcon.client.FalconAlertSearch')
    def test_init_creates_search_clients(self, mock_alert_search, mock_event_search, mock_config):
        """Test that event and alert search clients are created"""
        client = FalconSearchClient(config=mock_config)
        
        assert hasattr(client, 'event_search')
        assert hasattr(client, 'alert_search')


class TestFalconSearchClientEventMethods:
    """Tests for event search methods"""

    @patch('falcon.client.FalconEventSearch')
    @patch('falcon.client.FalconAlertSearch')
    def test_search_events(self, mock_alert_search, mock_event_search, mock_config):
        """Test search_events method"""
        mock_event_instance = Mock()
        mock_event_search.return_value = mock_event_instance
        mock_event_instance.search_events.return_value = [
            {"event_id": "1", "event_type": "ProcessRollup2"}
        ]
        
        client = FalconSearchClient(config=mock_config)
        results = client.search_events(
            query="event_simpleName='ProcessRollup2'",
            start_time="2024-01-01T00:00:00Z",
            end_time="2024-01-02T00:00:00Z",
            limit=1000,
            poll_interval=5,
            max_wait_time=300
        )
        
        assert len(results) == 1
        assert results[0]["event_id"] == "1"
        
        mock_event_instance.search_events.assert_called_once_with(
            query="event_simpleName='ProcessRollup2'",
            start_time="2024-01-01T00:00:00Z",
            end_time="2024-01-02T00:00:00Z",
            limit=1000,
            poll_interval=5,
            max_wait_time=300
        )

    @patch('falcon.client.FalconEventSearch')
    @patch('falcon.client.FalconAlertSearch')
    def test_search_events_with_defaults(self, mock_alert_search, mock_event_search, mock_config):
        """Test search_events with default parameters"""
        mock_event_instance = Mock()
        mock_event_search.return_value = mock_event_instance
        mock_event_instance.search_events.return_value = []
        
        client = FalconSearchClient(config=mock_config)
        results = client.search_events(
            query="test_query",
            start_time="2024-01-01T00:00:00Z",
            end_time="2024-01-02T00:00:00Z"
        )
        
        mock_event_instance.search_events.assert_called_once()
        call_args = mock_event_instance.search_events.call_args
        assert call_args.kwargs['limit'] == 10000
        assert call_args.kwargs['poll_interval'] == 5
        assert call_args.kwargs['max_wait_time'] == 300


class TestFalconSearchClientAlertMethods:
    """Tests for alert search methods"""

    @patch('falcon.client.FalconEventSearch')
    @patch('falcon.client.FalconAlertSearch')
    def test_get_alert_details(self, mock_alert_search, mock_event_search, mock_config):
        """Test get_alert_details method"""
        mock_alert_instance = Mock()
        mock_alert_search.return_value = mock_alert_instance
        mock_alert_instance.get_alert_details.return_value = [
            {"alert_id": "alert_1", "severity": "high"}
        ]
        
        client = FalconSearchClient(config=mock_config)
        results = client.get_alert_details(["alert_1"])
        
        assert len(results) == 1
        assert results[0]["alert_id"] == "alert_1"
        
        mock_alert_instance.get_alert_details.assert_called_once_with(["alert_1"])

    @patch('falcon.client.FalconEventSearch')
    @patch('falcon.client.FalconAlertSearch')
    def test_get_single_alert(self, mock_alert_search, mock_event_search, mock_config):
        """Test get_single_alert method"""
        mock_alert_instance = Mock()
        mock_alert_search.return_value = mock_alert_instance
        mock_alert_instance.get_single_alert.return_value = {
            "alert_id": "alert_1",
            "severity": "high"
        }
        
        client = FalconSearchClient(config=mock_config)
        result = client.get_single_alert("alert_1")
        
        assert result["alert_id"] == "alert_1"
        mock_alert_instance.get_single_alert.assert_called_once_with("alert_1")

    @patch('falcon.client.FalconEventSearch')
    @patch('falcon.client.FalconAlertSearch')
    def test_search_alerts_by_filter(self, mock_alert_search, mock_event_search, mock_config):
        """Test search_alerts_by_filter method"""
        mock_alert_instance = Mock()
        mock_alert_search.return_value = mock_alert_instance
        mock_alert_instance.search_alerts_by_filter.return_value = {
            "alert_ids": ["alert_1", "alert_2"],
            "total": 2,
            "offset": 0
        }
        
        client = FalconSearchClient(config=mock_config)
        result = client.search_alerts_by_filter(
            filter_query="severity:'high'",
            limit=100,
            offset=0,
            sort="created_timestamp.desc"
        )
        
        assert result["alert_ids"] == ["alert_1", "alert_2"]
        assert result["total"] == 2
        
        mock_alert_instance.search_alerts_by_filter.assert_called_once_with(
            filter_query="severity:'high'",
            limit=100,
            offset=0,
            sort="created_timestamp.desc"
        )

    @patch('falcon.client.FalconEventSearch')
    @patch('falcon.client.FalconAlertSearch')
    def test_search_and_get_alerts(self, mock_alert_search, mock_event_search, mock_config):
        """Test search_and_get_alerts method"""
        mock_alert_instance = Mock()
        mock_alert_search.return_value = mock_alert_instance
        mock_alert_instance.search_and_get_alerts.return_value = [
            {"alert_id": "alert_1", "severity": "high"},
            {"alert_id": "alert_2", "severity": "medium"}
        ]
        
        client = FalconSearchClient(config=mock_config)
        results = client.search_and_get_alerts(
            filter_query="severity:'high'",
            limit=50,
            offset=10,
            sort="created_timestamp.desc"
        )
        
        assert len(results) == 2
        
        mock_alert_instance.search_and_get_alerts.assert_called_once_with(
            filter_query="severity:'high'",
            limit=50,
            offset=10,
            sort="created_timestamp.desc"
        )


class TestFalconSearchClientCleanup:
    """Tests for cleanup and context manager"""

    @patch('falcon.client.FalconEventSearch')
    @patch('falcon.client.FalconAlertSearch')
    def test_close(self, mock_alert_search, mock_event_search, mock_config):
        """Test close method"""
        mock_event_instance = Mock()
        mock_alert_instance = Mock()
        mock_event_search.return_value = mock_event_instance
        mock_alert_search.return_value = mock_alert_instance
        
        client = FalconSearchClient(config=mock_config)
        client.close()
        
        mock_event_instance.close.assert_called_once()
        mock_alert_instance.close.assert_called_once()

    @patch('falcon.client.FalconEventSearch')
    @patch('falcon.client.FalconAlertSearch')
    def test_context_manager(self, mock_alert_search, mock_event_search, mock_config):
        """Test context manager usage"""
        mock_event_instance = Mock()
        mock_alert_instance = Mock()
        mock_event_search.return_value = mock_event_instance
        mock_alert_search.return_value = mock_alert_instance
        
        with FalconSearchClient(config=mock_config) as client:
            assert client is not None
        
        # close() should be called when exiting context
        mock_event_instance.close.assert_called_once()
        mock_alert_instance.close.assert_called_once()

    @patch('falcon.client.FalconEventSearch')
    @patch('falcon.client.FalconAlertSearch')
    def test_context_manager_with_exception(self, mock_alert_search, mock_event_search, mock_config):
        """Test context manager with exception"""
        mock_event_instance = Mock()
        mock_alert_instance = Mock()
        mock_event_search.return_value = mock_event_instance
        mock_alert_search.return_value = mock_alert_instance
        
        try:
            with FalconSearchClient(config=mock_config) as client:
                raise RuntimeError("Test exception")
        except RuntimeError:
            pass
        
        # close() should still be called even when exception occurs
        mock_event_instance.close.assert_called_once()
        mock_alert_instance.close.assert_called_once()
