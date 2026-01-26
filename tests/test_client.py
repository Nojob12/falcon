"""
Tests for FalconSearchClient class
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from falcon.client import FalconSearchClient
from falcon.config import FalconConfig


class TestFalconSearchClientInit:
    """Test FalconSearchClient initialization"""

    @patch('falcon.client.FalconAlertSearch')
    @patch('falcon.client.FalconEventSearch')
    def test_init_with_config(self, mock_event_search, mock_alert_search, mock_config):
        """Test initialization with FalconConfig object"""
        client = FalconSearchClient(config=mock_config)
        
        assert client.config == mock_config
        mock_event_search.assert_called_once_with(mock_config)
        mock_alert_search.assert_called_once_with(mock_config)

    @patch('falcon.client.FalconAlertSearch')
    @patch('falcon.client.FalconEventSearch')
    @patch('falcon.client.FalconConfig')
    def test_init_with_credentials(self, mock_config_class, mock_event_search, mock_alert_search):
        """Test initialization with client_id and client_secret"""
        mock_config_instance = Mock()
        mock_config_class.return_value = mock_config_instance
        
        client = FalconSearchClient(
            client_id="test_id",
            client_secret="test_secret",
            base_url="auto"
        )
        
        mock_config_class.assert_called_once_with(
            client_id="test_id",
            client_secret="test_secret",
            base_url="auto"
        )
        assert client.config == mock_config_instance


class TestFalconSearchClientEventMethods:
    """Test event search methods"""

    @patch('falcon.client.FalconAlertSearch')
    @patch('falcon.client.FalconEventSearch')
    def test_search_events(self, mock_event_search_class, mock_alert_search, mock_config, sample_event_data):
        """Test search_events method"""
        mock_event_instance = MagicMock()
        mock_event_search_class.return_value = mock_event_instance
        mock_event_instance.search_events.return_value = sample_event_data
        
        client = FalconSearchClient(config=mock_config)
        events = client.search_events(
            query="event_simpleName='ProcessRollup2'",
            start_time="2024-01-01T00:00:00Z",
            end_time="2024-01-01T23:59:59Z",
            limit=5000,
            poll_interval=10,
            max_wait_time=600
        )
        
        assert events == sample_event_data
        mock_event_instance.search_events.assert_called_once_with(
            query="event_simpleName='ProcessRollup2'",
            start_time="2024-01-01T00:00:00Z",
            end_time="2024-01-01T23:59:59Z",
            limit=5000,
            poll_interval=10,
            max_wait_time=600
        )


class TestFalconSearchClientAlertMethods:
    """Test alert search methods"""

    @patch('falcon.client.FalconAlertSearch')
    @patch('falcon.client.FalconEventSearch')
    def test_get_alert_details(self, mock_event_search, mock_alert_search_class, mock_config, sample_alert_data):
        """Test get_alert_details method"""
        mock_alert_instance = MagicMock()
        mock_alert_search_class.return_value = mock_alert_instance
        mock_alert_instance.get_alert_details.return_value = sample_alert_data
        
        client = FalconSearchClient(config=mock_config)
        alert_ids = ["alert_id_1", "alert_id_2"]
        alerts = client.get_alert_details(alert_ids)
        
        assert alerts == sample_alert_data
        mock_alert_instance.get_alert_details.assert_called_once_with(alert_ids)

    @patch('falcon.client.FalconAlertSearch')
    @patch('falcon.client.FalconEventSearch')
    def test_get_single_alert(self, mock_event_search, mock_alert_search_class, mock_config):
        """Test get_single_alert method"""
        mock_alert_instance = MagicMock()
        mock_alert_search_class.return_value = mock_alert_instance
        
        single_alert = {
            "composite_id": "alert_id_1",
            "severity": "high",
            "status": "new"
        }
        mock_alert_instance.get_single_alert.return_value = single_alert
        
        client = FalconSearchClient(config=mock_config)
        alert = client.get_single_alert("alert_id_1")
        
        assert alert == single_alert
        mock_alert_instance.get_single_alert.assert_called_once_with("alert_id_1")

    @patch('falcon.client.FalconAlertSearch')
    @patch('falcon.client.FalconEventSearch')
    def test_search_alerts_by_filter(self, mock_event_search, mock_alert_search_class, mock_config):
        """Test search_alerts_by_filter method"""
        mock_alert_instance = MagicMock()
        mock_alert_search_class.return_value = mock_alert_instance
        
        search_result = {
            "resources": ["alert_id_1", "alert_id_2"],
            "meta": {"pagination": {"total": 2}}
        }
        mock_alert_instance.search_alerts_by_filter.return_value = search_result
        
        client = FalconSearchClient(config=mock_config)
        result = client.search_alerts_by_filter(
            filter_query="severity:'high'",
            limit=100,
            offset=0,
            sort="created_timestamp.desc"
        )
        
        assert result == search_result
        mock_alert_instance.search_alerts_by_filter.assert_called_once_with(
            filter_query="severity:'high'",
            limit=100,
            offset=0,
            sort="created_timestamp.desc"
        )

    @patch('falcon.client.FalconAlertSearch')
    @patch('falcon.client.FalconEventSearch')
    def test_search_and_get_alerts(self, mock_event_search, mock_alert_search_class, mock_config, sample_alert_data):
        """Test search_and_get_alerts method"""
        mock_alert_instance = MagicMock()
        mock_alert_search_class.return_value = mock_alert_instance
        mock_alert_instance.search_and_get_alerts.return_value = sample_alert_data
        
        client = FalconSearchClient(config=mock_config)
        alerts = client.search_and_get_alerts(
            filter_query="severity:'critical'",
            limit=50
        )
        
        assert alerts == sample_alert_data
        mock_alert_instance.search_and_get_alerts.assert_called_once_with(
            filter_query="severity:'critical'",
            limit=50,
            offset=0,
            sort=None
        )


class TestFalconSearchClientCleanup:
    """Test cleanup and context manager methods"""

    @patch('falcon.client.FalconAlertSearch')
    @patch('falcon.client.FalconEventSearch')
    def test_close(self, mock_event_search_class, mock_alert_search_class, mock_config):
        """Test close method"""
        mock_event_instance = MagicMock()
        mock_alert_instance = MagicMock()
        mock_event_search_class.return_value = mock_event_instance
        mock_alert_search_class.return_value = mock_alert_instance
        
        client = FalconSearchClient(config=mock_config)
        client.close()
        
        mock_event_instance.close.assert_called_once()
        mock_alert_instance.close.assert_called_once()

    @patch('falcon.client.FalconAlertSearch')
    @patch('falcon.client.FalconEventSearch')
    def test_context_manager(self, mock_event_search_class, mock_alert_search_class, mock_config):
        """Test context manager usage"""
        mock_event_instance = MagicMock()
        mock_alert_instance = MagicMock()
        mock_event_search_class.return_value = mock_event_instance
        mock_alert_search_class.return_value = mock_alert_instance
        
        with FalconSearchClient(config=mock_config) as client:
            assert isinstance(client, FalconSearchClient)
        
        # Verify close was called on exit
        mock_event_instance.close.assert_called_once()
        mock_alert_instance.close.assert_called_once()

    @patch('falcon.client.FalconAlertSearch')
    @patch('falcon.client.FalconEventSearch')
    def test_context_manager_with_exception(self, mock_event_search_class, mock_alert_search_class, mock_config):
        """Test context manager handles exceptions properly"""
        mock_event_instance = MagicMock()
        mock_alert_instance = MagicMock()
        mock_event_search_class.return_value = mock_event_instance
        mock_alert_search_class.return_value = mock_alert_instance
        
        try:
            with FalconSearchClient(config=mock_config) as client:
                raise ValueError("Test exception")
        except ValueError:
            pass
        
        # Verify close was still called despite exception
        mock_event_instance.close.assert_called_once()
        mock_alert_instance.close.assert_called_once()
