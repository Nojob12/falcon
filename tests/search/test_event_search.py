"""
Tests for FalconEventSearch class
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from falcon.search.event_search import FalconEventSearch
from falcon.exceptions import (
    FalconEventSearchError,
    FalconAPIError,
    FalconAuthenticationError,
    FalconResourceNotFoundError
)


class TestFalconEventSearchInit:
    """Test FalconEventSearch initialization"""

    @patch('falcon.search.event_search.NGSIEM')
    def test_init_success(self, mock_ngsiem, mock_config):
        """Test successful initialization"""
        search = FalconEventSearch(mock_config)
        
        mock_ngsiem.assert_called_once_with(
            client_id=mock_config.client_id,
            client_secret=mock_config.client_secret,
            base_url=mock_config.base_url
        )
        assert search.config == mock_config

    @patch('falcon.search.event_search.NGSIEM')
    def test_init_authentication_failure(self, mock_ngsiem, mock_config):
        """Test initialization with authentication failure"""
        mock_ngsiem.side_effect = Exception("Auth failed")
        
        with pytest.raises(FalconAuthenticationError) as exc_info:
            FalconEventSearch(mock_config)
        
        assert "Falcon認証に失敗しました" in str(exc_info.value)


class TestFalconEventSearchStartSearch:
    """Test _start_search method"""

    @patch('falcon.search.event_search.NGSIEM')
    def test_start_search_success(self, mock_ngsiem, mock_config):
        """Test successful search start"""
        mock_client = MagicMock()
        mock_ngsiem.return_value = mock_client
        
        mock_response = {
            "status_code": 200,
            "body": {
                "resources": ["search_id_123"]
            }
        }
        mock_client.start_search_v1.return_value = mock_response
        
        search = FalconEventSearch(mock_config)
        search_id = search._start_search(
            query="event_simpleName='ProcessRollup2'",
            start_time="2024-01-01T00:00:00Z",
            end_time="2024-01-01T23:59:59Z",
            limit=10000
        )
        
        assert search_id == "search_id_123"
        mock_client.start_search_v1.assert_called_once()

    @patch('falcon.search.event_search.NGSIEM')
    def test_start_search_api_error(self, mock_ngsiem, mock_config):
        """Test search start with API error"""
        mock_client = MagicMock()
        mock_ngsiem.return_value = mock_client
        
        mock_response = {
            "status_code": 400,
            "body": {
                "errors": ["Bad request"]
            }
        }
        mock_client.start_search_v1.return_value = mock_response
        
        search = FalconEventSearch(mock_config)
        
        with pytest.raises(FalconAPIError) as exc_info:
            search._start_search("query", "start", "end", 1000)
        
        assert exc_info.value.status_code == 400

    @patch('falcon.search.event_search.NGSIEM')
    def test_start_search_missing_resources(self, mock_ngsiem, mock_config):
        """Test search start with missing resources key"""
        mock_client = MagicMock()
        mock_ngsiem.return_value = mock_client
        
        mock_response = {
            "status_code": 200,
            "body": {}
        }
        mock_client.start_search_v1.return_value = mock_response
        
        search = FalconEventSearch(mock_config)
        
        with pytest.raises(FalconResourceNotFoundError) as exc_info:
            search._start_search("query", "start", "end", 1000)
        
        assert "resources" in str(exc_info.value)

    @patch('falcon.search.event_search.NGSIEM')
    def test_start_search_empty_resources(self, mock_ngsiem, mock_config):
        """Test search start with empty resources array"""
        mock_client = MagicMock()
        mock_ngsiem.return_value = mock_client
        
        mock_response = {
            "status_code": 200,
            "body": {
                "resources": []
            }
        }
        mock_client.start_search_v1.return_value = mock_response
        
        search = FalconEventSearch(mock_config)
        
        with pytest.raises(FalconResourceNotFoundError):
            search._start_search("query", "start", "end", 1000)


class TestFalconEventSearchGetResults:
    """Test _get_search_results method"""

    @patch('falcon.search.event_search.NGSIEM')
    @patch('falcon.search.event_search.time.sleep')
    def test_get_search_results_immediate_success(self, mock_sleep, mock_ngsiem, mock_config, sample_event_data):
        """Test getting search results that are immediately ready"""
        mock_client = MagicMock()
        mock_ngsiem.return_value = mock_client
        
        mock_response = {
            "status_code": 200,
            "body": {
                "resources": [{
                    "status": "DONE",
                    "results": sample_event_data
                }]
            }
        }
        mock_client.get_search_status_v1.return_value = mock_response
        
        search = FalconEventSearch(mock_config)
        events = search._get_search_results("search_id_123", poll_interval=5, max_wait_time=300)
        
        assert events == sample_event_data
        mock_sleep.assert_not_called()

    @patch('falcon.search.event_search.NGSIEM')
    @patch('falcon.search.event_search.time.sleep')
    def test_get_search_results_with_polling(self, mock_sleep, mock_ngsiem, mock_config, sample_event_data):
        """Test getting search results that require polling"""
        mock_client = MagicMock()
        mock_ngsiem.return_value = mock_client
        
        # Simulate progression: PENDING -> RUNNING -> DONE
        mock_responses = [
            {
                "status_code": 200,
                "body": {
                    "resources": [{
                        "status": "PENDING"
                    }]
                }
            },
            {
                "status_code": 200,
                "body": {
                    "resources": [{
                        "status": "RUNNING"
                    }]
                }
            },
            {
                "status_code": 200,
                "body": {
                    "resources": [{
                        "status": "DONE",
                        "results": sample_event_data
                    }]
                }
            }
        ]
        mock_client.get_search_status_v1.side_effect = mock_responses
        
        search = FalconEventSearch(mock_config)
        events = search._get_search_results("search_id_123", poll_interval=5, max_wait_time=300)
        
        assert events == sample_event_data
        assert mock_sleep.call_count == 2

    @patch('falcon.search.event_search.NGSIEM')
    def test_get_search_results_error_status(self, mock_ngsiem, mock_config):
        """Test search results with ERROR status"""
        mock_client = MagicMock()
        mock_ngsiem.return_value = mock_client
        
        mock_response = {
            "status_code": 200,
            "body": {
                "resources": [{
                    "status": "ERROR",
                    "error_message": "Search failed"
                }]
            }
        }
        mock_client.get_search_status_v1.return_value = mock_response
        
        search = FalconEventSearch(mock_config)
        
        with pytest.raises(FalconEventSearchError) as exc_info:
            search._get_search_results("search_id_123", poll_interval=5, max_wait_time=300)
        
        assert "Search failed" in str(exc_info.value)

    @patch('falcon.search.event_search.NGSIEM')
    @patch('falcon.search.event_search.time.sleep')
    def test_get_search_results_timeout(self, mock_sleep, mock_ngsiem, mock_config):
        """Test search results timeout"""
        mock_client = MagicMock()
        mock_ngsiem.return_value = mock_client
        
        # Always return RUNNING status
        mock_response = {
            "status_code": 200,
            "body": {
                "resources": [{
                    "status": "RUNNING"
                }]
            }
        }
        mock_client.get_search_status_v1.return_value = mock_response
        
        search = FalconEventSearch(mock_config)
        
        with pytest.raises(FalconEventSearchError) as exc_info:
            search._get_search_results("search_id_123", poll_interval=5, max_wait_time=10)
        
        assert "タイムアウト" in str(exc_info.value)

    @patch('falcon.search.event_search.NGSIEM')
    def test_get_search_results_api_error(self, mock_ngsiem, mock_config):
        """Test getting results with API error"""
        mock_client = MagicMock()
        mock_ngsiem.return_value = mock_client
        
        mock_response = {
            "status_code": 500,
            "body": {
                "errors": ["Internal server error"]
            }
        }
        mock_client.get_search_status_v1.return_value = mock_response
        
        search = FalconEventSearch(mock_config)
        
        with pytest.raises(FalconAPIError) as exc_info:
            search._get_search_results("search_id_123", poll_interval=5, max_wait_time=300)
        
        assert exc_info.value.status_code == 500


class TestFalconEventSearchIntegration:
    """Test full search_events method"""

    @patch('falcon.search.event_search.NGSIEM')
    @patch('falcon.search.event_search.time.sleep')
    def test_search_events_success(self, mock_sleep, mock_ngsiem, mock_config, sample_event_data):
        """Test complete event search workflow"""
        mock_client = MagicMock()
        mock_ngsiem.return_value = mock_client
        
        # Mock start_search response
        mock_start_response = {
            "status_code": 200,
            "body": {
                "resources": ["search_id_123"]
            }
        }
        mock_client.start_search_v1.return_value = mock_start_response
        
        # Mock get_search_status response
        mock_status_response = {
            "status_code": 200,
            "body": {
                "resources": [{
                    "status": "DONE",
                    "results": sample_event_data
                }]
            }
        }
        mock_client.get_search_status_v1.return_value = mock_status_response
        
        search = FalconEventSearch(mock_config)
        events = search.search_events(
            query="event_simpleName='ProcessRollup2'",
            start_time="2024-01-01T00:00:00Z",
            end_time="2024-01-01T23:59:59Z",
            limit=10000
        )
        
        assert events == sample_event_data


class TestFalconEventSearchClose:
    """Test close method"""

    @patch('falcon.search.event_search.NGSIEM')
    def test_close(self, mock_ngsiem, mock_config):
        """Test close method"""
        search = FalconEventSearch(mock_config)
        search.close()
        
        assert not hasattr(search, 'client') or search.client is None
