"""
Tests for event_search module
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from falcon.config import FalconConfig
from falcon.search.event_search import FalconEventSearch
from falcon.exceptions import (
    FalconEventSearchError,
    FalconAPIError,
    FalconAuthenticationError,
    FalconResourceNotFoundError
)


@pytest.fixture
def mock_config():
    """Fixture for mock FalconConfig"""
    return FalconConfig(
        client_id="test_client_id",
        client_secret="test_client_secret",
        base_url="https://api.crowdstrike.com"
    )


@pytest.fixture
def mock_ngsiem_client():
    """Fixture for mock NGSIEM client"""
    with patch('falcon.search.event_search.NGSIEM') as mock:
        yield mock


class TestFalconEventSearchInit:
    """Tests for FalconEventSearch initialization"""

    def test_init_success(self, mock_config, mock_ngsiem_client):
        """Test successful initialization"""
        event_search = FalconEventSearch(mock_config)
        
        assert event_search.config == mock_config
        mock_ngsiem_client.assert_called_once_with(
            client_id=mock_config.client_id,
            client_secret=mock_config.client_secret,
            base_url=mock_config.base_url
        )

    def test_init_authentication_error(self, mock_config, mock_ngsiem_client):
        """Test initialization with authentication error"""
        mock_ngsiem_client.side_effect = Exception("Authentication failed")
        
        with pytest.raises(FalconAuthenticationError) as excinfo:
            FalconEventSearch(mock_config)
        
        assert "Falcon認証に失敗しました" in str(excinfo.value)


class TestFalconEventSearchStartSearch:
    """Tests for _start_search method"""

    def test_start_search_success(self, mock_config, mock_ngsiem_client):
        """Test successful search start"""
        mock_client_instance = Mock()
        mock_ngsiem_client.return_value = mock_client_instance
        
        mock_client_instance.start_search_v1.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["search_id_123"]
            }
        }
        
        event_search = FalconEventSearch(mock_config)
        search_id = event_search._start_search(
            query="event_simpleName='ProcessRollup2'",
            start_time="2024-01-01T00:00:00Z",
            end_time="2024-01-02T00:00:00Z",
            limit=1000
        )
        
        assert search_id == "search_id_123"
        mock_client_instance.start_search_v1.assert_called_once_with(
            filter="event_simpleName='ProcessRollup2'",
            start="2024-01-01T00:00:00Z",
            end="2024-01-02T00:00:00Z",
            limit=1000
        )

    def test_start_search_api_error(self, mock_config, mock_ngsiem_client):
        """Test search start with API error"""
        mock_client_instance = Mock()
        mock_ngsiem_client.return_value = mock_client_instance
        
        mock_client_instance.start_search_v1.return_value = {
            "status_code": 403,
            "body": {
                "errors": ["Forbidden"]
            }
        }
        
        event_search = FalconEventSearch(mock_config)
        
        with pytest.raises(FalconAPIError) as excinfo:
            event_search._start_search(
                query="test_query",
                start_time="2024-01-01T00:00:00Z",
                end_time="2024-01-02T00:00:00Z",
                limit=1000
            )
        
        assert "イベント検索の開始に失敗しました" in str(excinfo.value)
        assert excinfo.value.status_code == 403

    def test_start_search_missing_resources(self, mock_config, mock_ngsiem_client):
        """Test search start with missing resources key"""
        mock_client_instance = Mock()
        mock_ngsiem_client.return_value = mock_client_instance
        
        mock_client_instance.start_search_v1.return_value = {
            "status_code": 200,
            "body": {}
        }
        
        event_search = FalconEventSearch(mock_config)
        
        with pytest.raises(FalconResourceNotFoundError) as excinfo:
            event_search._start_search(
                query="test_query",
                start_time="2024-01-01T00:00:00Z",
                end_time="2024-01-02T00:00:00Z",
                limit=1000
            )
        
        assert "resourcesキーが含まれていません" in str(excinfo.value)

    def test_start_search_empty_resources(self, mock_config, mock_ngsiem_client):
        """Test search start with empty resources"""
        mock_client_instance = Mock()
        mock_ngsiem_client.return_value = mock_client_instance
        
        mock_client_instance.start_search_v1.return_value = {
            "status_code": 200,
            "body": {
                "resources": []
            }
        }
        
        event_search = FalconEventSearch(mock_config)
        
        with pytest.raises(FalconResourceNotFoundError) as excinfo:
            event_search._start_search(
                query="test_query",
                start_time="2024-01-01T00:00:00Z",
                end_time="2024-01-02T00:00:00Z",
                limit=1000
            )
        
        assert "検索IDが取得できませんでした" in str(excinfo.value)

    def test_start_search_unexpected_error(self, mock_config, mock_ngsiem_client):
        """Test search start with unexpected error"""
        mock_client_instance = Mock()
        mock_ngsiem_client.return_value = mock_client_instance
        
        mock_client_instance.start_search_v1.side_effect = RuntimeError("Unexpected error")
        
        event_search = FalconEventSearch(mock_config)
        
        with pytest.raises(FalconEventSearchError) as excinfo:
            event_search._start_search(
                query="test_query",
                start_time="2024-01-01T00:00:00Z",
                end_time="2024-01-02T00:00:00Z",
                limit=1000
            )
        
        assert "検索開始中にエラーが発生しました" in str(excinfo.value)


class TestFalconEventSearchGetResults:
    """Tests for _get_search_results method"""

    def test_get_search_results_success(self, mock_config, mock_ngsiem_client):
        """Test successful search results retrieval"""
        mock_client_instance = Mock()
        mock_ngsiem_client.return_value = mock_client_instance
        
        mock_client_instance.get_search_status_v1.return_value = {
            "status_code": 200,
            "body": {
                "resources": [{
                    "status": "DONE",
                    "results": [
                        {"event_id": "1", "event_type": "ProcessRollup2"},
                        {"event_id": "2", "event_type": "ProcessRollup2"}
                    ]
                }]
            }
        }
        
        event_search = FalconEventSearch(mock_config)
        results = event_search._get_search_results(
            search_id="search_id_123",
            poll_interval=1,
            max_wait_time=10
        )
        
        assert len(results) == 2
        assert results[0]["event_id"] == "1"
        assert results[1]["event_id"] == "2"

    def test_get_search_results_pending_then_done(self, mock_config, mock_ngsiem_client):
        """Test search results with pending status then done"""
        mock_client_instance = Mock()
        mock_ngsiem_client.return_value = mock_client_instance
        
        # First call returns PENDING, second call returns DONE
        mock_client_instance.get_search_status_v1.side_effect = [
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
                        "status": "DONE",
                        "results": [{"event_id": "1"}]
                    }]
                }
            }
        ]
        
        event_search = FalconEventSearch(mock_config)
        with patch('time.sleep'):  # Mock sleep to speed up test
            results = event_search._get_search_results(
                search_id="search_id_123",
                poll_interval=1,
                max_wait_time=10
            )
        
        assert len(results) == 1
        assert results[0]["event_id"] == "1"

    def test_get_search_results_running_then_done(self, mock_config, mock_ngsiem_client):
        """Test search results with running status then done"""
        mock_client_instance = Mock()
        mock_ngsiem_client.return_value = mock_client_instance
        
        mock_client_instance.get_search_status_v1.side_effect = [
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
                        "results": [{"event_id": "1"}]
                    }]
                }
            }
        ]
        
        event_search = FalconEventSearch(mock_config)
        with patch('time.sleep'):
            results = event_search._get_search_results(
                search_id="search_id_123",
                poll_interval=1,
                max_wait_time=10
            )
        
        assert len(results) == 1

    def test_get_search_results_error_status(self, mock_config, mock_ngsiem_client):
        """Test search results with error status"""
        mock_client_instance = Mock()
        mock_ngsiem_client.return_value = mock_client_instance
        
        mock_client_instance.get_search_status_v1.return_value = {
            "status_code": 200,
            "body": {
                "resources": [{
                    "status": "ERROR",
                    "error_message": "Search failed"
                }]
            }
        }
        
        event_search = FalconEventSearch(mock_config)
        
        with pytest.raises(FalconEventSearchError) as excinfo:
            event_search._get_search_results(
                search_id="search_id_123",
                poll_interval=1,
                max_wait_time=10
            )
        
        assert "検索がエラーで終了しました" in str(excinfo.value)

    def test_get_search_results_timeout(self, mock_config, mock_ngsiem_client):
        """Test search results timeout"""
        mock_client_instance = Mock()
        mock_ngsiem_client.return_value = mock_client_instance
        
        mock_client_instance.get_search_status_v1.return_value = {
            "status_code": 200,
            "body": {
                "resources": [{
                    "status": "RUNNING"
                }]
            }
        }
        
        event_search = FalconEventSearch(mock_config)
        
        with patch('time.sleep'):
            with pytest.raises(FalconEventSearchError) as excinfo:
                event_search._get_search_results(
                    search_id="search_id_123",
                    poll_interval=5,
                    max_wait_time=10
                )
        
        assert "検索がタイムアウトしました" in str(excinfo.value)

    def test_get_search_results_api_error(self, mock_config, mock_ngsiem_client):
        """Test search results with API error"""
        mock_client_instance = Mock()
        mock_ngsiem_client.return_value = mock_client_instance
        
        mock_client_instance.get_search_status_v1.return_value = {
            "status_code": 500,
            "body": {
                "errors": ["Internal server error"]
            }
        }
        
        event_search = FalconEventSearch(mock_config)
        
        with pytest.raises(FalconAPIError) as excinfo:
            event_search._get_search_results(
                search_id="search_id_123",
                poll_interval=1,
                max_wait_time=10
            )
        
        assert "検索ステータスの取得に失敗しました" in str(excinfo.value)

    def test_get_search_results_unknown_status(self, mock_config, mock_ngsiem_client):
        """Test search results with unknown status"""
        mock_client_instance = Mock()
        mock_ngsiem_client.return_value = mock_client_instance
        
        mock_client_instance.get_search_status_v1.return_value = {
            "status_code": 200,
            "body": {
                "resources": [{
                    "status": "UNKNOWN_STATUS"
                }]
            }
        }
        
        event_search = FalconEventSearch(mock_config)
        
        with pytest.raises(FalconEventSearchError) as excinfo:
            event_search._get_search_results(
                search_id="search_id_123",
                poll_interval=1,
                max_wait_time=10
            )
        
        assert "不明なステータス" in str(excinfo.value)


class TestFalconEventSearchComplete:
    """Tests for complete search_events flow"""

    def test_search_events_success(self, mock_config, mock_ngsiem_client):
        """Test complete event search flow"""
        mock_client_instance = Mock()
        mock_ngsiem_client.return_value = mock_client_instance
        
        # Mock start_search_v1
        mock_client_instance.start_search_v1.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["search_id_123"]
            }
        }
        
        # Mock get_search_status_v1
        mock_client_instance.get_search_status_v1.return_value = {
            "status_code": 200,
            "body": {
                "resources": [{
                    "status": "DONE",
                    "results": [
                        {"event_id": "1", "event_type": "ProcessRollup2"}
                    ]
                }]
            }
        }
        
        event_search = FalconEventSearch(mock_config)
        results = event_search.search_events(
            query="event_simpleName='ProcessRollup2'",
            start_time="2024-01-01T00:00:00Z",
            end_time="2024-01-02T00:00:00Z",
            limit=1000
        )
        
        assert len(results) == 1
        assert results[0]["event_id"] == "1"

    def test_close(self, mock_config, mock_ngsiem_client):
        """Test close method"""
        event_search = FalconEventSearch(mock_config)
        assert hasattr(event_search, 'client')
        
        event_search.close()
        assert not hasattr(event_search, 'client')
