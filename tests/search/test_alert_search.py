"""
Tests for alert_search module
"""
import pytest
from unittest.mock import Mock, patch
from falcon.config import FalconConfig
from falcon.search.alert_search import FalconAlertSearch
from falcon.exceptions import (
    FalconAlertSearchError,
    FalconAPIError,
    FalconAuthenticationError
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
def mock_alerts_client():
    """Fixture for mock Alerts client"""
    with patch('falcon.search.alert_search.Alerts') as mock:
        yield mock


class TestFalconAlertSearchInit:
    """Tests for FalconAlertSearch initialization"""

    def test_init_success(self, mock_config, mock_alerts_client):
        """Test successful initialization"""
        alert_search = FalconAlertSearch(mock_config)
        
        assert alert_search.config == mock_config
        mock_alerts_client.assert_called_once_with(
            client_id=mock_config.client_id,
            client_secret=mock_config.client_secret,
            base_url=mock_config.base_url
        )

    def test_init_authentication_error(self, mock_config, mock_alerts_client):
        """Test initialization with authentication error"""
        mock_alerts_client.side_effect = Exception("Authentication failed")
        
        with pytest.raises(FalconAuthenticationError) as excinfo:
            FalconAlertSearch(mock_config)
        
        assert "Falcon認証に失敗しました" in str(excinfo.value)


class TestGetAlertDetails:
    """Tests for get_alert_details method"""

    def test_get_alert_details_success(self, mock_config, mock_alerts_client):
        """Test successful alert details retrieval"""
        mock_client_instance = Mock()
        mock_alerts_client.return_value = mock_client_instance
        
        mock_client_instance.post_entities_alerts_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"alert_id": "alert_1", "severity": "high"},
                    {"alert_id": "alert_2", "severity": "medium"}
                ]
            }
        }
        
        alert_search = FalconAlertSearch(mock_config)
        results = alert_search.get_alert_details(["alert_1", "alert_2"])
        
        assert len(results) == 2
        assert results[0]["alert_id"] == "alert_1"
        assert results[1]["alert_id"] == "alert_2"
        
        mock_client_instance.post_entities_alerts_v2.assert_called_once_with(
            body={"composite_ids": ["alert_1", "alert_2"]}
        )

    def test_get_alert_details_empty_list(self, mock_config, mock_alerts_client):
        """Test get_alert_details with empty alert_ids list"""
        mock_client_instance = Mock()
        mock_alerts_client.return_value = mock_client_instance
        
        alert_search = FalconAlertSearch(mock_config)
        
        with pytest.raises(FalconAlertSearchError) as excinfo:
            alert_search.get_alert_details([])
        
        assert "アラートIDが指定されていません" in str(excinfo.value)

    def test_get_alert_details_api_error(self, mock_config, mock_alerts_client):
        """Test get_alert_details with API error"""
        mock_client_instance = Mock()
        mock_alerts_client.return_value = mock_client_instance
        
        mock_client_instance.post_entities_alerts_v2.return_value = {
            "status_code": 404,
            "body": {
                "errors": ["Alerts not found"]
            }
        }
        
        alert_search = FalconAlertSearch(mock_config)
        
        with pytest.raises(FalconAPIError) as excinfo:
            alert_search.get_alert_details(["alert_1"])
        
        assert "アラート詳細の取得に失敗しました" in str(excinfo.value)
        assert excinfo.value.status_code == 404

    def test_get_alert_details_unexpected_error(self, mock_config, mock_alerts_client):
        """Test get_alert_details with unexpected error"""
        mock_client_instance = Mock()
        mock_alerts_client.return_value = mock_client_instance
        
        mock_client_instance.post_entities_alerts_v2.side_effect = RuntimeError("Unexpected error")
        
        alert_search = FalconAlertSearch(mock_config)
        
        with pytest.raises(FalconAlertSearchError) as excinfo:
            alert_search.get_alert_details(["alert_1"])
        
        assert "アラート詳細取得中にエラーが発生しました" in str(excinfo.value)


class TestGetSingleAlert:
    """Tests for get_single_alert method"""

    def test_get_single_alert_success(self, mock_config, mock_alerts_client):
        """Test successful single alert retrieval"""
        mock_client_instance = Mock()
        mock_alerts_client.return_value = mock_client_instance
        
        mock_client_instance.post_entities_alerts_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"alert_id": "alert_1", "severity": "high"}
                ]
            }
        }
        
        alert_search = FalconAlertSearch(mock_config)
        result = alert_search.get_single_alert("alert_1")
        
        assert result is not None
        assert result["alert_id"] == "alert_1"
        assert result["severity"] == "high"

    def test_get_single_alert_not_found(self, mock_config, mock_alerts_client):
        """Test get_single_alert when alert not found"""
        mock_client_instance = Mock()
        mock_alerts_client.return_value = mock_client_instance
        
        mock_client_instance.post_entities_alerts_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": []
            }
        }
        
        alert_search = FalconAlertSearch(mock_config)
        result = alert_search.get_single_alert("nonexistent_alert")
        
        assert result is None


class TestSearchAlertsByFilter:
    """Tests for search_alerts_by_filter method"""

    def test_search_alerts_by_filter_success(self, mock_config, mock_alerts_client):
        """Test successful alert search by filter"""
        mock_client_instance = Mock()
        mock_alerts_client.return_value = mock_client_instance
        
        mock_client_instance.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["alert_1", "alert_2", "alert_3"],
                "meta": {
                    "pagination": {
                        "total": 3,
                        "offset": 0
                    }
                }
            }
        }
        
        alert_search = FalconAlertSearch(mock_config)
        result = alert_search.search_alerts_by_filter(
            filter_query="severity:'high'",
            limit=100,
            offset=0
        )
        
        assert result["alert_ids"] == ["alert_1", "alert_2", "alert_3"]
        assert result["total"] == 3
        assert result["offset"] == 0
        
        mock_client_instance.query_alerts_v2.assert_called_once_with(
            filter="severity:'high'",
            limit=100,
            offset=0
        )

    def test_search_alerts_by_filter_with_sort(self, mock_config, mock_alerts_client):
        """Test alert search with sort parameter"""
        mock_client_instance = Mock()
        mock_alerts_client.return_value = mock_client_instance
        
        mock_client_instance.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["alert_1"],
                "meta": {
                    "pagination": {
                        "total": 1,
                        "offset": 0
                    }
                }
            }
        }
        
        alert_search = FalconAlertSearch(mock_config)
        result = alert_search.search_alerts_by_filter(
            filter_query="severity:'high'",
            limit=50,
            offset=10,
            sort="created_timestamp.desc"
        )
        
        assert result["alert_ids"] == ["alert_1"]
        
        mock_client_instance.query_alerts_v2.assert_called_once_with(
            filter="severity:'high'",
            limit=50,
            offset=10,
            sort="created_timestamp.desc"
        )

    def test_search_alerts_by_filter_api_error(self, mock_config, mock_alerts_client):
        """Test alert search with API error"""
        mock_client_instance = Mock()
        mock_alerts_client.return_value = mock_client_instance
        
        mock_client_instance.query_alerts_v2.return_value = {
            "status_code": 400,
            "body": {
                "errors": ["Invalid filter query"]
            }
        }
        
        alert_search = FalconAlertSearch(mock_config)
        
        with pytest.raises(FalconAPIError) as excinfo:
            alert_search.search_alerts_by_filter(
                filter_query="invalid_query",
                limit=100,
                offset=0
            )
        
        assert "アラート検索に失敗しました" in str(excinfo.value)
        assert excinfo.value.status_code == 400

    def test_search_alerts_by_filter_unexpected_error(self, mock_config, mock_alerts_client):
        """Test alert search with unexpected error"""
        mock_client_instance = Mock()
        mock_alerts_client.return_value = mock_client_instance
        
        mock_client_instance.query_alerts_v2.side_effect = RuntimeError("Unexpected error")
        
        alert_search = FalconAlertSearch(mock_config)
        
        with pytest.raises(FalconAlertSearchError) as excinfo:
            alert_search.search_alerts_by_filter(
                filter_query="severity:'high'",
                limit=100,
                offset=0
            )
        
        assert "アラート検索中にエラーが発生しました" in str(excinfo.value)


class TestSearchAndGetAlerts:
    """Tests for search_and_get_alerts method"""

    def test_search_and_get_alerts_success(self, mock_config, mock_alerts_client):
        """Test successful search and get alerts"""
        mock_client_instance = Mock()
        mock_alerts_client.return_value = mock_client_instance
        
        # Mock query_alerts_v2
        mock_client_instance.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["alert_1", "alert_2"],
                "meta": {
                    "pagination": {
                        "total": 2,
                        "offset": 0
                    }
                }
            }
        }
        
        # Mock post_entities_alerts_v2
        mock_client_instance.post_entities_alerts_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"alert_id": "alert_1", "severity": "high"},
                    {"alert_id": "alert_2", "severity": "medium"}
                ]
            }
        }
        
        alert_search = FalconAlertSearch(mock_config)
        results = alert_search.search_and_get_alerts(
            filter_query="severity:'high'",
            limit=100,
            offset=0
        )
        
        assert len(results) == 2
        assert results[0]["alert_id"] == "alert_1"
        assert results[1]["alert_id"] == "alert_2"

    def test_search_and_get_alerts_no_results(self, mock_config, mock_alerts_client):
        """Test search and get alerts with no results"""
        mock_client_instance = Mock()
        mock_alerts_client.return_value = mock_client_instance
        
        mock_client_instance.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": [],
                "meta": {
                    "pagination": {
                        "total": 0,
                        "offset": 0
                    }
                }
            }
        }
        
        alert_search = FalconAlertSearch(mock_config)
        results = alert_search.search_and_get_alerts(
            filter_query="severity:'critical'",
            limit=100,
            offset=0
        )
        
        assert results == []
        # Should not call post_entities_alerts_v2 when no alert_ids found
        mock_client_instance.post_entities_alerts_v2.assert_not_called()


class TestClose:
    """Tests for close method"""

    def test_close(self, mock_config, mock_alerts_client):
        """Test close method"""
        alert_search = FalconAlertSearch(mock_config)
        assert hasattr(alert_search, 'client')
        
        alert_search.close()
        assert not hasattr(alert_search, 'client')
