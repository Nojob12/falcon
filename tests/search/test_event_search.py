"""
Tests for event_search module
"""
import unittest
from unittest.mock import Mock, patch
from falcon.config import FalconConfig
from falcon.search.event_search import FalconEventSearch
from falcon.exceptions import (
    FalconEventSearchError,
    FalconAuthenticationError
)



class TestFalconEventSearch(unittest.TestCase):
    """Tests for FalconEventSearch"""

    @patch('falcon.search.event_search.NGSIEM')
    def test_init_success(self, mock_ngsiem_client):
        """Test successful initialization"""
        config = FalconConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            base_url="https://api.crowdstrike.com"
        )
        event_search = FalconEventSearch(config)
        
        self.assertEqual(event_search.config, config)
        mock_ngsiem_client.assert_called_once_with(
            client_id=config.client_id,
            client_secret=config.client_secret,
            base_url=config.base_url
        )

    @patch('falcon.search.event_search.NGSIEM')
    def test_init_authentication_error(self, mock_ngsiem_client):
        """Test initialization with authentication error"""
        config = FalconConfig(
            client_id="test_client_id",
            client_secret="test_client_secret"
        )
        mock_ngsiem_client.side_effect = Exception("Authentication failed")
        
        with self.assertRaises(FalconAuthenticationError):
            FalconEventSearch(config)

    @patch('falcon.search.event_search.NGSIEM')
    def test_search_events_success(self, mock_ngsiem_client):
        """Test complete event search flow"""
        config = FalconConfig(
            client_id="test_client_id",
            client_secret="test_client_secret"
        )
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
        
        event_search = FalconEventSearch(config)
        results = event_search.search_events(
            query="event_simpleName='ProcessRollup2'",
            start_time="2024-01-01T00:00:00Z",
            end_time="2024-01-02T00:00:00Z",
            limit=1000
        )
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["event_id"], "1")


if __name__ == '__main__':
    unittest.main()
