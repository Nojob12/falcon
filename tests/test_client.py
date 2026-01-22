"""
Tests for client module
"""
import unittest
from unittest.mock import Mock, patch
from falcon.config import FalconConfig
from falcon.client import FalconSearchClient



class TestFalconSearchClient(unittest.TestCase):
    """Tests for FalconSearchClient"""

    @patch('falcon.client.FalconEventSearch')
    @patch('falcon.client.FalconAlertSearch')
    def test_init_with_credentials(self, mock_alert_search, mock_event_search):
        """Test initialization with client_id and client_secret"""
        client = FalconSearchClient(
            client_id="test_id",
            client_secret="test_secret",
            base_url="https://api.crowdstrike.com"
        )
        
        self.assertIsNotNone(client.config)
        self.assertEqual(client.config.client_id, "test_id")
        self.assertEqual(client.config.client_secret, "test_secret")

    @patch('falcon.client.FalconEventSearch')
    @patch('falcon.client.FalconAlertSearch')
    def test_search_events(self, mock_alert_search, mock_event_search):
        """Test search_events method"""
        mock_event_instance = Mock()
        mock_event_search.return_value = mock_event_instance
        mock_event_instance.search_events.return_value = [
            {"event_id": "1", "event_type": "ProcessRollup2"}
        ]
        
        config = FalconConfig(
            client_id="test_id",
            client_secret="test_secret"
        )
        client = FalconSearchClient(config=config)
        results = client.search_events(
            query="event_simpleName='ProcessRollup2'",
            start_time="2024-01-01T00:00:00Z",
            end_time="2024-01-02T00:00:00Z"
        )
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["event_id"], "1")


if __name__ == '__main__':
    unittest.main()
