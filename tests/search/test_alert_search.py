"""
Tests for alert_search module
"""
import unittest
from unittest.mock import Mock, patch
from falcon.config import FalconConfig
from falcon.search.alert_search import FalconAlertSearch
from falcon.exceptions import (
    FalconAlertSearchError,
    FalconAuthenticationError
)


class TestFalconAlertSearch(unittest.TestCase):
    """Tests for FalconAlertSearch"""

    @patch('falcon.search.alert_search.Alerts')
    def test_init_success(self, mock_alerts_client):
        """Test successful initialization"""
        config = FalconConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            base_url="https://api.crowdstrike.com"
        )
        alert_search = FalconAlertSearch(config)
        
        self.assertEqual(alert_search.config, config)
        mock_alerts_client.assert_called_once_with(
            client_id=config.client_id,
            client_secret=config.client_secret,
            base_url=config.base_url
        )

    @patch('falcon.search.alert_search.Alerts')
    def test_init_authentication_error(self, mock_alerts_client):
        """Test initialization with authentication error"""
        config = FalconConfig(
            client_id="test_client_id",
            client_secret="test_client_secret"
        )
        mock_alerts_client.side_effect = Exception("Authentication failed")
        
        with self.assertRaises(FalconAuthenticationError):
            FalconAlertSearch(config)

    @patch('falcon.search.alert_search.Alerts')
    def test_get_alert_details_success(self, mock_alerts_client):
        """Test successful alert details retrieval"""
        config = FalconConfig(
            client_id="test_client_id",
            client_secret="test_client_secret"
        )
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
        
        alert_search = FalconAlertSearch(config)
        results = alert_search.get_alert_details(["alert_1", "alert_2"])
        
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["alert_id"], "alert_1")
        self.assertEqual(results[1]["alert_id"], "alert_2")


if __name__ == '__main__':
    unittest.main()
