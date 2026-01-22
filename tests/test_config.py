"""
Tests for config module
"""
import os
import pytest
from falcon.config import FalconConfig
from falcon.exceptions import FalconConfigurationError


class TestFalconConfig:
    """Tests for FalconConfig class"""

    def test_config_with_explicit_credentials(self):
        """Test creating config with explicit credentials"""
        config = FalconConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            base_url="https://api.crowdstrike.com"
        )
        assert config.client_id == "test_client_id"
        assert config.client_secret == "test_client_secret"
        assert config.base_url == "https://api.crowdstrike.com"

    def test_config_with_default_base_url(self):
        """Test creating config with default base_url"""
        config = FalconConfig(
            client_id="test_client_id",
            client_secret="test_client_secret"
        )
        assert config.client_id == "test_client_id"
        assert config.client_secret == "test_client_secret"
        assert config.base_url == "auto"

    def test_config_with_env_variables(self, monkeypatch):
        """Test creating config from environment variables"""
        monkeypatch.setenv("FALCON_CLIENT_ID", "env_client_id")
        monkeypatch.setenv("FALCON_CLIENT_SECRET", "env_client_secret")
        
        config = FalconConfig()
        assert config.client_id == "env_client_id"
        assert config.client_secret == "env_client_secret"
        assert config.base_url == "auto"

    def test_config_explicit_overrides_env(self, monkeypatch):
        """Test that explicit credentials override environment variables"""
        monkeypatch.setenv("FALCON_CLIENT_ID", "env_client_id")
        monkeypatch.setenv("FALCON_CLIENT_SECRET", "env_client_secret")
        
        config = FalconConfig(
            client_id="explicit_client_id",
            client_secret="explicit_client_secret"
        )
        assert config.client_id == "explicit_client_id"
        assert config.client_secret == "explicit_client_secret"

    def test_config_missing_client_id(self, monkeypatch):
        """Test that missing client_id raises error"""
        monkeypatch.delenv("FALCON_CLIENT_ID", raising=False)
        monkeypatch.delenv("FALCON_CLIENT_SECRET", raising=False)
        
        with pytest.raises(FalconConfigurationError) as excinfo:
            FalconConfig(client_secret="test_secret")
        
        assert "Client IDとClient Secretが必要です" in str(excinfo.value)

    def test_config_missing_client_secret(self, monkeypatch):
        """Test that missing client_secret raises error"""
        monkeypatch.delenv("FALCON_CLIENT_ID", raising=False)
        monkeypatch.delenv("FALCON_CLIENT_SECRET", raising=False)
        
        with pytest.raises(FalconConfigurationError) as excinfo:
            FalconConfig(client_id="test_id")
        
        assert "Client IDとClient Secretが必要です" in str(excinfo.value)

    def test_config_missing_both_credentials(self, monkeypatch):
        """Test that missing both credentials raises error"""
        monkeypatch.delenv("FALCON_CLIENT_ID", raising=False)
        monkeypatch.delenv("FALCON_CLIENT_SECRET", raising=False)
        
        with pytest.raises(FalconConfigurationError) as excinfo:
            FalconConfig()
        
        assert "Client IDとClient Secretが必要です" in str(excinfo.value)

    def test_to_dict(self):
        """Test converting config to dictionary"""
        config = FalconConfig(
            client_id="test_id",
            client_secret="test_secret",
            base_url="https://api.crowdstrike.com"
        )
        
        config_dict = config.to_dict()
        assert config_dict == {
            "client_id": "test_id",
            "client_secret": "test_secret",
            "base_url": "https://api.crowdstrike.com"
        }

    def test_to_dict_with_default_base_url(self):
        """Test to_dict with default base_url"""
        config = FalconConfig(
            client_id="test_id",
            client_secret="test_secret"
        )
        
        config_dict = config.to_dict()
        assert config_dict["base_url"] == "auto"
