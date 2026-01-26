"""
Tests for FalconConfig class
"""
import pytest
import os
from falcon.config import FalconConfig
from falcon.exceptions import FalconConfigurationError


class TestFalconConfig:
    """Test FalconConfig initialization and methods"""

    def test_init_with_parameters(self, valid_credentials):
        """Test initialization with explicit parameters"""
        config = FalconConfig(
            client_id=valid_credentials["client_id"],
            client_secret=valid_credentials["client_secret"]
        )
        assert config.client_id == valid_credentials["client_id"]
        assert config.client_secret == valid_credentials["client_secret"]

    def test_init_with_env_variables(self, monkeypatch, valid_credentials):
        """Test initialization with environment variables"""
        monkeypatch.setenv("FALCON_CLIENT_ID", valid_credentials["client_id"])
        monkeypatch.setenv("FALCON_CLIENT_SECRET", valid_credentials["client_secret"])
        
        config = FalconConfig()
        assert config.client_id == valid_credentials["client_id"]
        assert config.client_secret == valid_credentials["client_secret"]

    def test_init_missing_client_id(self, monkeypatch):
        """Test that initialization fails when client_id is missing"""
        monkeypatch.delenv("FALCON_CLIENT_ID", raising=False)
        monkeypatch.delenv("FALCON_CLIENT_SECRET", raising=False)
        
        with pytest.raises(FalconConfigurationError) as exc_info:
            FalconConfig(client_secret="test_secret")
        
        assert "Client IDとClient Secretが必要です" in str(exc_info.value)

    def test_init_missing_client_secret(self, monkeypatch):
        """Test that initialization fails when client_secret is missing"""
        monkeypatch.delenv("FALCON_CLIENT_ID", raising=False)
        monkeypatch.delenv("FALCON_CLIENT_SECRET", raising=False)
        
        with pytest.raises(FalconConfigurationError) as exc_info:
            FalconConfig(client_id="test_id")
        
        assert "Client IDとClient Secretが必要です" in str(exc_info.value)

    def test_init_missing_both_credentials(self, monkeypatch):
        """Test that initialization fails when both credentials are missing"""
        monkeypatch.delenv("FALCON_CLIENT_ID", raising=False)
        monkeypatch.delenv("FALCON_CLIENT_SECRET", raising=False)
        
        with pytest.raises(FalconConfigurationError):
            FalconConfig()

    def test_to_dict(self, valid_credentials):
        """Test to_dict method returns correct dictionary"""
        config = FalconConfig(
            client_id=valid_credentials["client_id"],
            client_secret=valid_credentials["client_secret"]
        )
        
        config_dict = config.to_dict()
        assert config_dict["client_id"] == valid_credentials["client_id"]
        assert config_dict["client_secret"] == valid_credentials["client_secret"]

    def test_parameter_priority_over_env(self, monkeypatch):
        """Test that explicit parameters take priority over environment variables"""
        monkeypatch.setenv("FALCON_CLIENT_ID", "env_id")
        monkeypatch.setenv("FALCON_CLIENT_SECRET", "env_secret")
        
        config = FalconConfig(client_id="param_id", client_secret="param_secret")
        assert config.client_id == "param_id"
        assert config.client_secret == "param_secret"
