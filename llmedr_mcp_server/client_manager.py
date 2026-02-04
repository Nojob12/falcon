"""
CrowdStrike Client Manager

Manages CrowdStrike API client instances per customer.
Creates clients on-demand and maintains them for reuse.
"""
import os
from typing import Dict, Optional
from falcon.client import FalconSearchClient
from falcon.config import FalconConfig


class ClientManager:
    """
    Manages CrowdStrike API client instances for multiple customers.
    
    Each customer has its own client instance that is created on-demand
    and reused for subsequent requests.
    """
    
    def __init__(self):
        """Initialize the client manager with an empty client registry"""
        self._clients: Dict[str, FalconSearchClient] = {}
    
    def get_client(self, customer_code: str) -> FalconSearchClient:
        """
        Get or create a CrowdStrike client for the specified customer.
        
        Args:
            customer_code: Unique identifier for the customer
            
        Returns:
            FalconSearchClient instance for the customer
            
        Raises:
            ValueError: If customer credentials are not configured
        """
        # Return existing client if available
        if customer_code in self._clients:
            return self._clients[customer_code]
        
        # Create new client for this customer
        client = self._create_client(customer_code)
        self._clients[customer_code] = client
        
        return client
    
    def _create_client(self, customer_code: str) -> FalconSearchClient:
        """
        Create a new CrowdStrike client instance for a customer.
        
        Args:
            customer_code: Unique identifier for the customer
            
        Returns:
            New FalconSearchClient instance
            
        Raises:
            ValueError: If customer credentials are not found in environment
        """
        # Get credentials from environment variables
        # Format: FALCON_CLIENT_ID_<CUSTOMER_CODE> and FALCON_CLIENT_SECRET_<CUSTOMER_CODE>
        client_id_key = f"FALCON_CLIENT_ID_{customer_code.upper()}"
        client_secret_key = f"FALCON_CLIENT_SECRET_{customer_code.upper()}"
        
        client_id = os.getenv(client_id_key)
        client_secret = os.getenv(client_secret_key)
        
        if not client_id or not client_secret:
            raise ValueError(
                f"Credentials not found for customer '{customer_code}'. "
                f"Please set environment variables: {client_id_key} and {client_secret_key}"
            )
        
        # Create and return the client
        config = FalconConfig(
            client_id=client_id,
            client_secret=client_secret
        )
        
        return FalconSearchClient(config=config)
    
    def remove_client(self, customer_code: str) -> bool:
        """
        Remove a client instance for a customer.
        
        Args:
            customer_code: Unique identifier for the customer
            
        Returns:
            True if client was removed, False if it didn't exist
        """
        if customer_code in self._clients:
            # Close the client before removing
            self._clients[customer_code].close()
            del self._clients[customer_code]
            return True
        return False
    
    def close_all(self):
        """Close all client instances and clear the registry"""
        for client in self._clients.values():
            client.close()
        self._clients.clear()
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close all clients"""
        self.close_all()
