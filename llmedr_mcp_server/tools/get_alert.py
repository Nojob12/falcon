"""
Get Alert Tool

MCP tool to retrieve alert information from CrowdStrike by alert ID.
"""
from typing import Optional, Dict, Any


def register_get_alert_tool(mcp, client_manager):
    """
    Register the get_alert tool with the MCP instance.
    
    Args:
        mcp: FastMCP instance
        client_manager: ClientManager instance for accessing CrowdStrike clients
    """
    
    @mcp.tool()
    async def get_alert(tenant_code: str, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve alert information from CrowdStrike by alert ID.
        
        This tool fetches detailed information about a specific alert from CrowdStrike
        for the specified tenant.
        
        Args:
            tenant_code: Tenant identifier (e.g., 'tenant1', 'tenant2')
            alert_id: CrowdStrike alert ID to retrieve
            
        Returns:
            Alert details as a dictionary, or None if not found
            
        Raises:
            ValueError: If tenant credentials are not configured
            FalconSearchError: If the API request fails
            
        Example:
            >>> result = await get_alert("tenant1", "ldt:abc123:1234567890")
            >>> print(result['severity'])
        """
        # Get the CrowdStrike client for this tenant
        client = client_manager.get_client(tenant_code)
        
        # Retrieve the alert details
        alert_details = client.get_single_alert(alert_id)
        
        return alert_details
