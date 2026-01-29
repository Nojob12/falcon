"""
Get File Hash by Filename Tool

MCP tool to query CrowdStrike for file hashes by filename.
"""
from typing import List, Dict, Any


def register_get_file_hash_tool(mcp, client_manager):
    """
    Register the get_file_hash_by_filename tool with the MCP instance.
    
    Args:
        mcp: FastMCP instance
        client_manager: ClientManager instance for accessing CrowdStrike clients
    """
    
    @mcp.tool()
    async def get_file_hash_by_filename(
        tenant_code: str,
        filename: str,
        start_time: str,
        end_time: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Query CrowdStrike for events containing file hashes by filename.
        
        This tool searches for file execution events matching the specified filename
        and returns associated file hash information.
        
        Args:
            tenant_code: Tenant identifier (e.g., 'tenant1', 'tenant2')
            filename: Filename to search for (e.g., 'malware.exe')
            start_time: Search start time in ISO8601 format or epoch seconds
            end_time: Search end time in ISO8601 format or epoch seconds
            limit: Maximum number of events to return (default: 100)
            
        Returns:
            List of events containing file hash information
            
        Raises:
            ValueError: If tenant credentials are not configured
            FalconEventSearchError: If the API request fails
            
        Example:
            >>> events = await get_file_hash_by_filename(
            ...     "tenant1",
            ...     "suspicious.exe",
            ...     "2024-01-01T00:00:00Z",
            ...     "2024-01-31T23:59:59Z"
            ... )
            >>> for event in events:
            ...     print(event.get('SHA256HashData'))
        """
        # Get the CrowdStrike client for this tenant
        client = client_manager.get_client(tenant_code)
        
        # Build the query to search for the filename
        # Using ProcessRollup2 events which contain file execution information
        query = f"event_simpleName='ProcessRollup2' AND FileName='{filename}'"
        
        # Search for events
        events = client.search_events(
            query=query,
            start_time=start_time,
            end_time=end_time,
            limit=limit
        )
        
        return events
