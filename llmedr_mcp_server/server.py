"""
MCP Server instance and configuration

This module initializes the FastMCP server and registers all tools
with the client manager for tenant-based CrowdStrike API access.
"""
from fastmcp import FastMCP
from .client_manager import ClientManager
from .tools.get_alert import register_get_alert_tool
from .tools.get_file_hash_by_filename import register_get_file_hash_tool


# Create the MCP instance
mcp = FastMCP("LLMEDR CrowdStrike MCP Server")

# Create the client manager for tenant-based client instances
client_manager = ClientManager()


def initialize_server():
    """
    Initialize the MCP server by registering all tools.
    
    Returns:
        Initialized FastMCP instance
    """
    # Register all tools with the client manager
    register_get_alert_tool(mcp, client_manager)
    register_get_file_hash_tool(mcp, client_manager)
    
    return mcp


def cleanup():
    """
    Cleanup function to close all client connections.
    Should be called on server shutdown.
    """
    client_manager.close_all()
