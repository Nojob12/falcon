"""Main entry point for the LLMEDR CrowdStrike MCP Server"""

from .server import initialize_server, cleanup
import atexit


def main():
    """Main function to run the MCP server"""
    # Initialize the server
    mcp = initialize_server()
    
    # Register cleanup on exit
    atexit.register(cleanup)
    
    # Run the server
    mcp.run()


if __name__ == "__main__":
    main()
