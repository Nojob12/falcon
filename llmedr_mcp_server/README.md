# LLMEDR CrowdStrike MCP Server

A Model Context Protocol (MCP) server for automated CrowdStrike alert analysis with multi-tenant support.

## Features

- **Multi-tenant Support**: Manage separate CrowdStrike API clients for each tenant
- **Automatic Client Management**: Client instances are created on-demand and reused
- **Async Tools**: All tools are async for efficient API communication
- **Alert Analysis**: Retrieve and analyze CrowdStrike alerts and events

## Architecture

```
llmedr_mcp_server/
├── __init__.py              # Package initialization
├── main.py                  # Entry point
├── server.py                # MCP instance and initialization
├── client_manager.py        # Tenant-based CrowdStrike client manager
├── requirements.txt         # Dependencies
├── .env.example             # Environment configuration template
├── tools/                   # MCP tool implementations
│   ├── __init__.py
│   ├── get_alert.py         # Get alert by ID
│   └── get_file_hash_by_filename.py  # Query events for file hashes
└── README.md                # This file
```

## Installation

1. Install dependencies:
```bash
cd /Users/nojob/WorkSpace/falcon
pip install -r llmedr_mcp_server/requirements.txt
```

2. Configure tenant credentials:
```bash
cp llmedr_mcp_server/.env.example llmedr_mcp_server/.env
# Edit .env and add your tenant credentials
```

## Configuration

Each tenant requires two environment variables:

- `FALCON_CLIENT_ID_<TENANT_CODE>`: CrowdStrike Client ID
- `FALCON_CLIENT_SECRET_<TENANT_CODE>`: CrowdStrike Client Secret

**Example:**
```bash
# Tenant: tenant1
export FALCON_CLIENT_ID_TENANT1="abc123..."
export FALCON_CLIENT_SECRET_TENANT1="xyz789..."

# Tenant: tenant2
export FALCON_CLIENT_ID_TENANT2="def456..."
export FALCON_CLIENT_SECRET_TENANT2="uvw012..."
```

## Usage

Run the MCP server:

```bash
python -m llmedr_mcp_server.main
```

## Available Tools

### 1. get_alert

Retrieve alert information from CrowdStrike by alert ID.

**Parameters:**
- `tenant_code` (str): Tenant identifier (e.g., 'tenant1')
- `alert_id` (str): CrowdStrike alert ID

**Returns:** Alert details dictionary or None if not found

**Example:**
```python
result = await get_alert("tenant1", "ldt:abc123:1234567890")
```

### 2. get_file_hash_by_filename

Query CrowdStrike for events containing file hashes by filename.

**Parameters:**
- `tenant_code` (str): Tenant identifier
- `filename` (str): Filename to search for
- `start_time` (str): Search start time (ISO8601 or epoch seconds)
- `end_time` (str): Search end time (ISO8601 or epoch seconds)
- `limit` (int, optional): Max events to return (default: 100)

**Returns:** List of events containing file hash information

**Example:**
```python
events = await get_file_hash_by_filename(
    "tenant1",
    "malware.exe",
    "2024-01-01T00:00:00Z",
    "2024-01-31T23:59:59Z"
)
```

## Client Management

The `ClientManager` automatically:
1. Creates CrowdStrike client instances when first requested for a tenant
2. Reuses existing client instances for subsequent requests
3. Manages client lifecycle and cleanup

When an LLM sends a request with a `tenant_code`, the server:
- Checks if a client exists for that tenant
- Creates a new client if needed (using environment variables)
- Returns the client instance to the tool for API calls

## Project Structure

### server.py
Contains the FastMCP instance and tool registration. When the MCP server receives a request, tools use the `client_manager` to get appropriate CrowdStrike clients.

### client_manager.py
Manages CrowdStrike API client instances per tenant. Responsible for:
- Creating new clients on-demand
- Maintaining client registry
- Handling client cleanup

### tools/
Each tool is in its own file:
- **get_alert.py**: Retrieves alert details by ID
- **get_file_hash_by_filename.py**: Queries events for file hashes

All tools are async functions that:
1. Receive `tenant_code` as first parameter
2. Get CrowdStrike client from `client_manager`
3. Execute API calls
4. Return results

## Development

To add new tools:

1. Create a new file in `tools/` (e.g., `tools/my_tool.py`)
2. Define an async registration function:

```python
def register_my_tool(mcp, client_manager):
    @mcp.tool()
    async def my_tool(tenant_code: str, param: str) -> dict:
        """Tool description"""
        client = client_manager.get_client(tenant_code)
        # Use client to call CrowdStrike API
        return result
```

3. Import and register in `server.py`:

```python
from .tools.my_tool import register_my_tool

def initialize_server():
    register_get_alert_tool(mcp, client_manager)
    register_get_file_hash_tool(mcp, client_manager)
    register_my_tool(mcp, client_manager)  # Add this
    return mcp
```

## License

See the main falcon project for license information.
