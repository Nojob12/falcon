from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from mcp.server.fastmcp import FastMCP

class ToolBase(ABC):
    @abstractmethod
    def register(self, mcp: FastMCP, client_manager: Any):
        pass
