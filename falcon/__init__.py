"""
CrowdStrike Falcon検索ライブラリ

イベント検索とアラート検索を簡単に行うためのライブラリ
"""

from .client import FalconSearchClient
from .search import FalconEventSearch, FalconAlertSearch
from .config import FalconConfig
from .exceptions import (
    FalconSearchError,
    FalconAPIError,
    FalconAuthenticationError,
    FalconConfigurationError,
    FalconEventSearchError,
    FalconAlertSearchError,
    FalconResourceNotFoundError
)

__version__ = "1.0.0"

__all__ = [
    # Main client
    "FalconSearchClient",

    # Search classes
    "FalconEventSearch",
    "FalconAlertSearch",

    # Configuration
    "FalconConfig",

    # Exceptions
    "FalconSearchError",
    "FalconAPIError",
    "FalconAuthenticationError",
    "FalconConfigurationError",
    "FalconEventSearchError",
    "FalconAlertSearchError",
    "FalconResourceNotFoundError",
]
