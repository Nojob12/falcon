"""
CrowdStrike Falcon検索モジュール

イベント検索とアラート検索を行うクラスを提供
"""

from .event import FalconEventSearch
from .alert import FalconAlertSearch

__all__ = [
    "FalconEventSearch",
    "FalconAlertSearch",
]
