"""
CrowdStrike Falcon Investigation Module

CrowdStrike Falconを使った各種調査機能を提供するモジュール

使用例:
    from falcon import FalconSearchClient
    from llmedr_mcp_server.investigator.crowdstrike import (
        FileInvestigation,
        ProcessInvestigation,
        AlertInvestigation
    )

    # クライアント初期化
    client = FalconSearchClient(
        client_id="your_client_id",
        client_secret="your_client_secret"
    )

    # ファイル調査
    file_inv = FileInvestigation(client)

    # 特定ホストでの検索
    results = await file_inv.get_hash_by_filename("malware.exe", aid="2e5445246a35d55", exclude=False)

    # 他ホストでの検索（特定ホストを除外）
    results = await file_inv.get_hash_by_filename("malware.exe", aid="2e5445246a35d55", exclude=True)

    # 全ホストでの検索
    results = await file_inv.get_hash_by_filename("malware.exe")

    # プロセス調査
    proc_inv = ProcessInvestigation(client)

    # ホストIDは必須
    results = await proc_inv.get_process_startup_by_pid("40612979432", aid="2e5445246a35d55")

    # アラート調査
    alert_inv = AlertInvestigation(client)

    # アラート詳細を取得
    alert_details = await alert_inv.get_alert_details("alert_id_12345")
"""

from .base import InvestigationBase
from .file import FileInvestigation
from .process import ProcessInvestigation
from .network import NetworkInvestigation
from .alert import AlertInvestigation

__all__ = [
    "InvestigationBase",
    "FileInvestigation",
    "ProcessInvestigation",
    "NetworkInvestigation",
    "AlertInvestigation",
]

__version__ = "1.0.0"
