"""
CrowdStrike Falcon Investigation Base Module

すべての調査クラスの基底クラスと共通機能
"""
from typing import Dict, List, Any, Optional
from abc import ABC
import sys
sys.path.insert(0, '/Users/nojob/WorkSpace/falcon')

from falcon import FalconSearchClient
from falcon.query import Query


class InvestigationBase(ABC):
    """調査機能の基底クラス"""

    def __init__(self, client: FalconSearchClient, host_aid: Optional[str] = None):
        """
        調査基底クラスの初期化

        Args:
            client: FalconSearchClientインスタンス
            host_aid: 調査対象ホストID（Noneの場合は全ホスト）
        """
        self.client = client
        self.default_host_aid = host_aid

    async def execute_query(
        self,
        query: Query,
        repository: str = "search-all",
        start: str = "15m",
        is_live: bool = False,
        interval: int = 5,
        max_retries: int = 60
    ) -> List[Dict[str, Any]]:
        """
        クエリを実行して結果を取得

        Args:
            query: Queryオブジェクト
            repository: 検索対象のリポジトリ
            start: 検索範囲（例: "15m", "1h", "24h"）
            is_live: ライブ検索フラグ
            interval: ポーリング間隔（秒）
            max_retries: 最大試行回数

        Returns:
            検索結果のリスト
        """
        query_str = str(query)

        # async APIを想定した実装（現在のclientは同期的だが、将来的に非同期化を想定）
        results = self.client.search_events(
            query=query_str,
            repository=repository,
            start=start,
            is_live=is_live,
            interval=interval,
            max_retries=max_retries
        )

        return results

    def set_host(self, host_aid: str) -> None:
        """
        調査対象ホストを設定

        Args:
            host_aid: ホストID
        """
        self.default_host_aid = host_aid

    def get_host(self, host_aid: Optional[str] = None) -> Optional[str]:
        """
        使用するホストIDを取得

        Args:
            host_aid: 指定されたホストID

        Returns:
            使用するホストID（指定がない場合はdefault_host_aid）
        """
        return host_aid if host_aid is not None else self.default_host_aid
