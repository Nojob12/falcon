"""
CrowdStrike Falcon統合検索クライアント
"""
from typing import Dict, List, Optional, Any
from .config import FalconConfig
from .search import FalconEventSearch, FalconAlertSearch
from .exceptions import FalconSearchError


class FalconSearchClient:
    """
    FalconEventSearchとFalconAlertSearchを統合して使用するクライアントクラス
    イベント検索とアラート検索を一元的に管理する
    """

    def __init__(self, config: FalconConfig = None, client_id: str = None, client_secret: str = None, base_url: str = "auto"):
        """
        FalconSearchClientの初期化
        Args:
            config: FalconConfigオブジェクト (指定しない場合は、client_idとclient_secretから生成)
            client_id: CrowdStrike Client ID (configが指定されていない場合に使用)
            client_secret: CrowdStrike Client Secret (configが指定されていない場合に使用)
            base_url: Falcon API のベースURL (デフォルト: "auto")

        Raises:
            FalconSearchError: 初期化に失敗した場合
        """
        if config is None:
            config = FalconConfig(
                client_id=client_id,
                client_secret=client_secret,
            )

        self.config = config
        self.event_search = FalconEventSearch(config)
        self.alert_search = FalconAlertSearch(config)

    # --- イベント検索関連メソッド ---

    def search_events(
        self,
        query: str,
        repository: str = "search-all",
        start: str = "15m",
        is_live: bool = False,
        interval: int = 5,
        max_retries: int = 60
    ) -> List[Dict[str, Any]]:
        """
        イベントを検索する

        Args:
            query: クエリ文字列。CrowdStrikeAPIに渡す。
            repository: CrowdStrikeの検索対象のリポジトリを決める項目。デフォルト値は"search-all"。
            start: 直近から過去どれくらいまでを検索範囲にするか決める項目。s,m,hで指定する。デフォルト値は"15m"。
            is_live: デフォルト値はFalse。不明な項目だがAPIを叩く時に指定する必要がある。
            interval: ポーリングするまでのインターバルを決める秒数。
            max_retries: 最大何回検索を試行するかを決める回数。

        Returns:
            イベントのリスト

        Raises:
            FalconEventSearchError: イベント検索に失敗した場合
        """
        return self.event_search.search_events(
            query=query,
            repository=repository,
            start=start,
            is_live=is_live,
            interval=interval,
            max_retries=max_retries
        )

    # --- アラート検索関連メソッド ---

    def get_alert_details(self, alert_ids: List[str]) -> List[Dict[str, Any]]:
        """
        アラートIDからアラート詳細を取得する

        Args:
            alert_ids: アラートIDのリスト

        Returns:
            アラート詳細のリスト

        Raises:
            FalconAlertSearchError: アラート検索に失敗した場合
        """
        return self.alert_search.get_alert_details(alert_ids)

    def get_single_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        単一のアラートIDからアラート詳細を取得する

        Args:
            alert_id: アラートID

        Returns:
            アラート詳細の辞書。見つからない場合はNone

        Raises:
            FalconAlertSearchError: アラート検索に失敗した場合
        """
        return self.alert_search.get_single_alert(alert_id)

    def search_alerts_by_filter(
        self,
        filter_query: str,
        limit: int = 100,
        offset: int = 0,
        sort: str = None
    ) -> Dict[str, Any]:
        """
        フィルタークエリでアラートを検索する

        Args:
            filter_query: FQL形式のフィルタークエリ
            limit: 取得する最大アラート数
            offset: 取得開始位置
            sort: ソート順

        Returns:
            検索結果(アラートIDのリストとメタデータ)

        Raises:
            FalconAlertSearchError: アラート検索に失敗した場合
        """
        return self.alert_search.search_alerts_by_filter(
            filter_query=filter_query,
            limit=limit,
            offset=offset,
            sort=sort
        )

    def search_and_get_alerts(
        self,
        filter_query: str,
        limit: int = 100,
        offset: int = 0,
        sort: str = None
    ) -> List[Dict[str, Any]]:
        """
        フィルタークエリでアラートを検索し、詳細を取得する

        Args:
            filter_query: FQL形式のフィルタークエリ
            limit: 取得する最大アラート数
            offset: 取得開始位置
            sort: ソート順

        Returns:
            アラート詳細のリスト

        Raises:
            FalconAlertSearchError: アラート検索に失敗した場合
        """
        return self.alert_search.search_and_get_alerts(
            filter_query=filter_query,
            limit=limit,
            offset=offset,
            sort=sort
        )

    # --- クリーンアップ ---

    def close(self):
        """
        すべてのクライアントをクリーンアップする
        """
        self.event_search.close()
        self.alert_search.close()

    def __enter__(self):
        """コンテキストマネージャーのエントリ"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """コンテキストマネージャーの終了"""
        self.close()
