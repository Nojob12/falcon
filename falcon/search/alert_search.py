"""
CrowdStrike Falconアラート検索クラス
"""
from typing import Dict, List, Optional, Any
from falconpy import Alerts
from ..config import FalconConfig
from ..exceptions import (
    FalconAlertSearchError,
    FalconAPIError,
    FalconAuthenticationError
)


class FalconAlertSearch:
    """FalconPyを使用してアラート検索を行うクラス"""

    def __init__(self, config: FalconConfig):
        """
        FalconAlertSearchの初期化

        Args:
            config: Falcon認証情報を含むFalconConfigオブジェクト

        Raises:
            FalconAuthenticationError: 認証に失敗した場合
        """
        self.config = config
        try:
            self.client = Alerts(
                client_id=config.client_id,
                client_secret=config.client_secret,
                base_url=config.base_url
            )
        except Exception as e:
            raise FalconAuthenticationError(f"Falcon認証に失敗しました: {str(e)}")

    def get_alert_details(self, alert_ids: List[str]) -> List[Dict[str, Any]]:
        """
        アラートIDからアラート詳細を取得する

        Args:
            alert_ids: アラートIDのリスト

        Returns:
            アラート詳細のリスト

        Raises:
            FalconAlertSearchError: アラート検索に失敗した場合
            FalconAPIError: API呼び出しに失敗した場合
        """
        if not alert_ids:
            raise FalconAlertSearchError("アラートIDが指定されていません")

        try:
            response = self.client.post_entities_alerts_v2(
                body={
                    "composite_ids": alert_ids
                }
            )

            # ステータスコードのチェック
            if response.get("status_code") != 200:
                status_code = response.get("status_code")
                error_message = response.get("body", {}).get("errors", [])
                raise FalconAPIError(
                    f"アラート詳細の取得に失敗しました: {error_message}",
                    status_code=status_code,
                    response=response
                )

            resources = response.get("body", {}).get("resources", [])
            return resources

        except FalconAPIError:
            raise
        except Exception as e:
            raise FalconAlertSearchError(f"アラート詳細取得中にエラーが発生しました: {str(e)}")

    def get_single_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        単一のアラートIDからアラート詳細を取得する

        Args:
            alert_id: アラートID

        Returns:
            アラート詳細の辞書。見つからない場合はNone

        Raises:
            FalconAlertSearchError: アラート検索に失敗した場合
            FalconAPIError: API呼び出しに失敗した場合
        """
        alerts = self.get_alert_details([alert_id])
        return alerts[0] if alerts else None

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
            FalconAPIError: API呼び出しに失敗した場合
        """
        try:
            params = {
                "filter": filter_query,
                "limit": limit,
                "offset": offset
            }
            if sort:
                params["sort"] = sort

            response = self.client.query_alerts_v2(**params)

            # ステータスコードのチェック
            if response.get("status_code") != 200:
                status_code = response.get("status_code")
                error_message = response.get("body", {}).get("errors", [])
                raise FalconAPIError(
                    f"アラート検索に失敗しました: {error_message}",
                    status_code=status_code,
                    response=response
                )

            body = response.get("body", {})
            return {
                "alert_ids": body.get("resources", []),
                "total": body.get("meta", {}).get("pagination", {}).get("total", 0),
                "offset": body.get("meta", {}).get("pagination", {}).get("offset", 0)
            }

        except FalconAPIError:
            raise
        except Exception as e:
            raise FalconAlertSearchError(f"アラート検索中にエラーが発生しました: {str(e)}")

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
            FalconAPIError: API呼び出しに失敗した場合
        """
        # まずアラートIDを検索
        search_result = self.search_alerts_by_filter(
            filter_query=filter_query,
            limit=limit,
            offset=offset,
            sort=sort
        )

        alert_ids = search_result.get("alert_ids", [])
        if not alert_ids:
            return []

        # アラートIDから詳細を取得
        return self.get_alert_details(alert_ids)

    def close(self):
        """クライアントのクリーンアップ"""
        if hasattr(self, 'client'):
            del self.client
