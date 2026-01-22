"""
CrowdStrike Falconイベント検索クラス
"""
import time
from typing import Dict, List, Optional, Any
from falconpy import NGSIEM
from ..config import FalconConfig
from ..exceptions import (
    FalconEventSearchError,
    FalconAPIError,
    FalconAuthenticationError,
    FalconResourceNotFoundError
)


class FalconEventSearch:
    """FalconPyを使用してイベント検索を行うクラス"""

    def __init__(self, config: FalconConfig):
        """
        FalconEventSearchの初期化

        Args:
            config: Falcon認証情報を含むFalconConfigオブジェクト

        Raises:
            FalconAuthenticationError: 認証に失敗した場合
        """
        self.config = config
        try:
            self.client = NGSIEM(
                client_id=config.client_id,
                client_secret=config.client_secret,
                base_url=config.base_url
            )
        except Exception as e:
            raise FalconAuthenticationError(f"Falcon認証に失敗しました: {str(e)}")

    def search_events(
        self,
        query: str,
        start_time: str,
        end_time: str,
        limit: int = 10000,
        poll_interval: int = 5,
        max_wait_time: int = 300
    ) -> List[Dict[str, Any]]:
        """
        イベントを検索する

        Args:
            query: 検索クエリ (例: "event_simpleName='ProcessRollup2'")
            start_time: 検索開始時刻 (ISO8601形式またはエポック秒)
            end_time: 検索終了時刻 (ISO8601形式またはエポック秒)
            limit: 取得する最大イベント数
            poll_interval: ポーリング間隔(秒)
            max_wait_time: 最大待機時間(秒)

        Returns:
            イベントのリスト

        Raises:
            FalconEventSearchError: イベント検索に失敗した場合
            FalconAPIError: API呼び出しに失敗した場合
        """
        # 検索を開始
        search_id = self._start_search(query, start_time, end_time, limit)

        # 検索結果を取得
        events = self._get_search_results(search_id, poll_interval, max_wait_time)

        return events

    def _start_search(
        self,
        query: str,
        start_time: str,
        end_time: str,
        limit: int
    ) -> str:
        """
        検索を開始する

        Args:
            query: 検索クエリ
            start_time: 検索開始時刻
            end_time: 検索終了時刻
            limit: 取得する最大イベント数

        Returns:
            検索ID

        Raises:
            FalconEventSearchError: 検索開始に失敗した場合
            FalconAPIError: API呼び出しに失敗した場合
            FalconResourceNotFoundError: リソースキーが見つからない場合
        """
        try:
            response = self.client.start_search_v1(
                filter=query,
                start=start_time,
                end=end_time,
                limit=limit
            )

            # ステータスコードのチェック
            if response.get("status_code") != 200:
                status_code = response.get("status_code")
                error_message = response.get("body", {}).get("errors", [])
                raise FalconAPIError(
                    f"イベント検索の開始に失敗しました: {error_message}",
                    status_code=status_code,
                    response=response
                )

            # resourcesキーの存在チェック
            if "resources" not in response.get("body", {}):
                raise FalconResourceNotFoundError(
                    "レスポンスに'resources'キーが含まれていません"
                )

            resources = response["body"]["resources"]
            if not resources or len(resources) == 0:
                raise FalconResourceNotFoundError(
                    "検索IDが取得できませんでした"
                )

            search_id = resources[0]
            return search_id

        except (FalconAPIError, FalconResourceNotFoundError):
            raise
        except Exception as e:
            raise FalconEventSearchError(f"検索開始中にエラーが発生しました: {str(e)}")

    def _get_search_results(
        self,
        search_id: str,
        poll_interval: int,
        max_wait_time: int
    ) -> List[Dict[str, Any]]:
        """
        検索結果を取得する

        Args:
            search_id: 検索ID
            poll_interval: ポーリング間隔(秒)
            max_wait_time: 最大待機時間(秒)

        Returns:
            イベントのリスト

        Raises:
            FalconEventSearchError: 検索結果の取得に失敗した場合
            FalconAPIError: API呼び出しに失敗した場合
        """
        elapsed_time = 0
        events = []

        try:
            while elapsed_time < max_wait_time:
                response = self.client.get_search_status_v1(ids=search_id)

                # ステータスコードのチェック
                if response.get("status_code") != 200:
                    status_code = response.get("status_code")
                    error_message = response.get("body", {}).get("errors", [])
                    raise FalconAPIError(
                        f"検索ステータスの取得に失敗しました: {error_message}",
                        status_code=status_code,
                        response=response
                    )

                resources = response.get("body", {}).get("resources", [])
                if not resources:
                    time.sleep(poll_interval)
                    elapsed_time += poll_interval
                    continue

                search_status = resources[0]
                status = search_status.get("status")

                if status == "DONE":
                    # 検索完了
                    events = search_status.get("results", [])
                    break
                elif status == "ERROR":
                    error_msg = search_status.get("error_message", "不明なエラー")
                    raise FalconEventSearchError(f"検索がエラーで終了しました: {error_msg}")
                elif status in ["RUNNING", "PENDING"]:
                    # まだ実行中
                    time.sleep(poll_interval)
                    elapsed_time += poll_interval
                else:
                    raise FalconEventSearchError(f"不明なステータス: {status}")

            if elapsed_time >= max_wait_time:
                raise FalconEventSearchError(
                    f"検索がタイムアウトしました({max_wait_time}秒)"
                )

            return events

        except (FalconAPIError, FalconEventSearchError):
            raise
        except Exception as e:
            raise FalconEventSearchError(f"検索結果取得中にエラーが発生しました: {str(e)}")

    def close(self):
        """クライアントのクリーンアップ"""
        if hasattr(self, 'client'):
            del self.client
