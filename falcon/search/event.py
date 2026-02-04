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
            FalconAPIError: API呼び出しに失敗した場合
        """
        # 検索を開始
        search_id = self._start_search(query, repository, start, is_live)

        # 検索結果を取得
        events = self._get_search_results(search_id, interval, max_retries)

        return events

    def _start_search(
        self,
        query: str,
        repository: str,
        start: str,
        is_live: bool
    ) -> str:
        """
        検索を開始する

        Args:
            query: 検索クエリ
            repository: 検索対象のリポジトリ
            start: 検索範囲（例: "15m", "1h"）
            is_live: ライブ検索フラグ

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
                repo_or_view=repository,
                start=start,
                is_live=is_live
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
        interval: int,
        max_retries: int
    ) -> List[Dict[str, Any]]:
        """
        検索結果を取得する

        Args:
            search_id: 検索ID
            interval: ポーリング間隔(秒)
            max_retries: 最大試行回数

        Returns:
            イベントのリスト

        Raises:
            FalconEventSearchError: 検索結果の取得に失敗した場合
            FalconAPIError: API呼び出しに失敗した場合
        """
        retry_count = 0
        events = []

        try:
            while retry_count < max_retries:
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
                    time.sleep(interval)
                    retry_count += 1
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
                    time.sleep(interval)
                    retry_count += 1
                else:
                    raise FalconEventSearchError(f"不明なステータス: {status}")

            if retry_count >= max_retries:
                raise FalconEventSearchError(
                    f"検索がタイムアウトしました({max_retries}回の試行)"
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
