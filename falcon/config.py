"""
CrowdStrike Falcon認証情報の設定
"""
import os
from typing import Dict
from .exceptions import FalconConfigurationError


class FalconConfig:
    """Falcon API認証情報を管理するクラス"""

    def __init__(self, client_id: str = None, client_secret: str = None, base_url: str = "auto"):
        """
        認証情報の初期化

        Args:
            client_id: CrowdStrike Client ID (指定がない場合は環境変数FALCON_CLIENT_IDを使用)
            client_secret: CrowdStrike Client Secret (指定がない場合は環境変数FALCON_CLIENT_SECRETを使用)
            base_url: Falcon API のベースURL (デフォルト: "auto")

        Raises:
            FalconConfigurationError: 認証情報が不足している場合
        """
        self.client_id = client_id or os.getenv("FALCON_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("FALCON_CLIENT_SECRET")

        if not self.client_id or not self.client_secret:
            raise FalconConfigurationError(
                "Client IDとClient Secretが必要です。"
                "引数または環境変数(FALCON_CLIENT_ID, FALCON_CLIENT_SECRET)で設定してください。"
            )

    def to_dict(self) -> Dict[str, str]:
        """
        認証情報を辞書形式で返す

        Returns:
            認証情報の辞書
        """
        return {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
