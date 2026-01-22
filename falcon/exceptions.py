"""
CrowdStrike Falcon検索ライブラリのカスタム例外クラス
"""


class FalconSearchError(Exception):
    """Falcon検索の基底例外クラス"""
    pass


class FalconAPIError(FalconSearchError):
    """FalconAPIの呼び出しエラー"""
    def __init__(self, message: str, status_code: int = None, response: dict = None):
        self.status_code = status_code
        self.response = response
        super().__init__(message)


class FalconAuthenticationError(FalconSearchError):
    """Falcon認証エラー"""
    pass


class FalconConfigurationError(FalconSearchError):
    """Falcon設定エラー"""
    pass


class FalconEventSearchError(FalconSearchError):
    """イベント検索エラー"""
    pass


class FalconAlertSearchError(FalconSearchError):
    """アラート検索エラー"""
    pass


class FalconResourceNotFoundError(FalconSearchError):
    """リソースが見つからないエラー"""
    pass
