"""
CrowdStrike Falcon Alert Investigation Module

アラートに関する調査機能を提供
"""
from typing import Dict, Any, Optional
import sys
sys.path.insert(0, '/Users/nojob/WorkSpace/falcon')

from .base import InvestigationBase


class AlertInvestigation(InvestigationBase):
    """アラート関連の調査クラス"""

    async def get_alert_details(
        self,
        alert_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        単一のアラートIDからアラート詳細情報を取得

        Args:
            alert_id: アラートID

        Returns:
            アラート詳細情報の辞書。見つからない場合はNone

        Raises:
            FalconAlertSearchError: アラート検索に失敗した場合

        使用例:
            alert_inv = AlertInvestigation(client)
            alert_details = await alert_inv.get_alert_details("alert_id_12345")
            if alert_details:
                print(f"アラート: {alert_details.get('alert_id')}")
                print(f"重要度: {alert_details.get('severity')}")
                print(f"ステータス: {alert_details.get('status')}")
        """
        # FalconSearchClientのget_single_alertメソッドを使用
        # 注意: get_single_alertは同期関数なので、将来的に非同期化が必要
        alert_details = self.client.get_single_alert(alert_id)

        return alert_details
