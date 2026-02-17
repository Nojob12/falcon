"""
CrowdStrike Falcon Process Investigation Module

プロセスに関する調査機能を提供
"""
from typing import Dict, List, Any
import sys
sys.path.insert(0, '/Users/nojob/WorkSpace/falcon')

from falcon.query import Query
from .base import InvestigationBase


class ProcessInvestigation(InvestigationBase):
    """プロセス関連の調査クラス"""

    # ========================================
    # コマンドライン関連
    # ========================================

    async def get_process_with_filename_in_cmdline(
        self,
        filename: str,
        aid: str,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        ファイル名から、そのファイルがコマンドラインに入るプロセスを検索

        Args:
            filename: 検索対象のファイル名
            aid: ホストID（必須）
            **search_params: 検索パラメータ（repository, start, is_live, interval, max_retries）

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #7
        """
        query = Query()
        query.add("aid", aid)
        query.contain("#event_simpleName", "ProcessRollup2")
        query.contain("CommandLine", filename)
        query.select([
            "timestamp", "aid", "FilePath", "FileName", "TargetProcessId",
            "CommandLine", "ParentBaseFileName", "ParentProcessId"
        ])

        return await self.execute_query(query, **search_params)

    # ========================================
    # 親子関係関連
    # ========================================

    async def get_child_processes_by_parent_name(
        self,
        parent_name: str,
        aid: str,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        親プロセス名から実行されているプロセスの一覧を取得

        Args:
            parent_name: 親プロセスのベースファイル名（例: "explorer.exe"）
            aid: ホストID（必須）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #10
        """
        query = Query()
        query.add("aid", aid)
        query.contain("#event_simpleName", "ProcessRollup2")
        query.add("ParentBaseFileName", parent_name)
        query.select([
            "timestamp", "aid", "FilePath", "FileName", "TargetProcessId",
            "CommandLine", "ParentBaseFileName", "ParentProcessId"
        ])

        return await self.execute_query(query, **search_params)

    # ========================================
    # プロセスID関連
    # ========================================

    async def get_process_startup_by_pid(
        self,
        process_id: str,
        aid: str,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        プロセスIDから、プロセスの起動ログを検索

        Args:
            process_id: ターゲットプロセスID
            aid: ホストID（必須）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #14
        """
        query = Query()
        query.add("aid", aid)
        query.add("TargetProcessId", process_id)
        query.select([
            "timestamp", "aid", "FilePath", "FileName", "TargetProcessId",
            "CommandLine", "ParentBaseFileName", "ParentProcessId"
        ])

        return await self.execute_query(query, **search_params)

    async def get_process_details_by_pid(
        self,
        process_id: str,
        aid: str,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        プロセスIDからプロセス内容を取得

        Args:
            process_id: ターゲットプロセスID
            aid: ホストID（必須）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト

        使用例:
            proc_inv = ProcessInvestigation(client)
            details = await proc_inv.get_process_details_by_pid(
                "40612979432",
                aid="2e5445246a35d55"
            )
            for process in details:
                print(f"プロセス名: {process.get('FileName')}")
                print(f"コマンドライン: {process.get('CommandLine')}")
                print(f"親プロセス: {process.get('ParentBaseFileName')}")
        """
        query = Query()
        query.add("aid", aid)
        query.add("TargetProcessId", process_id)
        query.contain("#event_simpleName", "ProcessRollup2")
        query.rename("TargetProcessId", "ProcessId")
        query.rename("FileName", "ProcessName")
        query.rename("FilePath", "ProcessPath")
        query.rename("ParentBaseFileName", "ParentProcessName")
        query.select([
            "timestamp", "aid", "FilePath", "FileName", "TargetProcessId",
            "CommandLine", "ParentBaseFileName", "ParentProcessId"
        ])

        return await self.execute_query(query, **search_params)

    # ========================================
    # プロセスID起点の調査関連
    # ========================================

    async def get_child_processes_by_pid(
        self,
        process_id: str,
        aid: str,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        プロセスIDから、そのプロセスが生成した子プロセス一覧を検索

        Args:
            process_id: 親プロセスID
            aid: ホストID（必須）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト
        """
        query = Query()
        query.add("aid", aid)
        query.add("ParentProcessId", process_id)
        query.contain("#event_simpleName", "ProcessRollup2")
        query.select([
            "timestamp", "aid", "FilePath", "FileName",
            "TargetProcessId", "CommandLine", "SHA256HashData"
        ])

        return await self.execute_query(query, **search_params)

    async def get_dns_requests_by_pid(
        self,
        process_id: str,
        aid: str,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        プロセスIDから、そのプロセスが行った名前解決一覧を検索

        Args:
            process_id: ターゲットプロセスID
            aid: ホストID（必須）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト
        """
        query = Query()
        query.add("aid", aid)
        query.add("ContextProcessId", process_id)
        query.add("#event_simpleName", "DnsRequest")
        query.select([
            "timestamp", "aid", "DomainName", "IP4Records", "IP6Records"
        ])

        return await self.execute_query(query, **search_params)

    async def get_network_connections_by_pid(
        self,
        process_id: str,
        aid: str,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        プロセスIDから、そのプロセスが行った通信先を検索

        Args:
            process_id: ターゲットプロセスID
            aid: ホストID（必須）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト
        """
        query = Query()
        query.add("aid", aid)
        query.add("ContextProcessId", process_id)
        query.contain("#event_simpleName", "Network")
        query.select([
            "timestamp", "aid", "DomainName", "LocalIP", "LPort", "RemoteIP", "RPort"
        ])

        return await self.execute_query(query, **search_params)

    async def get_created_files_by_pid(
        self,
        process_id: str,
        aid: str,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        プロセスIDから、そのプロセスが作成したファイルを検索

        Args:
            process_id: ターゲットプロセスID
            aid: ホストID（必須）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト
        """
        query = Query()
        query.add("aid", aid)
        query.add("ContextProcessId", process_id)

        # #event_simpleNameに「Written」を含むもしくは「FileCreateInfo」と一致
        sub_query = Query(operator="OR")
        sub_query.contain("#event_simpleName", "Written")
        sub_query.add("#event_simpleName", "FileCreateInfo")
        query.add_subquery(sub_query)

        query.select([
            "timestamp", "aid", "#event_simpleName",
            "FileName", "FilePath", "SHA256HashData"
        ])

        return await self.execute_query(query, **search_params)

    async def get_deleted_files_by_pid(
        self,
        process_id: str,
        aid: str,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        プロセスIDから、そのプロセスが削除したファイルを検索

        Args:
            process_id: ターゲットプロセスID
            aid: ホストID（必須）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト
        """
        query = Query()
        query.add("aid", aid)
        query.add("ContextProcessId", process_id)

        # #event_simpleNameに「Deleted」を含むもしくは「FileDeleteInfo」と一致
        sub_query = Query(operator="OR")
        sub_query.contain("#event_simpleName", "Deleted")
        sub_query.add("#event_simpleName", "FileDeleteInfo")
        query.add_subquery(sub_query)

        query.select([
            "timestamp", "aid", "#event_simpleName",
            "FileName", "FilePath", "SHA256HashData"
        ])

        return await self.execute_query(query, **search_params)

    async def get_opened_files_by_pid(
        self,
        process_id: str,
        aid: str,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        プロセスIDから、そのプロセスがオープンしたファイルを検索

        Args:
            process_id: ターゲットプロセスID
            aid: ホストID（必須）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト
        """
        query = Query()
        query.add("aid", aid)
        query.add("ContextProcessId", process_id)
        query.add("#event_simpleName", "FileOpenInfo")
        query.select([
            "timestamp", "aid", "#event_simpleName",
            "FileName", "FilePath", "SHA256HashData"
        ])

        return await self.execute_query(query, **search_params)

    async def get_renamed_files_by_pid(
        self,
        process_id: str,
        aid: str,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        プロセスIDから、そのプロセスが名前変更したファイルを検索

        Args:
            process_id: ターゲットプロセスID
            aid: ホストID（必須）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト
        """
        query = Query()
        query.add("aid", aid)
        query.add("ContextProcessId", process_id)
        query.contain("#event_simpleName", "Rename")
        query.select([
            "timestamp", "aid", "#event_simpleName",
            "FileName", "FilePath", "SourceFileName", "SHA256HashData"
        ])

        return await self.execute_query(query, **search_params)

    async def get_created_directories_by_pid(
        self,
        process_id: str,
        aid: str,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        プロセスIDから、そのプロセスが作成したディレクトリを検索

        Args:
            process_id: ターゲットプロセスID
            aid: ホストID（必須）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト
        """
        query = Query()
        query.add("aid", aid)
        query.add("ContextProcessId", process_id)
        query.add("#event_simpleName", "DirectoryCreate")
        query.select([
            "timestamp", "aid", "#event_simpleName",
            "FileName", "FilePath"
        ])

        return await self.execute_query(query, **search_params)

    # ========================================
    # プロセス系統関連（将来拡張）
    # ========================================

    async def get_process_tree(
        self,
        process_id: str,
        aid: str,
        depth: int = 3,
        **search_params
    ) -> Dict[str, Any]:
        """
        プロセスツリーを取得（親・子プロセスを再帰的に取得）

        Args:
            process_id: 起点となるプロセスID
            aid: ホストID（必須）
            depth: 探索する深さ
            **search_params: 検索パラメータ

        Returns:
            プロセスツリー構造

        備考: 将来の拡張機能
        """
        # TODO: 実装予定
        raise NotImplementedError("get_process_tree is not implemented yet")
