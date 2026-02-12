"""
CrowdStrike Falcon File Investigation Module

ファイルに関する調査機能を提供
"""
from typing import Dict, List, Any, Optional
import sys
sys.path.insert(0, '/Users/nojob/WorkSpace/falcon')

from falcon.query import Query, CaseCondition
from .base import InvestigationBase


class FileInvestigation(InvestigationBase):
    """ファイル関連の調査クラス"""

    # ========================================
    # ハッシュ値関連
    # ========================================

    async def get_hash_by_filename(
        self,
        filename: str,
        aid: Optional[str] = None,
        exclude: bool = False,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        ファイル名からハッシュ値を検索

        Args:
            filename: 検索対象のファイル名
            aid: ホストID
            exclude: 除外フラグ（Falseの場合は特定ホスト、Trueの場合は他ホスト）デフォルト値はFalse
            **search_params: 検索パラメータ（repository, start, is_live, interval, max_retries）

        Returns:
            検索結果のリスト

        使用例:
            - 特定ホスト: aid="xxx", exclude=False
            - 他ホスト: aid="xxx", exclude=True
            - 全ホスト: aid=None

        対応クエリ: query_examples.py #1
        """
        query = Query()

        # ホスト指定の処理
        if aid is not None:
            query.add("aid", aid, exclude=exclude)
        # aidが指定されていない場合は全ホスト検索

        query.add("FileName", filename)
        query.have("SHA256HashData")
        query.select([
            "timestamp", "aid", "#event_simpleName", "FilePath",
            "FileName", "SHA256HashData"
        ])

        return await self.execute_query(query, **search_params)

    # ========================================
    # ファイル作成関連
    # ========================================

    async def get_creator_process_by_filename(
        self,
        filename: str,
        aid: Optional[str] = None,
        exclude: bool = False,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        ファイル名から、そのファイルを作成したプロセスを検索

        Args:
            filename: 検索対象のファイル名
            aid: ホストID
            exclude: 除外フラグ（デフォルト: False）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #2
        """
        query = Query()

        if aid is not None:
            query.add("aid", aid, exclude=exclude)

        query.add("FileName", filename)
        query.contain("#event_simpleName", "Written")
        query.select([
            "timestamp", "aid", "#event_simpleName", "FilePath", "FileName",
            "ContextProcessId", "ContextBaseFileName", "ContextImageFileName"
        ])

        return await self.execute_query(query, **search_params)

    async def get_creator_process_by_hash(
        self,
        file_hash: str,
        aid: Optional[str] = None,
        exclude: bool = False,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        ハッシュ値から、そのファイルを作成したプロセスを検索

        Args:
            file_hash: SHA256ハッシュ値
            aid: ホストID
            exclude: 除外フラグ（デフォルト: False）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #3
        """
        query = Query()

        if aid is not None:
            query.add("aid", aid, exclude=exclude)

        query.add("SHA256HashData", file_hash)
        query.contain("#event_simpleName", "Written")
        query.select([
            "timestamp", "aid", "#event_simpleName", "FilePath", "FileName",
            "ContextProcessId", "ContextBaseFileName", "ContextImageFileName"
        ])

        return await self.execute_query(query, **search_params)

    # ========================================
    # ファイル実行関連
    # ========================================

    async def get_executor_process_by_filename(
        self,
        filename: str,
        aid: Optional[str] = None,
        exclude: bool = False,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        ファイル名から、そのファイルを実行したプロセスを検索

        Args:
            filename: 検索対象のファイル名
            aid: ホストID
            exclude: 除外フラグ（デフォルト: False）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #4
        """
        query = Query()

        if aid is not None:
            query.add("aid", aid, exclude=exclude)

        query.contain("#event_simpleName", "ProcessRollup2")

        # サブクエリ: FileName=ファイル名 OR CommandLineにファイル名を含む
        sub_query = Query(operator="OR")
        sub_query.add("FileName", filename)
        sub_query.contain("CommandLine", filename)

        query.add_subquery(sub_query)
        query.select([
            "timestamp", "aid", "FilePath", "FileName", "TargetProcessId",
            "CommandLine", "ParentBaseFileName", "ParentProcessId"
        ])

        return await self.execute_query(query, **search_params)

    async def get_executor_process_by_hash(
        self,
        file_hash: str,
        aid: Optional[str] = None,
        exclude: bool = False,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        ハッシュ値から、そのファイルを実行したプロセスを検索

        Args:
            file_hash: SHA256ハッシュ値
            aid: ホストID
            exclude: 除外フラグ（デフォルト: False）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #5
        """
        query = Query()

        if aid is not None:
            query.add("aid", aid, exclude=exclude)

        query.add("SHA256HashData", file_hash)
        query.contain("#event_simpleName", "ProcessRollup2")
        query.select([
            "timestamp", "aid", "FilePath", "FileName", "TargetProcessId",
            "CommandLine", "ParentBaseFileName", "ParentProcessId"
        ])

        return await self.execute_query(query, **search_params)

    # ========================================
    # スクリプトコンテンツ関連
    # ========================================

    async def get_script_content_by_filename(
        self,
        filename: str,
        aid: Optional[str] = None,
        exclude: bool = False,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        ファイル名から、そのファイルの中身が記録されたログを検索

        Args:
            filename: 検索対象のファイル名
            aid: ホストID
            exclude: 除外フラグ（デフォルト: False）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #6
        """
        query = Query()

        if aid is not None:
            query.add("aid", aid, exclude=exclude)

        query.add("FileName", filename)
        query.have("ScriptContent")
        query.select([
            "timestamp", "aid", "#event_simpleName", "FileName",
            "FilePath", "ScriptContent"
        ])

        return await self.execute_query(query, **search_params)

    # ========================================
    # モジュールロード関連
    # ========================================

    async def get_module_loader_by_filename(
        self,
        filename: str,
        aid: Optional[str] = None,
        exclude: bool = False,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        ファイル名から、そのファイルをロードしているプロセスを検索

        Args:
            filename: 検索対象のファイル名
            aid: ホストID
            exclude: 除外フラグ（デフォルト: False）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #8
        """
        query = Query()

        if aid is not None:
            query.add("aid", aid, exclude=exclude)

        query.add("#event_simpleName", "ClassifiedModuleLoad")
        query.add("FileName", filename)
        query.select([
            "timestamp", "aid", "FilePath", "FileName", "TargetProcessId",
            "CommandLine", "ParentBaseFileName", "ParentProcessId"
        ])

        return await self.execute_query(query, **search_params)

    async def get_module_loader_by_hash(
        self,
        file_hash: str,
        aid: Optional[str] = None,
        exclude: bool = False,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        ハッシュ値から、そのファイルをロードしているプロセスを検索

        Args:
            file_hash: SHA256ハッシュ値
            aid: ホストID
            exclude: 除外フラグ（デフォルト: False）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #9
        """
        query = Query()

        if aid is not None:
            query.add("aid", aid, exclude=exclude)

        query.add("#event_simpleName", "ClassifiedModuleLoad")
        query.add("SHA256HashData", file_hash)
        query.select([
            "timestamp", "aid", "FilePath", "FileName", "TargetProcessId",
            "CommandLine", "ParentBaseFileName", "ParentProcessId"
        ])

        return await self.execute_query(query, **search_params)

    # ========================================
    # ダウンロード関連
    # ========================================

    async def get_download_url_by_filename(
        self,
        filename: str,
        aid: Optional[str] = None,
        exclude: bool = False,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        ファイル名から、ダウンロード元URLを特定

        Args:
            filename: 検索対象のファイル名
            aid: ホストID
            exclude: 除外フラグ（デフォルト: False）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #11
        """
        query = Query()

        if aid is not None:
            query.add("aid", aid, exclude=exclude)

        query.add("FileName", filename)

        # サブクエリ: HostUrl または ReferrerUrl を持つ
        sub_query = Query(operator="OR")
        sub_query.have("HostUrl")
        sub_query.have("ReferrerUrl")

        query.add_subquery(sub_query)
        query.select([
            "timestamp", "aid", "#event_simpleName", "FilePath", "FileName",
            "HostUrl", "ReferrerUrl", "ContextProcessId", "ContextBaseFileName",
            "ContextImageFileName"
        ])

        return await self.execute_query(query, **search_params)

    async def get_download_url_by_hash(
        self,
        file_hash: str,
        aid: Optional[str] = None,
        exclude: bool = False,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        ハッシュ値から、ダウンロード元URLを特定

        Args:
            file_hash: SHA256ハッシュ値
            aid: ホストID
            exclude: 除外フラグ（デフォルト: False）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #12
        """
        query = Query()

        if aid is not None:
            query.add("aid", aid, exclude=exclude)

        query.add("SHA256HashData", file_hash)

        # サブクエリ: HostUrl または ReferrerUrl を持つ
        sub_query = Query(operator="OR")
        sub_query.have("HostUrl")
        sub_query.have("ReferrerUrl")

        query.add_subquery(sub_query)
        query.select([
            "timestamp", "aid", "#event_simpleName", "FilePath", "FileName",
            "HostUrl", "ReferrerUrl", "ContextProcessId", "ContextBaseFileName",
            "ContextImageFileName"
        ])

        return await self.execute_query(query, **search_params)

    # ========================================
    # 圧縮ファイル関連
    # ========================================

    async def search_compressed_file_operations(
        self,
        aid: Optional[str] = None,
        exclude: bool = False,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        圧縮ファイルを作成もしくはオープンしているプロセスを検索

        Args:
            aid: ホストID
            exclude: 除外フラグ（デフォルト: False）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #13
        """
        query = Query(operator="AND") if aid is not None else Query(operator="OR")

        if aid is not None:
            query.add("aid", aid, exclude=exclude)

        # 圧縮ファイル条件をサブクエリとして追加
        compressed_query = Query(operator="OR")
        compressed_query.regex("FileName", r".+\.(zip|rar|7z|tar|gz|bz2|xz|lzh|sitx|dmg|iso|jar|apk)$")
        compressed_query.regex("CommandLine", r".+\.(zip|rar|7z|tar|gz|bz2|xz|lzh|sitx|dmg|iso|jar|apk)")

        if aid is not None:
            query.add_subquery(compressed_query)
        else:
            # 全ホスト検索の場合はサブクエリではなく直接条件を追加
            query = compressed_query

        # case文の定義
        # ProcessRollup2の場合
        case1 = CaseCondition().when(
            Query().contain("#event_simpleName", "ProcessRollup2")
        ).then_rename("ProcessId", "TargetProcessId").then_rename("ProcessName", "FileName")

        # それ以外の場合
        case2 = CaseCondition().when(
            Query().add("#event_simpleName", "*")
        ).then_rename("ProcessId", "ContextProcessId").then_rename(
            "CompressedFile", "FileName"
        ).then_rename("ProcessName", "ContextBaseFileName")

        # case文とselectを追加
        query.case(case1, case2)
        query.select([
            "timestamp", "aid", "#event_simpleName",
            "ProcessName", "ProcessId", "CompressedFile", "CommandLine"
        ])

        return await self.execute_query(query, **search_params)
