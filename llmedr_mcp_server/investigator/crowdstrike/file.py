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

    async def get_creator_process(
        self,
        filename: Optional[str] = None,
        hash_value: Optional[str] = None,
        aid: Optional[str] = None,
        exclude: bool = False,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        ファイル名またはハッシュ値から、そのファイルを作成したプロセスを検索

        Args:
            filename: 検索対象のファイル名（hash_valueと排他的）
            hash_value: SHA256ハッシュ値（filenameと排他的）
            aid: ホストID
            exclude: 除外フラグ（デフォルト: False）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト

        Raises:
            ValueError: filenameとhash_valueの両方が指定された、または両方とも未指定の場合

        対応クエリ: query_examples.py #2, #3
        """
        # 排他チェック
        if (filename is None and hash_value is None):
            raise ValueError("Either filename or hash_value must be specified")
        if (filename is not None and hash_value is not None):
            raise ValueError("Cannot specify both filename and hash_value")

        query = Query()

        if aid is not None:
            query.add("aid", aid, exclude=exclude)

        if filename is not None:
            query.add("FileName", filename)
        else:
            query.add("SHA256HashData", hash_value)

        query.contain("#event_simpleName", "Written")
        query.rename("ContextProcessId", "ProcessId")
        query.rename("ContextbaseFileName", "ProcessName")
        query.select([
            "timestamp", "aid", "#event_simpleName", "FilePath", "FileName",
            "ProcessId", "ProcessName", "SHA256HashData"
        ])

        return await self.execute_query(query, **search_params)

    # ========================================
    # ファイル実行関連
    # ========================================

    async def get_executor_process(
        self,
        filename: Optional[str] = None,
        hash_value: Optional[str] = None,
        aid: Optional[str] = None,
        exclude: bool = False,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        ファイル名またはハッシュ値から、そのファイルを実行したプロセスを検索

        Args:
            filename: 検索対象のファイル名（hash_valueと排他的）
            hash_value: SHA256ハッシュ値（filenameと排他的）
            aid: ホストID
            exclude: 除外フラグ（デフォルト: False）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト

        Raises:
            ValueError: filenameとhash_valueの両方が指定された、または両方とも未指定の場合

        対応クエリ: query_examples.py #4, #5
        """
        # 排他チェック
        if (filename is None and hash_value is None):
            raise ValueError("Either filename or hash_value must be specified")
        if (filename is not None and hash_value is not None):
            raise ValueError("Cannot specify both filename and hash_value")

        query = Query()

        if aid is not None:
            query.add("aid", aid, exclude=exclude)

        query.contain("#event_simpleName", "ProcessRollup2")

        if filename is not None:
            # サブクエリ: FileName=ファイル名 OR CommandLineにファイル名を含む
            sub_query = Query(operator="OR")
            sub_query.add("FileName", filename)
            sub_query.contain("CommandLine", filename)
            query.add_subquery(sub_query)
        else:
            query.add("SHA256HashData", hash_value)

        query.rename("TargetProcessId", "ProcessId")
        query.rename("FileName", "ProcessName")
        query.rename("FilePath", "ProcessPath")
        query.rename("ParentBaseFileName", "ParentProcessName")
        query.select([
            "timestamp", "aid", "ProcessPath", "ProcessName", "ProcessId",
            "CommandLine","SHA256HashData", "ParentProcessName", "ParentProcessId"
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

    async def get_module_loader(
        self,
        filename: Optional[str] = None,
        hash_value: Optional[str] = None,
        aid: Optional[str] = None,
        exclude: bool = False,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        ファイル名またはハッシュ値から、そのファイルをロードしているプロセスを検索

        Args:
            filename: 検索対象のファイル名（hash_valueと排他的）
            hash_value: SHA256ハッシュ値（filenameと排他的）
            aid: ホストID
            exclude: 除外フラグ（デフォルト: False）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト

        Raises:
            ValueError: filenameとhash_valueの両方が指定された、または両方とも未指定の場合

        対応クエリ: query_examples.py #8, #9
        """
        # 排他チェック
        if (filename is None and hash_value is None):
            raise ValueError("Either filename or hash_value must be specified")
        if (filename is not None and hash_value is not None):
            raise ValueError("Cannot specify both filename and hash_value")

        query = Query()

        if aid is not None:
            query.add("aid", aid, exclude=exclude)

        query.add("#event_simpleName", "ClassifiedModuleLoad")

        if filename is not None:
            query.add("FileName", filename)
        else:
            query.add("SHA256HashData", hash_value)

        query.rename("ContextProcessId", "ProcessId")
        query.rename("ContextBaseFileName", "ProcessName")
        query.select([
            "timestamp", "aid", "FilePath", "FileName",
            "ProcessName", "ProcessId", "SHA256HashData"
        ])

        return await self.execute_query(query, **search_params)

    # ========================================
    # ダウンロード関連
    # ========================================

    async def get_download_url(
        self,
        filename: Optional[str] = None,
        hash_value: Optional[str] = None,
        aid: Optional[str] = None,
        exclude: bool = False,
        **search_params
    ) -> List[Dict[str, Any]]:
        """
        ファイル名またはハッシュ値から、ダウンロード元URLを特定

        Args:
            filename: 検索対象のファイル名（hash_valueと排他的）
            hash_value: SHA256ハッシュ値（filenameと排他的）
            aid: ホストID
            exclude: 除外フラグ（デフォルト: False）
            **search_params: 検索パラメータ

        Returns:
            検索結果のリスト

        Raises:
            ValueError: filenameとhash_valueの両方が指定された、または両方とも未指定の場合

        対応クエリ: query_examples.py #11, #12
        """
        # 排他チェック
        if (filename is None and hash_value is None):
            raise ValueError("Either filename or hash_value must be specified")
        if (filename is not None and hash_value is not None):
            raise ValueError("Cannot specify both filename and hash_value")

        query = Query()

        if aid is not None:
            query.add("aid", aid, exclude=exclude)

        if filename is not None:
            query.add("FileName", filename)
        else:
            query.add("SHA256HashData", hash_value)

        # サブクエリ: HostUrl または ReferrerUrl を持つ
        sub_query = Query(operator="OR")
        sub_query.have("HostUrl")
        sub_query.have("ReferrerUrl")

        query.add_subquery(sub_query)
        query.rename("HostUrl", "SourceUrl")
        query.rename("ReferrerUrl", "SourceUrl")
        query.rename("ContextProcessId", "ProcessId")
        query.rename("ContextBaseFileName", "ProcessName")
        query.select([
            "timestamp", "aid", "#event_simpleName", "FilePath", "FileName",
            "SourceUrl", "ProcessId", "ProcessName",
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
        ).then_rename("TargetProcessId", "ProcessId").then_rename("FileName", "ProcessName")

        # それ以外の場合
        case2 = CaseCondition().when(
            Query().add("#event_simpleName", "*")
        ).then_rename("ContextProcessId", "ProcessId").then_rename(
            "FileName", "CompressedFile"
        ).then_rename("ContextBaseFileName", "ProcessName")

        # case文とselectを追加
        query.case(case1, case2)
        query.select([
            "timestamp", "aid", "#event_simpleName",
            "ProcessName", "ProcessId", "CompressedFile", "CommandLine"
        ])

        return await self.execute_query(query, **search_params)
