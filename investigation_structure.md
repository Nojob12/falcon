# CrowdStrike Falcon 調査機能の構成設計

## ディレクトリ構造

```
falcon/
├── investigation/
│   ├── __init__.py
│   ├── file.py          # ファイル関連の調査
│   ├── process.py       # プロセス関連の調査
│   ├── network.py       # ネットワーク関連の調査（将来拡張用）
│   └── base.py          # 基底クラス
```

## ファイル別クラス・関数構成

### 1. `falcon/investigation/base.py`
**目的**: すべての調査クラスの基底クラスと共通機能

```python
class InvestigationBase:
    """調査機能の基底クラス"""

    def __init__(self, client: FalconSearchClient, host_aid: str = None):
        """
        Args:
            client: FalconSearchClientインスタンス
            host_aid: 調査対象ホストID（Noneの場合は全ホスト）
        """
        pass

    def execute_query(self, query: Query, **search_params) -> List[Dict[str, Any]]:
        """クエリを実行して結果を取得"""
        pass

    def set_host(self, host_aid: str) -> None:
        """調査対象ホストを設定"""
        pass
```

---

### 2. `falcon/investigation/file.py`
**目的**: ファイルに関する調査機能を提供

```python
class FileInvestigation(InvestigationBase):
    """ファイル関連の調査クラス"""

    # ========================================
    # ハッシュ値関連
    # ========================================

    def get_hash_by_filename(
        self,
        filename: str,
        host_aid: str = None
    ) -> List[Dict[str, Any]]:
        """
        ファイル名からハッシュ値を検索

        Args:
            filename: 検索対象のファイル名
            host_aid: ホストID（Noneの場合は初期化時のhost_aidを使用）

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #1
        """
        pass

    # ========================================
    # ファイル作成関連
    # ========================================

    def get_creator_process_by_filename(
        self,
        filename: str,
        host_aid: str = None
    ) -> List[Dict[str, Any]]:
        """
        ファイル名から、そのファイルを作成したプロセスを検索

        Args:
            filename: 検索対象のファイル名
            host_aid: ホストID

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #2
        """
        pass

    def get_creator_process_by_hash(
        self,
        file_hash: str,
        host_aid: str = None
    ) -> List[Dict[str, Any]]:
        """
        ハッシュ値から、そのファイルを作成したプロセスを検索

        Args:
            file_hash: SHA256ハッシュ値
            host_aid: ホストID

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #3
        """
        pass

    # ========================================
    # ファイル実行関連
    # ========================================

    def get_executor_process_by_filename(
        self,
        filename: str,
        host_aid: str = None
    ) -> List[Dict[str, Any]]:
        """
        ファイル名から、そのファイルを実行したプロセスを検索

        Args:
            filename: 検索対象のファイル名
            host_aid: ホストID

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #4
        """
        pass

    def get_executor_process_by_hash(
        self,
        file_hash: str,
        host_aid: str = None
    ) -> List[Dict[str, Any]]:
        """
        ハッシュ値から、そのファイルを実行したプロセスを検索

        Args:
            file_hash: SHA256ハッシュ値
            host_aid: ホストID

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #5
        """
        pass

    # ========================================
    # スクリプトコンテンツ関連
    # ========================================

    def get_script_content_by_filename(
        self,
        filename: str,
        host_aid: str = None
    ) -> List[Dict[str, Any]]:
        """
        ファイル名から、そのファイルの中身が記録されたログを検索

        Args:
            filename: 検索対象のファイル名
            host_aid: ホストID

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #6
        """
        pass

    # ========================================
    # モジュールロード関連
    # ========================================

    def get_module_loader_by_filename(
        self,
        filename: str,
        host_aid: str = None
    ) -> List[Dict[str, Any]]:
        """
        ファイル名から、そのファイルをロードしているプロセスを検索

        Args:
            filename: 検索対象のファイル名
            host_aid: ホストID

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #8
        """
        pass

    def get_module_loader_by_hash(
        self,
        file_hash: str,
        host_aid: str = None
    ) -> List[Dict[str, Any]]:
        """
        ハッシュ値から、そのファイルをロードしているプロセスを検索

        Args:
            file_hash: SHA256ハッシュ値
            host_aid: ホストID

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #9
        """
        pass

    # ========================================
    # ダウンロード関連
    # ========================================

    def get_download_url_by_filename(
        self,
        filename: str,
        host_aid: str = None
    ) -> List[Dict[str, Any]]:
        """
        ファイル名から、ダウンロード元URLを特定

        Args:
            filename: 検索対象のファイル名
            host_aid: ホストID

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #11
        """
        pass

    def get_download_url_by_hash(
        self,
        file_hash: str,
        host_aid: str = None
    ) -> List[Dict[str, Any]]:
        """
        ハッシュ値から、ダウンロード元URLを特定

        Args:
            file_hash: SHA256ハッシュ値
            host_aid: ホストID

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #12
        """
        pass

    # ========================================
    # 圧縮ファイル関連
    # ========================================

    def search_compressed_file_operations(
        self,
        host_aid: str = None
    ) -> List[Dict[str, Any]]:
        """
        圧縮ファイルを作成もしくはオープンしているプロセスを検索

        Args:
            host_aid: ホストID

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #13
        """
        pass
```

---

### 3. `falcon/investigation/process.py`
**目的**: プロセスに関する調査機能を提供

```python
class ProcessInvestigation(InvestigationBase):
    """プロセス関連の調査クラス"""

    # ========================================
    # コマンドライン関連
    # ========================================

    def get_process_with_filename_in_cmdline(
        self,
        filename: str,
        host_aid: str = None
    ) -> List[Dict[str, Any]]:
        """
        ファイル名から、そのファイルがコマンドラインに入るプロセスを検索

        Args:
            filename: 検索対象のファイル名
            host_aid: ホストID

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #7
        """
        pass

    # ========================================
    # 親子関係関連
    # ========================================

    def get_child_processes_by_parent_name(
        self,
        parent_name: str,
        host_aid: str = None
    ) -> List[Dict[str, Any]]:
        """
        親プロセス名から実行されているプロセスの一覧を取得

        Args:
            parent_name: 親プロセスのベースファイル名（例: "explorer.exe"）
            host_aid: ホストID

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #10
        """
        pass

    # ========================================
    # プロセスID関連
    # ========================================

    def get_process_startup_by_pid(
        self,
        process_id: str,
        host_aid: str
    ) -> List[Dict[str, Any]]:
        """
        プロセスIDから、プロセスの起動ログを検索

        Args:
            process_id: ターゲットプロセスID
            host_aid: ホストID（必須）

        Returns:
            検索結果のリスト

        対応クエリ: query_examples.py #14
        """
        pass

    # ========================================
    # プロセス系統関連
    # ========================================

    def get_process_tree(
        self,
        process_id: str,
        host_aid: str,
        depth: int = 3
    ) -> Dict[str, Any]:
        """
        プロセスツリーを取得（親・子プロセスを再帰的に取得）

        Args:
            process_id: 起点となるプロセスID
            host_aid: ホストID
            depth: 探索する深さ

        Returns:
            プロセスツリー構造

        備考: 将来の拡張機能
        """
        pass
```

---

### 4. `falcon/investigation/network.py`
**目的**: ネットワーク関連の調査機能を提供（将来拡張用）

```python
class NetworkInvestigation(InvestigationBase):
    """ネットワーク関連の調査クラス（将来拡張用）"""

    def get_network_connections_by_process(
        self,
        process_id: str,
        host_aid: str = None
    ) -> List[Dict[str, Any]]:
        """プロセスIDからネットワーク接続を検索"""
        pass

    def get_dns_queries_by_domain(
        self,
        domain: str,
        host_aid: str = None
    ) -> List[Dict[str, Any]]:
        """ドメイン名からDNSクエリを検索"""
        pass
```

---

### 5. `falcon/investigation/__init__.py`
**目的**: 調査モジュールのエントリポイント

```python
"""
CrowdStrike Falcon Investigation Module

各種調査機能を提供するモジュール
"""

from .base import InvestigationBase
from .file import FileInvestigation
from .process import ProcessInvestigation
from .network import NetworkInvestigation

__all__ = [
    "InvestigationBase",
    "FileInvestigation",
    "ProcessInvestigation",
    "NetworkInvestigation",
]
```

---

## 使用例

```python
from falcon import FalconSearchClient
from falcon.investigation import FileInvestigation, ProcessInvestigation

# クライアント初期化
client = FalconSearchClient(
    client_id="your_client_id",
    client_secret="your_client_secret"
)

# ファイル調査
file_inv = FileInvestigation(client, host_aid="2e5445246a35d55")

# 1. ファイル名からハッシュ値を検索
hash_results = file_inv.get_hash_by_filename("malware.exe")

# 2. ハッシュ値から作成プロセスを検索
creator_results = file_inv.get_creator_process_by_hash("abc123def456...")

# 3. ダウンロード元URLを特定
download_results = file_inv.get_download_url_by_filename("malware.exe")

# プロセス調査
proc_inv = ProcessInvestigation(client, host_aid="2e5445246a35d55")

# 4. explorer.exeの子プロセスを取得
children = proc_inv.get_child_processes_by_parent_name("explorer.exe")

# 5. プロセスIDから起動ログを検索
startup = proc_inv.get_process_startup_by_pid("40612979432", "2e5445246a35d55")
```

---

## 機能分類マッピング

| クエリ番号 | 機能名 | クラス | メソッド名 |
|-----------|--------|--------|-----------|
| 1 | ファイル名→ハッシュ値 | FileInvestigation | get_hash_by_filename |
| 2 | ファイル名→作成プロセス | FileInvestigation | get_creator_process_by_filename |
| 3 | ハッシュ値→作成プロセス | FileInvestigation | get_creator_process_by_hash |
| 4 | ファイル名→実行プロセス | FileInvestigation | get_executor_process_by_filename |
| 5 | ハッシュ値→実行プロセス | FileInvestigation | get_executor_process_by_hash |
| 6 | ファイル名→スクリプト内容 | FileInvestigation | get_script_content_by_filename |
| 7 | ファイル名→コマンドライン | ProcessInvestigation | get_process_with_filename_in_cmdline |
| 8 | ファイル名→モジュールロード | FileInvestigation | get_module_loader_by_filename |
| 9 | ハッシュ値→モジュールロード | FileInvestigation | get_module_loader_by_hash |
| 10 | 親プロセス名→子プロセス | ProcessInvestigation | get_child_processes_by_parent_name |
| 11 | ファイル名→ダウンロードURL | FileInvestigation | get_download_url_by_filename |
| 12 | ハッシュ値→ダウンロードURL | FileInvestigation | get_download_url_by_hash |
| 13 | 圧縮ファイル操作検索 | FileInvestigation | search_compressed_file_operations |
| 14 | プロセスID→起動ログ | ProcessInvestigation | get_process_startup_by_pid |

---

## 設計の特徴

### 1. **関心の分離**
- ファイル関連: `FileInvestigation`
- プロセス関連: `ProcessInvestigation`
- ネットワーク関連: `NetworkInvestigation`（将来拡張）

### 2. **一貫性のある命名規則**
- `get_XXX_by_YYY`: YYYからXXXを取得
- `search_XXX`: XXXを検索

### 3. **柔軟なホスト指定**
- 初期化時にデフォルトホストを設定可能
- メソッド呼び出し時に個別にホストを指定可能

### 4. **拡張性**
- 基底クラスで共通機能を実装
- 新しい調査カテゴリを追加しやすい設計

### 5. **再利用性**
- クエリビルダー（Query、CaseCondition）を内部で使用
- FalconSearchClientと統合
