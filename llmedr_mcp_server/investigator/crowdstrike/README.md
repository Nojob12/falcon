# CrowdStrike Falcon Investigation Module

CrowdStrike Falconを使った各種調査機能を提供するモジュール

## ディレクトリ構造

```
llmedr_mcp_server/investigator/crowdstrike/
├── __init__.py        # モジュールエントリポイント
├── base.py            # 基底クラス（InvestigationBase）
├── file.py            # ファイル関連調査（FileInvestigation）
├── process.py         # プロセス関連調査（ProcessInvestigation）
└── network.py         # ネットワーク関連調査（NetworkInvestigation）- 将来拡張用
```

## 実装済み機能

### FileInvestigation (file.py) - 11メソッド

| メソッド名 | 説明 | 対応クエリ |
|-----------|------|-----------|
| `get_hash_by_filename` | ファイル名→ハッシュ値 | #1 |
| `get_creator_process_by_filename` | ファイル名→作成プロセス | #2 |
| `get_creator_process_by_hash` | ハッシュ値→作成プロセス | #3 |
| `get_executor_process_by_filename` | ファイル名→実行プロセス | #4 |
| `get_executor_process_by_hash` | ハッシュ値→実行プロセス | #5 |
| `get_script_content_by_filename` | ファイル名→スクリプト内容 | #6 |
| `get_module_loader_by_filename` | ファイル名→モジュールロード | #8 |
| `get_module_loader_by_hash` | ハッシュ値→モジュールロード | #9 |
| `get_download_url_by_filename` | ファイル名→ダウンロードURL | #11 |
| `get_download_url_by_hash` | ハッシュ値→ダウンロードURL | #12 |
| `search_compressed_file_operations` | 圧縮ファイル操作検索 | #13 |

**ホスト指定オプション:**
- `aid="xxx", exclude=False`: 特定ホスト内で検索（デフォルト）
- `aid="xxx", exclude=True`: 特定ホストを除外して検索（他ホスト）
- `aid=None`: 全ホスト検索

### ProcessInvestigation (process.py) - 3メソッド + 1将来拡張

| メソッド名 | 説明 | 対応クエリ |
|-----------|------|-----------|
| `get_process_with_filename_in_cmdline` | ファイル名→コマンドライン検索 | #7 |
| `get_child_processes_by_parent_name` | 親プロセス名→子プロセス | #10 |
| `get_process_startup_by_pid` | プロセスID→起動ログ | #14 |
| `get_process_tree` | プロセスツリー取得（未実装） | 将来拡張 |

**ホスト指定:**
- `aid`: 必須（特定ホスト内での検索のみ）

### NetworkInvestigation (network.py) - 将来拡張用

| メソッド名 | 説明 | ステータス |
|-----------|------|-----------|
| `get_network_connections_by_process` | プロセスID→ネットワーク接続 | 未実装 |
| `get_dns_queries_by_domain` | ドメイン名→DNSクエリ | 未実装 |
| `get_outbound_connections_by_ip` | IPアドレス→アウトバウンド接続 | 未実装 |

## 使用例

### 基本的な使い方

```python
import asyncio
from falcon import FalconSearchClient
from llmedr_mcp_server.investigator.crowdstrike import FileInvestigation, ProcessInvestigation

async def main():
    # クライアント初期化
    client = FalconSearchClient(
        client_id="your_client_id",
        client_secret="your_client_secret"
    )

    # ファイル調査インスタンス作成
    file_inv = FileInvestigation(client)

    # 1. 特定ホストでの検索
    print("=== 特定ホストでの検索 ===")
    results = await file_inv.get_hash_by_filename(
        "malware.exe",
        aid="2e5445246a35d55",
        exclude=False  # デフォルト値
    )
    print(f"検索結果: {len(results)}件")

    # 2. 他ホストでの検索（特定ホストを除外）
    print("\n=== 他ホストでの検索 ===")
    results = await file_inv.get_hash_by_filename(
        "malware.exe",
        aid="2e5445246a35d55",
        exclude=True  # 除外フラグをTrue
    )
    print(f"検索結果: {len(results)}件")

    # 3. 全ホストでの検索
    print("\n=== 全ホストでの検索 ===")
    results = await file_inv.get_hash_by_filename("malware.exe")
    print(f"検索結果: {len(results)}件")

    # プロセス調査インスタンス作成
    proc_inv = ProcessInvestigation(client)

    # 4. プロセス調査（ホストID必須）
    print("\n=== プロセス起動ログ検索 ===")
    results = await proc_inv.get_process_startup_by_pid(
        "40612979432",
        aid="2e5445246a35d55"
    )
    print(f"検索結果: {len(results)}件")

if __name__ == "__main__":
    asyncio.run(main())
```

### 検索パラメータのカスタマイズ

```python
# 検索範囲とポーリング設定をカスタマイズ
results = await file_inv.get_creator_process_by_hash(
    file_hash="abc123def456...",
    aid="2e5445246a35d55",
    repository="search-all",  # リポジトリ指定
    start="1h",               # 過去1時間
    is_live=False,            # ライブ検索無効
    interval=10,              # 10秒ごとにポーリング
    max_retries=30            # 最大30回試行
)
```

### 複数の調査を組み合わせる

```python
async def investigate_suspicious_file(filename: str, host_aid: str):
    """不審なファイルを包括的に調査"""
    file_inv = FileInvestigation(client)

    # 1. ハッシュ値を取得
    hash_results = await file_inv.get_hash_by_filename(filename, aid=host_aid)
    if not hash_results:
        print("ファイルが見つかりません")
        return

    file_hash = hash_results[0].get("SHA256HashData")

    # 2. 作成プロセスを調査
    creator_results = await file_inv.get_creator_process_by_hash(file_hash, aid=host_aid)

    # 3. 実行プロセスを調査
    executor_results = await file_inv.get_executor_process_by_hash(file_hash, aid=host_aid)

    # 4. ダウンロード元URLを調査
    download_results = await file_inv.get_download_url_by_hash(file_hash, aid=host_aid)

    # 結果をまとめて返す
    return {
        "hash": file_hash,
        "creator": creator_results,
        "executor": executor_results,
        "download_url": download_results
    }
```

## 実装の特徴

### 1. 非同期処理 (async/await)
すべてのメソッドは`async`関数として実装されており、CrowdStrike APIへの非同期呼び出しに対応しています。

### 2. 柔軟なホスト指定

**FileInvestigation (ファイル調査):**
- `aid="xxx", exclude=False`: 特定ホスト内で検索（デフォルト）
- `aid="xxx", exclude=True`: 指定ホスト以外で検索（他ホスト）
- `aid=None`: 全ホストで検索

**ProcessInvestigation (プロセス調査):**
- `aid="xxx"`: 必須（特定ホスト内での検索のみ）

### 3. 検索パラメータのカスタマイズ
すべてのメソッドで以下のパラメータをカスタマイズ可能:
- `repository`: 検索対象リポジトリ（デフォルト: "search-all"）
- `start`: 検索範囲（デフォルト: "15m"）
- `is_live`: ライブ検索フラグ（デフォルト: False）
- `interval`: ポーリング間隔秒数（デフォルト: 5）
- `max_retries`: 最大試行回数（デフォルト: 60）

### 4. クエリビルダーの活用
内部で`Query`と`CaseCondition`クラスを使用してFQLクエリを動的に構築します。

### 5. 基底クラスによる共通機能
`InvestigationBase`クラスで共通機能を提供:
- `execute_query()`: クエリ実行
- `set_host()`: デフォルトホスト設定
- `get_host()`: ホストID取得

## 統計情報

- **総コード行数**: 855行
- **実装済みメソッド**: 14メソッド
- **将来拡張用メソッド**: 4メソッド
- **クラス数**: 4クラス（Base + File + Process + Network）

## 将来の拡張予定

1. **NetworkInvestigation の実装**
   - ネットワーク接続の調査
   - DNSクエリの調査
   - アウトバウンド接続の調査

2. **ProcessInvestigation の拡張**
   - プロセスツリーの再帰的取得
   - プロセス系統図の生成

3. **エラーハンドリングの強化**
   - リトライロジックの改善
   - タイムアウト処理の最適化

4. **キャッシング機能**
   - 同一クエリの結果をキャッシュ
   - パフォーマンス向上
