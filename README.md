# CrowdStrike Falcon検索ライブラリ

CrowdStrike FalconのイベントとアラートをPythonで簡単に検索できるライブラリです。FalconPy SDKをベースに、使いやすいインターフェースを提供します。

## 機能

- **イベント検索**: FQL (Falcon Query Language)を使用したイベント検索
- **アラート検索**: アラートIDまたはフィルタークエリによるアラート検索
- **エラーハンドリング**: 専用のカスタム例外クラスによる詳細なエラー情報
- **認証管理**: 環境変数または直接指定による柔軟な認証設定

## インストール

```bash
pip install -r requirements.txt
```

## セットアップ

### 認証情報の設定

2つの方法で認証情報を設定できます。

#### 方法1: 環境変数を使用

```bash
export FALCON_CLIENT_ID="your_client_id"
export FALCON_CLIENT_SECRET="your_client_secret"
```

#### 方法2: コードで直接指定

```python
from client import FalconSearchClient

client = FalconSearchClient(
    client_id="your_client_id",
    client_secret="your_client_secret"
)
```

## 使用例

### イベント検索

```python
from client import FalconSearchClient
from config import FalconConfig

# 環境変数から認証情報を読み込む
config = FalconConfig()
client = FalconSearchClient(config=config)

# イベント検索
events = client.search_events(
    query="event_simpleName='ProcessRollup2'",
    start_time="2024-01-01T00:00:00Z",
    end_time="2024-01-02T00:00:00Z",
    limit=100
)

print(f"取得したイベント数: {len(events)}")
client.close()
```

### アラート検索

#### アラートIDから詳細を取得

```python
from client import FalconSearchClient

client = FalconSearchClient(
    client_id="your_client_id",
    client_secret="your_client_secret"
)

# 複数のアラート詳細を取得
alert_ids = ["alert_id_1", "alert_id_2"]
alerts = client.get_alert_details(alert_ids)

# 単一のアラート詳細を取得
alert = client.get_single_alert("alert_id_1")

client.close()
```

#### フィルタークエリでアラート検索

```python
from client import FalconSearchClient

client = FalconSearchClient(
    client_id="your_client_id",
    client_secret="your_client_secret"
)

# フィルタークエリでアラートを検索し、詳細を取得
alerts = client.search_and_get_alerts(
    filter_query="status:'new'+severity:['high','critical']",
    limit=10,
    sort="created_timestamp.desc"
)

for alert in alerts:
    print(f"アラートID: {alert.get('composite_id')}")
    print(f"重大度: {alert.get('severity')}")

client.close()
```

### コンテキストマネージャーを使用

```python
from client import FalconSearchClient

# withステートメントで自動的にクリーンアップ
with FalconSearchClient(
    client_id="your_client_id",
    client_secret="your_client_secret"
) as client:
    events = client.search_events(
        query="event_simpleName='DnsRequest'",
        start_time="2024-01-01T00:00:00Z",
        end_time="2024-01-02T00:00:00Z"
    )
    print(f"イベント数: {len(events)}")
```

### エラーハンドリング

```python
from client import FalconSearchClient
from exceptions import FalconAPIError, FalconSearchError

try:
    client = FalconSearchClient(
        client_id="your_client_id",
        client_secret="your_client_secret"
    )

    events = client.search_events(
        query="event_simpleName='ProcessRollup2'",
        start_time="2024-01-01T00:00:00Z",
        end_time="2024-01-02T00:00:00Z"
    )

except FalconAPIError as e:
    print(f"API呼び出しエラー: {e}")
    print(f"ステータスコード: {e.status_code}")
    print(f"レスポンス: {e.response}")
except FalconSearchError as e:
    print(f"検索エラー: {e}")
```

## テスト

### テストの実行

```bash
# すべてのテストを実行
pytest

# カバレッジ付きでテストを実行
pytest --cov=. --cov-report=html

# 特定のテストファイルを実行
pytest tests/test_config.py

# 特定のテストクラスを実行
pytest tests/test_event_search.py::TestFalconEventSearch

# 特定のテスト関数を実行
pytest tests/test_config.py::TestFalconConfig::test_init_with_direct_credentials

# 詳細な出力
pytest -v

# テストカバレッジレポートの表示
pytest --cov=. --cov-report=term-missing
```

### テストファイル

- [tests/test_config.py](tests/test_config.py) - FalconConfigのテスト
- [tests/test_event_search.py](tests/test_event_search.py) - FalconEventSearchのテスト
- [tests/test_alert_search.py](tests/test_alert_search.py) - FalconAlertSearchのテスト
- [tests/test_client.py](tests/test_client.py) - FalconSearchClientのテスト
- [tests/test_exceptions.py](tests/test_exceptions.py) - カスタム例外のテスト
- [tests/conftest.py](tests/conftest.py) - pytestフィクスチャとテスト設定

## ファイル構成

```
falcon/
├── client.py           # FalconSearchClient - メインクライアント
├── config.py           # FalconConfig - 認証情報管理
├── exceptions.py       # カスタム例外クラス
├── search/             # 検索クラス用ディレクトリ
│   ├── __init__.py
│   ├── event_search.py     # FalconEventSearch - イベント検索クラス
│   └── alert_search.py     # FalconAlertSearch - アラート検索クラス
├── tests/              # テストディレクトリ
│   ├── __init__.py
│   ├── conftest.py         # pytestフィクスチャ
│   ├── test_config.py      # FalconConfigのテスト
│   ├── test_event_search.py    # FalconEventSearchのテスト
│   ├── test_alert_search.py    # FalconAlertSearchのテスト
│   ├── test_client.py      # FalconSearchClientのテスト
│   └── test_exceptions.py  # カスタム例外のテスト
├── example.py          # 使用例
├── requirements.txt    # 依存パッケージ
├── pytest.ini          # pytest設定
├── .gitignore          # Git除外設定
├── __init__.py         # パッケージ初期化
└── README.md          # このファイル
```

## クラス説明

### FalconSearchClient

イベント検索とアラート検索を統合して管理するメインクライアントクラス。

主なメソッド:
- `search_events()`: イベント検索
- `get_alert_details()`: アラートID指定でアラート詳細取得
- `get_single_alert()`: 単一アラート取得
- `search_alerts_by_filter()`: フィルタークエリでアラート検索(IDのみ)
- `search_and_get_alerts()`: フィルタークエリでアラート検索と詳細取得

### FalconEventSearch

FalconPyのNGSIEMサービスを使用してイベント検索を行うクラス。

- `StartSearchV1`: イベント検索を開始
- `GetSearchStatusV1`: 検索ステータスを取得し、結果を取得

### FalconAlertSearch

FalconPyのAlertsサービスを使用してアラート検索を行うクラス。

- `post_entities_alerts_v2`: アラートIDからアラート詳細を取得
- `query_alerts_v2`: フィルタークエリでアラートIDを検索

### FalconConfig

CrowdStrike Falconの認証情報を管理するクラス。

### カスタム例外

- `FalconSearchError`: 基底例外クラス
- `FalconAPIError`: API呼び出しエラー
- `FalconAuthenticationError`: 認証エラー
- `FalconConfigurationError`: 設定エラー
- `FalconEventSearchError`: イベント検索エラー
- `FalconAlertSearchError`: アラート検索エラー
- `FalconResourceNotFoundError`: リソース未検出エラー

## API仕様

- [FalconPy NGSIEM Service](https://www.falconpy.io/Service-Collections/NGSIEM.html)
- [FalconPy Alerts Service](https://www.falconpy.io/Service-Collections/Alerts.html)

## ライセンス

このプロジェクトはMITライセンスの下で公開されています。
