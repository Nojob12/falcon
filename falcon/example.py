"""
CrowdStrike Falcon検索ライブラリの使用例
"""
from client import FalconSearchClient
from config import FalconConfig
from exceptions import FalconSearchError, FalconAPIError


def example_event_search():
    """イベント検索の使用例"""
    print("=== イベント検索の例 ===")

    # 方法1: 環境変数から認証情報を読み込む
    # export FALCON_CLIENT_ID="your_client_id"
    # export FALCON_CLIENT_SECRET="your_client_secret"
    try:
        config = FalconConfig()
        client = FalconSearchClient(config=config)

        # イベント検索を実行
        events = client.search_events(
            query="event_simpleName='ProcessRollup2'",
            start_time="2024-01-01T00:00:00Z",
            end_time="2024-01-02T00:00:00Z",
            limit=100,
            poll_interval=5,
            max_wait_time=300
        )

        print(f"取得したイベント数: {len(events)}")
        if events:
            print(f"最初のイベント: {events[0]}")

        client.close()

    except FalconSearchError as e:
        print(f"エラー: {e}")


def example_event_search_with_credentials():
    """認証情報を直接指定してイベント検索する例"""
    print("\n=== 認証情報を直接指定してイベント検索 ===")

    # 方法2: 認証情報を直接指定
    try:
        client = FalconSearchClient(
            client_id="your_client_id",
            client_secret="your_client_secret",
            base_url="auto"
        )

        events = client.search_events(
            query="event_simpleName='DnsRequest'",
            start_time="2024-01-01T00:00:00Z",
            end_time="2024-01-02T00:00:00Z",
            limit=50
        )

        print(f"取得したイベント数: {len(events)}")

        client.close()

    except FalconSearchError as e:
        print(f"エラー: {e}")


def example_alert_search():
    """アラート検索の使用例"""
    print("\n=== アラート検索の例 ===")

    try:
        config = FalconConfig()
        client = FalconSearchClient(config=config)

        # アラートIDから詳細を取得
        alert_ids = ["alert_id_1", "alert_id_2"]
        alerts = client.get_alert_details(alert_ids)

        print(f"取得したアラート数: {len(alerts)}")
        if alerts:
            print(f"最初のアラート: {alerts[0]}")

        client.close()

    except FalconSearchError as e:
        print(f"エラー: {e}")


def example_alert_search_by_filter():
    """フィルタークエリでアラートを検索する例"""
    print("\n=== フィルタークエリでアラート検索 ===")

    try:
        config = FalconConfig()
        client = FalconSearchClient(config=config)

        # フィルタークエリでアラートを検索
        filter_query = "status:'new'+severity:['high','critical']"

        # 方法1: アラートIDのみを取得
        search_result = client.search_alerts_by_filter(
            filter_query=filter_query,
            limit=10,
            sort="created_timestamp.desc"
        )

        print(f"総アラート数: {search_result['total']}")
        print(f"取得したアラートID数: {len(search_result['alert_ids'])}")

        # 方法2: アラートIDと詳細を一度に取得
        alerts = client.search_and_get_alerts(
            filter_query=filter_query,
            limit=10,
            sort="created_timestamp.desc"
        )

        print(f"取得したアラート詳細数: {len(alerts)}")
        for i, alert in enumerate(alerts[:3], 1):
            print(f"アラート{i}: {alert.get('composite_id', 'N/A')}")

        client.close()

    except FalconSearchError as e:
        print(f"エラー: {e}")


def example_single_alert():
    """単一のアラートを取得する例"""
    print("\n=== 単一アラート取得 ===")

    try:
        config = FalconConfig()
        client = FalconSearchClient(config=config)

        alert = client.get_single_alert("alert_id_example")

        if alert:
            print(f"アラート詳細: {alert}")
        else:
            print("アラートが見つかりませんでした")

        client.close()

    except FalconSearchError as e:
        print(f"エラー: {e}")


def example_context_manager():
    """コンテキストマネージャーを使用した例"""
    print("\n=== コンテキストマネージャーの使用例 ===")

    try:
        # withステートメントを使用すると、自動的にclose()が呼ばれる
        with FalconSearchClient(
            client_id="your_client_id",
            client_secret="your_client_secret"
        ) as client:
            # イベント検索
            events = client.search_events(
                query="event_simpleName='ProcessRollup2'",
                start_time="2024-01-01T00:00:00Z",
                end_time="2024-01-02T00:00:00Z",
                limit=10
            )
            print(f"イベント数: {len(events)}")

            # アラート検索
            alerts = client.search_and_get_alerts(
                filter_query="status:'new'",
                limit=5
            )
            print(f"アラート数: {len(alerts)}")

        # ブロックを抜けると自動的にクリーンアップされる

    except FalconSearchError as e:
        print(f"エラー: {e}")


def example_error_handling():
    """エラーハンドリングの例"""
    print("\n=== エラーハンドリングの例 ===")

    try:
        # 無効な認証情報でエラーが発生
        client = FalconSearchClient(
            client_id="invalid_id",
            client_secret="invalid_secret"
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
    except Exception as e:
        print(f"予期しないエラー: {e}")


if __name__ == "__main__":
    # 各例を実行
    # 注意: 実際に実行する前に、有効な認証情報を設定してください

    print("CrowdStrike Falcon検索ライブラリの使用例\n")

    # コメントを外して実行してください
    # example_event_search()
    # example_event_search_with_credentials()
    # example_alert_search()
    # example_alert_search_by_filter()
    # example_single_alert()
    # example_context_manager()
    # example_error_handling()

    print("\n注意: 実際に実行するには、有効な認証情報を設定し、上記の関数のコメントを外してください。")
