#!/bin/bash
# テスト実行スクリプト

echo "CrowdStrike Falcon検索ライブラリのテストを実行します..."
echo ""

# テスト依存パッケージがインストールされているか確認
if ! command -v pytest &> /dev/null; then
    echo "pytestがインストールされていません。インストールしますか? (y/n)"
    read -r answer
    if [ "$answer" = "y" ]; then
        pip install -r requirements.txt
    else
        echo "pytestをインストールしてから再度実行してください。"
        exit 1
    fi
fi

echo "=== すべてのテストを実行 ==="
pytest -v

echo ""
echo "=== カバレッジ付きでテストを実行 ==="
pytest --cov=. --cov-report=term-missing --cov-report=html

echo ""
echo "テストが完了しました。"
echo "HTMLカバレッジレポートは htmlcov/index.html に生成されました。"
