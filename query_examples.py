"""
CrowdStrike Falcon Query Examples

各検索機能のクエリ作成例（特定ホスト内での検索のみ）
"""
import sys
sys.path.insert(0, '/Users/nojob/WorkSpace/falcon')

import importlib.util
spec = importlib.util.spec_from_file_location('query', '/Users/nojob/WorkSpace/falcon/falcon/query.py')
query_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(query_module)

Query = query_module.Query
CaseCondition = query_module.CaseCondition


def print_query(number: str, title: str, query: Query):
    """クエリを整形して表示"""
    print(f"\n{'='*80}")
    print(f"{number}. {title}")
    print(f"{'='*80}")
    print(query)
    print()


# ============================================================================
# 1. ファイル名からハッシュ値を検索する機能
# ============================================================================
query1 = Query()
query1.add("aid", "2e5445246a35d55")
query1.add("FileName", "malware.exe")
query1.have("SHA256HashData")
query1.select([
    "timestamp", "aid", "#event_simpleName", "FilePath",
    "FileName", "SHA256HashData"
])
print_query("1", "ファイル名からハッシュ値を検索", query1)


# ============================================================================
# 2. ファイル名から、そのファイルを作成したプロセスを検索する機能
# ============================================================================
query2 = Query()
query2.add("aid", "2e5445246a35d55")
query2.add("FileName", "suspicious.dll")
query2.contain("#event_simpleName", "Written")
query2.select([
    "timestamp", "aid", "#event_simpleName", "FilePath", "FileName",
    "ContextProcessId", "ContextBaseFileName", "ContextImageFileName"
])
print_query("2", "ファイル名から、そのファイルを作成したプロセスを検索", query2)


# ============================================================================
# 3. ハッシュ値から、そのファイルを作成したプロセスを検索する機能
# ============================================================================
query3 = Query()
query3.add("aid", "2e5445246a35d55")
query3.add("SHA256HashData", "abc123def456...")
query3.contain("#event_simpleName", "Written")
query3.select([
    "timestamp", "aid", "#event_simpleName", "FilePath", "FileName",
    "ContextProcessId", "ContextBaseFileName", "ContextImageFileName"
])
print_query("3", "ハッシュ値から、そのファイルを作成したプロセスを検索", query3)


# ============================================================================
# 4. ファイル名から、そのファイルを実行したプロセスを検索する機能
# ============================================================================
query4 = Query()
query4.add("aid", "2e5445246a35d55")
query4.contain("#event_simpleName", "ProcessRollup2")

# サブクエリ: FileName=ファイル名 OR CommandLineにファイル名を含む
sub_query4 = Query(operator="OR")
sub_query4.add("FileName", "cmd.exe")
sub_query4.contain("CommandLine", "cmd.exe")

query4.add_subquery(sub_query4)
query4.select([
    "timestamp", "aid", "FilePath", "FileName", "TargetProcessId",
    "CommandLine", "ParentBaseFileName", "ParentProcessId"
])
print_query("4", "ファイル名から、そのファイルを実行したプロセスを検索", query4)


# ============================================================================
# 5. ハッシュ値から、そのファイルを実行したプロセスを検索する機能
# ============================================================================
query5 = Query()
query5.add("aid", "2e5445246a35d55")
query5.add("SHA256HashData", "abc123def456...")
query5.contain("#event_simpleName", "ProcessRollup2")
query5.select([
    "timestamp", "aid", "FilePath", "FileName", "TargetProcessId",
    "CommandLine", "ParentBaseFileName", "ParentProcessId"
])
print_query("5", "ハッシュ値から、そのファイルを実行したプロセスを検索", query5)


# ============================================================================
# 6. ファイル名から、そのファイルの中身が記録されたログを検索する機能
# ============================================================================
query6 = Query()
query6.add("aid", "2e5445246a35d55")
query6.add("FileName", "script.ps1")
query6.have("ScriptContent")
query6.select([
    "timestamp", "aid", "#event_simpleName", "FileName",
    "FilePath", "SHA256HashData"
])
print_query("6", "ファイル名から、そのファイルの中身が記録されたログを検索", query6)


# ============================================================================
# 7. ファイル名から、そのファイルがコマンドラインに入るプロセスを検索する機能
# ============================================================================
query7 = Query()
query7.add("aid", "2e5445246a35d55")
query7.contain("#event_simpleName", "ProcessRollup2")
query7.contain("CommandLine", "malware.exe")
query7.select([
    "timestamp", "aid", "FilePath", "FileName", "TargetProcessId",
    "CommandLine", "ParentBaseFileName", "ParentProcessId"
])
print_query("7", "ファイル名から、そのファイルがコマンドラインに入るプロセスを検索", query7)


# ============================================================================
# 8. ファイル名から、そのファイルをロードしているプロセスを検索する機能
# ============================================================================
query8 = Query()
query8.add("aid", "2e5445246a35d55")
query8.add("#event_simpleName", "ClassifiedModuleLoad")
query8.add("FileName", "kernel32.dll")
query8.select([
    "timestamp", "aid", "FilePath", "FileName", "TargetProcessId",
    "CommandLine", "ParentBaseFileName", "ParentProcessId"
])
print_query("8", "ファイル名から、そのファイルをロードしているプロセスを検索", query8)


# ============================================================================
# 9. ハッシュ値から、そのファイルをロードしているプロセスを検索する機能
# ============================================================================
query9 = Query()
query9.add("aid", "2e5445246a35d55")
query9.add("#event_simpleName", "ClassifiedModuleLoad")
query9.add("SHA256HashData", "abc123def456...")
query9.select([
    "timestamp", "aid", "FilePath", "FileName", "TargetProcessId",
    "CommandLine", "ParentBaseFileName", "ParentProcessId"
])
print_query("9", "ハッシュ値から、そのファイルをロードしているプロセスを検索", query9)


# ============================================================================
# 10. explorer.exeから実行されているプロセスの一覧を取得する機能
# ============================================================================
query10 = Query()
query10.add("aid", "2e5445246a35d55")
query10.contain("#event_simpleName", "ProcessRollup2")
query10.add("ParentBaseFileName", "explorer.exe")
query10.select([
    "timestamp", "aid", "FilePath", "FileName", "TargetProcessId",
    "CommandLine", "ParentBaseFileName", "ParentProcessId"
])
print_query("10", "explorer.exeから実行されているプロセスの一覧を取得", query10)


# ============================================================================
# 11. ファイル名から、ダウンロード元URLを特定する機能
# ============================================================================
query11 = Query()
query11.add("aid", "2e5445246a35d55")
query11.add("FileName", "malware.exe")

# サブクエリ: HostUrl または ReferrerUrl を持つ
sub_query11 = Query(operator="OR")
sub_query11.have("HostUrl")
sub_query11.have("ReferrerUrl")

query11.add_subquery(sub_query11)
query11.select([
    "timestamp", "aid", "#event_simpleName", "FilePath", "FileName",
    "HostUrl", "ReferrerUrl", "ContextProcessId", "ContextBaseFileName",
    "ContextImageFileName"
])
print_query("11", "ファイル名から、ダウンロード元URLを特定", query11)


# ============================================================================
# 12. ハッシュ値から、ダウンロード元URLを特定する機能
# ============================================================================
query12 = Query()
query12.add("aid", "2e5445246a35d55")
query12.add("SHA256HashData", "abc123def456...")

# サブクエリ: HostUrl または ReferrerUrl を持つ
sub_query12 = Query(operator="OR")
sub_query12.have("HostUrl")
sub_query12.have("ReferrerUrl")

query12.add_subquery(sub_query12)
query12.select([
    "timestamp", "aid", "#event_simpleName", "FilePath", "FileName",
    "HostUrl", "ReferrerUrl", "ContextProcessId", "ContextBaseFileName",
    "ContextImageFileName"
])
print_query("12", "ハッシュ値から、ダウンロード元URLを特定", query12)


# ============================================================================
# 13. 圧縮ファイルを作成もしくはオープンしているプロセスを検索する機能
# ============================================================================
query13 = Query(operator="AND")
query13.add("aid", "2e5445246a35d55")

# 圧縮ファイル条件をサブクエリとして追加
compressed_query = Query(operator="OR")
compressed_query.regex("FileName", r".+\.(zip|rar|7z|tar|gz|bz2|xz|lzh|sitx|dmg|iso|jar|apk)$")
compressed_query.regex("CommandLine", r".+\.(zip|rar|7z|tar|gz|bz2|xz|lzh|sitx|dmg|iso|jar|apk)")

query13.add_subquery(compressed_query)

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
query13.case(case1, case2)
query13.select([
    "timestamp", "aid", "#event_simpleName",
    "ProcessName", "ProcessId", "CompressedFile", "CommandLine"
])
print_query("13", "圧縮ファイルを作成もしくはオープンしているプロセスを検索", query13)


# ============================================================================
# 14. プロセスIDから、プロセスの起動ログを検索する機能
# ============================================================================
query14 = Query()
query14.add("aid", "2e5445246a35d55")
query14.add("TargetProcessId", "40612979432")
query14.select([
    "timestamp", "aid", "FilePath", "FileName", "TargetProcessId",
    "CommandLine", "ParentBaseFileName", "ParentProcessId"
])
print_query("14", "プロセスIDから、プロセスの起動ログを検索", query14)


print("="*80)
print("すべてのクエリ例の生成が完了しました")
print("="*80)
