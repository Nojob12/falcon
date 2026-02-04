"""
CrowdStrike Falcon Query - Case Statement Test

case文の動作テスト
"""
import sys
sys.path.insert(0, '/Users/nojob/WorkSpace/falcon')

import importlib.util
spec = importlib.util.spec_from_file_location('query', '/Users/nojob/WorkSpace/falcon/falcon/query.py')
query_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(query_module)

Query = query_module.Query
CaseCondition = query_module.CaseCondition


print("=" * 80)
print("Case Statement Test Examples")
print("=" * 80)

# Example 1: Basic case statement (from user's original example)
print("\n1. Basic case statement:")
print("-" * 80)

case1 = CaseCondition().when(
    Query().add("#event_simpleName", "ProcessRollup2")
).then_rename("ProcessId", "ContextProcessId")

case2 = CaseCondition().when(
    Query().add("#event_simpleName", "***")
).then_rename("ProcessId", "TargetProcessId")

query1 = Query()
query1.add("aid", "12345")
query1.case(case1, case2)
query1.select(["aid", "ProcessId"])

print(query1)
print()


# Example 2: Case with multiple actions
print("\n2. Case with multiple actions per condition:")
print("-" * 80)

case3 = CaseCondition().when(
    Query().add("EventType", "FileCreated")
).then_rename("Action", "EventType").then_set("Severity", "High")

case4 = CaseCondition().when(
    Query().add("EventType", "FileDeleted")
).then_rename("Action", "EventType").then_set("Severity", "Low")

query2 = Query()
query2.add("aid", "67890")
query2.case(case3, case4)
query2.select(["aid", "Action", "Severity"])

print(query2)
print()


# Example 3: Complex case with rename and select
print("\n3. Complex query with rename + case + select:")
print("-" * 80)

case5 = CaseCondition().when(
    Query().contain("#event_simpleName", "Process")
).then_rename("PID", "TargetProcessId")

case6 = CaseCondition().when(
    Query().contain("#event_simpleName", "Network")
).then_set("Category", "Network Activity")

query3 = Query()
query3.add("aid", "2e5445246a35d55")
query3.contain("#event_simpleName", "Rollup")
query3.rename("EventName", "#event_simpleName")
query3.case(case5, case6)
query3.select(["timestamp", "aid", "EventName", "PID", "Category"])

print(query3)
print()

print("=" * 80)
print("All case statement tests completed successfully!")
print("=" * 80)
