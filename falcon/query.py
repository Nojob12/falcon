"""
CrowdStrike Falcon Query Builder

CrowdStrikeのイベント検索を行うためのクエリを作成するクラス

クエリ例:
    aid="2e5445246a35d55" AND ((ContextProcessId="40612979432") OR (TargetProcessId="40612979432" AND #event_simpleName="*ProcessRollup2*") OR (ParentProcessId="40612979432"))
    |  !in(#event_simpleName, values=["NetworkCloseIP4", "ImageHash", "UserIdentity"])
    | select([#event_simpleName, FileName, TargetProcessId])
"""
from __future__ import annotations
from typing import List


class CaseCondition:
    """
    case文の1つの条件を表すクラス

    使用例:
        >>> case1 = CaseCondition()
        >>> case1.when(Query().add("#event_simpleName", "ProcessRollup2"))
        >>> case1.then_rename("ProcessId", "ContextProcessId")
    """

    def __init__(self):
        """CaseConditionの初期化"""
        self._condition_query = None
        self._actions: List[str] = []

    def when(self, query: 'Query') -> 'CaseCondition':
        """
        条件を設定

        Args:
            query: 条件となるQueryオブジェクト

        Returns:
            自身のインスタンス（メソッドチェーン用）

        例:
            >>> case = CaseCondition()
            >>> case.when(Query().add("#event_simpleName", "ProcessRollup2"))
        """
        self._condition_query = query
        return self

    def then_rename(self, new_name: str, old_name: str) -> 'CaseCondition':
        """
        アクション: フィールド名を変更

        Args:
            new_name: 新しいフィールド名
            old_name: 元のフィールド名

        Returns:
            自身のインスタンス（メソッドチェーン用）

        例:
            >>> case = CaseCondition()
            >>> case.when(Query().add("#event_simpleName", "ProcessRollup2"))
            >>> case.then_rename("ProcessId", "ContextProcessId")
        """
        self._actions.append(f"{new_name} := rename({old_name})")
        return self

    def then_set(self, field: str, value: str) -> 'CaseCondition':
        """
        アクション: フィールドに値を設定

        Args:
            field: フィールド名
            value: 設定する値

        Returns:
            自身のインスタンス（メソッドチェーン用）

        例:
            >>> case = CaseCondition()
            >>> case.when(Query().add("Status", "active"))
            >>> case.then_set("Priority", "high")
        """
        self._actions.append(f'{field} := "{value}"')
        return self

    def build(self) -> str:
        """
        case条件をビルド

        Returns:
            ビルドされたcase条件文字列
        """
        if not self._condition_query or not self._actions:
            return ""

        condition = self._condition_query._build_conditions()
        actions = "| ".join(self._actions)
        return f"{condition} | {actions};"

    def __str__(self) -> str:
        """文字列表現"""
        return self.build()


class Query:
    """
    CrowdStrike FQLクエリを構築するクラス

    使用例:
        >>> query = Query()
        >>> query.add("aid", "2e5445246a35d55")
        >>> query.add("ContextProcessId", "40612979432")
        >>> print(query)
        aid="2e5445246a35d55" AND ContextProcessId="40612979432"
    """

    def __init__(self, operator: str = "AND"):
        """
        Queryの初期化

        Args:
            operator: 条件を結合する演算子 ("AND" または "OR")
        """
        self._conditions: List[str] = []
        self._operator = operator
        self._in_functions: List[str] = []
        self._rename_fields: List[tuple] = []  # (new_name, old_name)のタプルのリスト
        self._case_statements: List[str] = []
        self._select_fields: List[str] = []

    def add(self, field: str, value: str, exclude: bool = False) -> 'Query':
        """
        シンプルな等式条件を追加

        Args:
            field: フィールド名
            value: 値
            exclude: Falseの場合は"="、Trueの場合は"!="

        Returns:
            自身のインスタンス（メソッドチェーン用）

        例:
            >>> query = Query()
            >>> query.add("aid", "12345")
            >>> query.add("status", "active", exclude=True)
        """
        operator = "!=" if exclude else "="
        condition = f'{field}{operator}"{value}"'
        self._conditions.append(condition)
        return self

    def freeword(self, value: str) -> 'Query':
        """
        フリーワード検索条件を追加
        ログ内のどこかに指定した文字列が含まれているログを検索

        Args:
            value: 検索する値

        Returns:
            自身のインスタンス（メソッドチェーン用）

        例:
            >>> query = Query()
            >>> query.freeword("malware")
        """
        condition = f'"{value}"'
        self._conditions.append(condition)
        return self

    def have(self, field: str) -> 'Query':
        """
        指定したフィールドを持つログを検索

        Args:
            field: フィールド名
            exclude: Falseの場合は存在するもの、Trueの場合は存在しないもの

        Returns:
            自身のインスタンス（メソッドチェーン用）

        例:
            >>> query = Query()
            >>> query.have("FileName")
        """
        operator = "="
        condition = f'{field}{operator}/.+/'
        self._conditions.append(condition)
        return self

    def contain(self, field: str, value: str, exclude: bool = False) -> 'Query':
        """
        フィールドに文字列が含まれているログを検索（部分一致）

        Args:
            field: フィールド名
            value: 検索する値
            exclude: Falseの場合は含む、Trueの場合は含まない

        Returns:
            自身のインスタンス（メソッドチェーン用）

        例:
            >>> query = Query()
            >>> query.contain("FileName", "malware")
            >>> query.contain("event_simpleName", "ProcessRollup2", exclude=True)
        """
        operator = "!=" if exclude else "="
        condition = f'{field}{operator}"*{value}*"'
        self._conditions.append(condition)
        return self

    def endwith(self, field: str, value: str, exclude: bool = False) -> 'Query':
        """
        値が指定した文字列で終わるログを検索

        Args:
            field: フィールド名
            value: 検索する値
            exclude: Falseの場合は終わる、Trueの場合は終わらない

        Returns:
            自身のインスタンス（メソッドチェーン用）

        例:
            >>> query = Query()
            >>> query.endwith("FileName", ".exe")
            >>> query.endwith("event_simpleName", "ProcessRollup2", exclude=True)
        """
        operator = "!=" if exclude else "="
        condition = f'{field}{operator}"*{value}"'
        self._conditions.append(condition)
        return self

    def regex(self, field: str, pattern: str, exclude: bool = False) -> 'Query':
        """
        正規表現に合致するログを検索

        Args:
            field: フィールド名
            pattern: 正規表現パターン
            exclude: Falseの場合は合致する、Trueの場合は合致しない

        Returns:
            自身のインスタンス（メソッドチェーン用）

        例:
            >>> query = Query()
            >>> query.regex("FileName", ".*\\.exe$")
            >>> query.regex("CommandLine", "powershell.*-enc", exclude=True)
        """
        operator = "!=" if exclude else "="
        condition = f'{field}{operator}/{pattern}/'
        self._conditions.append(condition)
        return self

    def in_values(self, field: str, values: List[str], exclude: bool = False) -> 'Query':
        """
        指定したフィールドに対して複数の値をマッチ（in関数）
        パイプ（|）の後に関数として付与される

        Args:
            field: フィールド名
            values: 値のリスト
            exclude: Falseの場合はin、Trueの場合は!in

        Returns:
            自身のインスタンス（メソッドチェーン用）

        例:
            >>> query = Query()
            >>> query.add("aid", "12345")
            >>> query.in_values("event_simpleName", ["NetworkCloseIP4", "ImageHash"])
            >>> # 結果: aid="12345" | in(event_simpleName, values=["NetworkCloseIP4", "ImageHash"])
        """
        function_name = "!in" if exclude else "in"
        values_str = ", ".join(f'"{v}"' for v in values)
        in_function = f'{function_name}({field}, values=[{values_str}])'
        self._in_functions.append(in_function)
        return self

    def rename(self, new_name: str, old_name: str) -> 'Query':
        """
        指定したフィールドを別のフィールド名に置き換える
        パイプ（|）の後に関数として付与される

        Args:
            new_name: 新しいフィールド名
            old_name: 元のフィールド名

        Returns:
            自身のインスタンス（メソッドチェーン用）

        例:
            >>> query = Query()
            >>> query.add("aid", "1234fdfadg")
            >>> query.add("FileName", "malware.exe")
            >>> query.rename("ProcessId", "ContextProcessId")
            >>> query.select(["aid", "FileName", "ProcessId"])
            >>> # 結果: aid="1234fdfadg" AND FileName="malware.exe" | ProcessId := rename(ContextProcessId) | select([aid, FileName, ProcessId])
        """
        self._rename_fields.append((new_name, old_name))
        return self

    def case(self, *conditions: CaseCondition) -> 'Query':
        """
        case文を追加
        パイプ（|）の後に関数として付与される

        Args:
            *conditions: CaseConditionオブジェクトのリスト

        Returns:
            自身のインスタンス（メソッドチェーン用）

        例:
            >>> # case1: ProcessRollup2の場合
            >>> case1 = CaseCondition()
            >>> case1.when(Query().add("#event_simpleName", "ProcessRollup2"))
            >>> case1.then_rename("ProcessId", "ContextProcessId")
            >>>
            >>> # case2: それ以外の場合
            >>> case2 = CaseCondition()
            >>> case2.when(Query().contain("#event_simpleName", "*"))
            >>> case2.then_rename("ProcessId", "TargetProcessId")
            >>>
            >>> # メインクエリ
            >>> query = Query()
            >>> query.add("aid", "12345")
            >>> query.case(case1, case2)
            >>> query.select(["aid", "ProcessId"])
        """
        case_parts = []
        for condition in conditions:
            built_condition = condition.build()
            if built_condition:
                case_parts.append(built_condition)

        if case_parts:
            case_statement = "case {\n  " + "\n  ".join(case_parts) + "\n}"
            self._case_statements.append(case_statement)

        return self

    def select(self, fields: List[str]) -> 'Query':
        """
        出力する項目を絞る（select関数）

        Args:
            fields: 出力するフィールド名のリスト

        Returns:
            自身のインスタンス（メソッドチェーン用）

        例:
            >>> query = Query()
            >>> query.add("aid", "12345")
            >>> query.select(["event_simpleName", "FileName", "TargetProcessId"])
            >>> # 結果: aid="12345" | select([event_simpleName, FileName, TargetProcessId])
        """
        self._select_fields = fields
        return self

    def add_subquery(self, subquery: 'Query') -> 'Query':
        """
        サブクエリを条件として追加（括弧で囲まれる）

        Args:
            subquery: サブクエリのQueryインスタンス

        Returns:
            自身のインスタンス（メソッドチェーン用）

        例:
            >>> main_query = Query()
            >>> main_query.add("aid", "12345")
            >>>
            >>> sub_query = Query(operator="OR")
            >>> sub_query.add("ContextProcessId", "40612979432")
            >>> sub_query.add("TargetProcessId", "40612979432")
            >>>
            >>> main_query.add_subquery(sub_query)
            >>> # 結果: aid="12345" AND (ContextProcessId="40612979432" OR TargetProcessId="40612979432")
        """
        # サブクエリの条件部分のみを取得（in関数やselect関数は含めない）
        subquery_str = subquery._build_conditions()
        if subquery_str:
            condition = f"({subquery_str})"
            self._conditions.append(condition)
        return self

    def add_raw(self, condition: str) -> 'Query':
        """
        生のクエリ文字列を条件として追加

        Args:
            condition: クエリ条件文字列

        Returns:
            自身のインスタンス（メソッドチェーン用）

        例:
            >>> query = Query()
            >>> query.add_raw('ProcessId>1000')
        """
        if condition:
            self._conditions.append(condition)
        return self

    def set_operator(self, operator: str) -> 'Query':
        """
        条件を結合する演算子を設定

        Args:
            operator: "AND" または "OR"

        Returns:
            自身のインスタンス（メソッドチェーン用）
        """
        self._operator = operator
        return self

    def _build_conditions(self) -> str:
        """
        条件部分のみを構築（内部用）

        Returns:
            条件文字列
        """
        if not self._conditions:
            return ""
        return f" {self._operator} ".join(self._conditions)

    def _build_in_functions(self) -> str:
        """
        in関数部分を構築（内部用）

        Returns:
            in関数文字列
        """
        if not self._in_functions:
            return ""
        return " | ".join(self._in_functions)

    def _build_rename(self) -> str:
        """
        rename関数部分を構築（内部用）

        Returns:
            rename関数文字列（複数の場合は | で結合）
        """
        if not self._rename_fields:
            return ""
        rename_parts = []
        for new_name, old_name in self._rename_fields:
            rename_parts.append(f"{new_name} := rename({old_name})")
        return " | ".join(rename_parts)

    def _build_case(self) -> str:
        """
        case文部分を構築（内部用）

        Returns:
            case文文字列
        """
        if not self._case_statements:
            return ""
        # 複数のcase文がある場合は結合（通常は1つ）
        return " | ".join(self._case_statements)

    def _build_select(self) -> str:
        """
        select関数部分を構築（内部用）

        Returns:
            select関数文字列
        """
        if not self._select_fields:
            return ""
        fields_str = ", ".join(self._select_fields)
        return f"select([{fields_str}])"

    def build(self) -> str:
        """
        最終的なクエリ文字列を構築

        Returns:
            完全なクエリ文字列

        例:
            >>> query = Query()
            >>> query.add("aid", "12345")
            >>> query.in_values("event_simpleName", ["NetworkCloseIP4"], match=False)
            >>> query.select(["FileName"])
            >>> result = query.build()
            >>> # 結果: aid="12345" | !in(event_simpleName, values=["NetworkCloseIP4"]) | select([FileName])
        """
        parts = []

        # 条件部分
        conditions = self._build_conditions()
        if conditions:
            parts.append(conditions)

        # in関数部分
        in_functions = self._build_in_functions()
        if in_functions:
            parts.append(in_functions)

        # rename関数部分
        rename_part = self._build_rename()
        if rename_part:
            parts.append(rename_part)

        # case文部分
        case_part = self._build_case()
        if case_part:
            parts.append(case_part)

        # select関数部分
        select_part = self._build_select()
        if select_part:
            parts.append(select_part)

        # パイプで結合
        if len(parts) == 1:
            return parts[0]
        elif len(parts) > 1:
            # 最初の部分は通常の条件、残りはパイプで結合
            result = parts[0]
            for part in parts[1:]:
                result += f" | {part}"
            return result

        return ""

    def __str__(self) -> str:
        """
        文字列表現（クエリをビルド）

        Returns:
            完全なクエリ文字列
        """
        return self.build()

    def __repr__(self) -> str:
        """
        開発者向け文字列表現

        Returns:
            Queryオブジェクトの情報
        """
        return f"Query(conditions={len(self._conditions)}, operator={self._operator})"

    def clear(self) -> 'Query':
        """
        すべての条件をクリア

        Returns:
            自身のインスタンス（メソッドチェーン用）
        """
        self._conditions.clear()
        self._in_functions.clear()
        self._rename_fields.clear()
        self._case_statements.clear()
        self._select_fields.clear()
        return self

    def is_empty(self) -> bool:
        """
        クエリが空かどうかを判定

        Returns:
            空の場合True
        """
        return (not self._conditions and
                not self._in_functions and
                not self._rename_fields and
                not self._case_statements and
                not self._select_fields)
