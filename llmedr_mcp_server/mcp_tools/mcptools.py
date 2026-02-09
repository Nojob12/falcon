"""
CrowdStrike MCP Tools

FastMCPを使用したCrowdStrike調査ツールの実装
"""
import sys
sys.path.insert(0, '/Users/nojob/WorkSpace/falcon')

from typing import Any, Optional
from llmedr_mcp_server.investigator.crowdstrike import (
    AlertInvestigation,
    ProcessInvestigation,
    FileInvestigation
)


class MCPTool(ToolBase):
    def register(self, mcp: FastMCP, client_manager: Any):

        # ========================================
        # getAlert: アラート情報取得ツール
        # ========================================
        @mcp.tool()
        async def getAlert(customer_id: str, alert_id: str) -> dict:
            """
            Retrieve detailed information about a CrowdStrike security alert.

            Use this tool when you need to investigate a specific security alert,
            including associated file information, malware details, and related processes.
            This is typically used as a starting point for incident investigation.

            Args:
                customer_id: Customer/tenant identifier (e.g., "customer_001")
                alert_id: Unique CrowdStrike alert identifier

            Returns:
                Dict containing alert details: description, file_name, file_path,
                hash_value (SHA256), process_id, and success status
            """
            try:
                # 1. ClientManagerを使って顧客コード毎のFalconClientを取得
                client = client_manager.get_client(customer_id)

                # 2. AlertInvestigationクラスを使ってアラート情報を取得
                alert_inv = AlertInvestigation(client)
                alert_details = await alert_inv.get_alert_details(alert_id)

                if not alert_details:
                    return {
                        "success": False,
                        "error": f"Alert not found: {alert_id}"
                    }

                # 3. アラート情報から応答内容を抽出して返す
                return {
                    "success": True,
                    "alert_id": alert_id,
                    "description": alert_details.get("description", ""),
                    "file_name": alert_details.get("file_name", ""),
                    "file_path": alert_details.get("file_path", ""),
                    "hash_value": alert_details.get("sha256", ""),
                    "process_id": alert_details.get("process_id", "")
                }

            except Exception as e:
                return {
                    "success": False,
                    "error": str(e)
                }

        # ========================================
        # getProcessInfoByProcessId: プロセス情報取得ツール
        # ========================================
        @mcp.tool()
        async def getProcessInfoByProcessId(
            customer_id: str,
            host_id: str,
            process_id: str,
            search_period: str = "7d"
        ) -> dict:
            """
            Get comprehensive process execution details from CrowdStrike by process ID.

            Use this tool to investigate a specific process on a host, including its
            executable file, command line arguments, parent process, and file hash.
            Essential for understanding process behavior during security investigations.

            Args:
                customer_id: Customer/tenant identifier (e.g., "customer_001")
                host_id: CrowdStrike Agent ID (aid) of the target host
                process_id: Target process ID to investigate
                search_period: Time range to search (default: "7d"). Format: "1h", "24h", "7d", "30d"

            Returns:
                Dict with process details: host_id, file_name, file_path, hash_value,
                command_line, parent_process, timestamps, and total_results count
            """
            try:
                # 1. ClientManagerを使って顧客コード毎のFalconClientを取得
                client = client_manager.get_client(customer_id)

                # 2. ProcessInvestigationクラスを使ってプロセス情報を取得
                proc_inv = ProcessInvestigation(client)
                process_details = await proc_inv.get_process_details_by_pid(
                    process_id=process_id,
                    aid=host_id,
                    start=search_period
                )

                if not process_details:
                    return {
                        "success": False,
                        "error": f"Process not found: {process_id}"
                    }

                # 3. プロセス情報を返す（複数結果がある場合は最初の1件）
                first_result = process_details[0] if process_details else {}

                return {
                    "success": True,
                    "host_id": first_result.get("aid", host_id),
                    "file_name": first_result.get("FileName", ""),
                    "file_path": first_result.get("FilePath", ""),
                    "hash_value": first_result.get("SHA256HashData", ""),
                    "process_id": first_result.get("TargetProcessId", process_id),
                    "command_line": first_result.get("CommandLine", ""),
                    "parent_process": first_result.get("ParentBaseFileName", ""),
                    "parent_process_id": first_result.get("ParentProcessId", ""),
                    "timestamp": first_result.get("timestamp", ""),
                    "total_results": len(process_details)
                }

            except Exception as e:
                return {
                    "success": False,
                    "error": str(e)
                }

        # ========================================
        # getHashByFileName: ファイル名からハッシュ値取得ツール
        # ========================================
        @mcp.tool()
        async def getHashByFileName(
            customer_id: str,
            file_name: str,
            host_id: Optional[str] = None,
            search_period: str = "7d"
        ) -> dict:
            """
            Search for file hash values and metadata by filename across CrowdStrike endpoints.

            Use this tool to find SHA256 hashes of files by name, which is crucial for
            malware analysis, threat hunting, and identifying file presence across your
            environment. Can search a specific host or all hosts. Returns multiple results
            if the file appears on different hosts or at different times.

            Args:
                customer_id: Customer/tenant identifier (e.g., "customer_001")
                file_name: Target filename to search for (e.g., "malware.exe", "suspicious.dll")
                host_id: Optional CrowdStrike Agent ID (aid). If None, searches all hosts
                search_period: Time range to search (default: "7d"). Format: "1h", "24h", "7d", "30d"

            Returns:
                Dict with file_name, total_results count, and results list containing:
                host_id, file_path, hash_value (SHA256), timestamp, event_type per occurrence
            """
            try:
                # 1. ClientManagerを使って顧客コード毎のFalconClientを取得
                client = client_manager.get_client(customer_id)

                # 2. FileInvestigationクラスを使ってハッシュ情報を取得
                file_inv = FileInvestigation(client)
                file_details = await file_inv.get_hash_by_filename(
                    filename=file_name,
                    aid=host_id,
                    start=search_period
                )

                if not file_details:
                    return {
                        "success": False,
                        "error": f"File not found: {file_name}"
                    }

                # 3. ハッシュ情報を返す
                results = []
                for file_info in file_details:
                    results.append({
                        "host_id": file_info.get("aid", ""),
                        "file_path": file_info.get("FilePath", ""),
                        "file_name": file_info.get("FileName", file_name),
                        "hash_value": file_info.get("SHA256HashData", ""),
                        "timestamp": file_info.get("timestamp", ""),
                        "event_type": file_info.get("#event_simpleName", "")
                    })

                return {
                    "success": True,
                    "file_name": file_name,
                    "total_results": len(results),
                    "results": results
                }

            except Exception as e:
                return {
                    "success": False,
                    "error": str(e)
                }

        # 注意: 戻り値は不要です（デコレータが勝手にmcpに登録してくれるため）
