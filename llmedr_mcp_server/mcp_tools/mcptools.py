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
                    "process_name": first_result.get("ProcessName", ""),
                    "process_path": first_result.get("ProcessPath", ""),
                    "hash_value": first_result.get("SHA256HashData", ""),
                    "process_id": first_result.get("ProcessId", process_id),
                    "command_line": first_result.get("CommandLine", ""),
                    "parent_process_name": first_result.get("ParentProcessName", ""),
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

        # ========================================
        # getScriptContentByFileName: スクリプト内容取得ツール
        # ========================================
        @mcp.tool()
        async def getScriptContentByFileName(
            customer_id: str,
            file_name: str,
            host_id: Optional[str] = None,
            search_period: str = "7d"
        ) -> dict:
            """
            Retrieve script content from CrowdStrike by filename.

            Use this tool to extract the actual script content of suspicious files,
            such as PowerShell scripts, batch files, or shell scripts. This is essential
            for malware analysis and understanding what commands were executed on endpoints.

            Args:
                customer_id: Customer/tenant identifier (e.g., "customer_001")
                file_name: Target script filename to search for (e.g., "malicious.ps1", "backdoor.sh")
                host_id: Optional CrowdStrike Agent ID (aid). If None, searches all hosts
                search_period: Time range to search (default: "7d"). Format: "1h", "24h", "7d", "30d"

            Returns:
                Dict with total_results count and results list containing:
                host_id, file_path, script_content, timestamp per occurrence
            """
            try:
                # 1. ClientManagerを使って顧客コード毎のFalconClientを取得
                client = client_manager.get_client(customer_id)

                # 2. FileInvestigationクラスを使ってスクリプト内容を取得
                file_inv = FileInvestigation(client)
                script_details = await file_inv.get_script_content_by_filename(
                    filename=file_name,
                    aid=host_id,
                    start=search_period
                )

                if not script_details:
                    return {
                        "success": False,
                        "error": f"Script content not found for file: {file_name}"
                    }

                # 3. スクリプト内容を返す
                results = []
                for script_info in script_details:
                    results.append({
                        "host_id": script_info.get("aid", ""),
                        "file_path": script_info.get("FilePath", ""),
                        "file_name": script_info.get("FileName", file_name),
                        "script_content": script_info.get("ScriptContent", ""),
                        "timestamp": script_info.get("timestamp", "")
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

        # ========================================
        # getModuleLoaderProcessByFileName: ファイル名からモジュールローダープロセス取得ツール
        # ========================================
        @mcp.tool()
        async def getModuleLoaderProcessByFileName(
            customer_id: str,
            file_name: str,
            host_id: Optional[str] = None,
            search_period: str = "7d"
        ) -> dict:
            """
            Find processes that loaded a specific module/DLL file by filename.

            Use this tool to track which processes loaded suspicious DLLs or modules.
            This is critical for DLL injection detection, malware analysis, and
            understanding malicious code execution through legitimate processes.

            Args:
                customer_id: Customer/tenant identifier (e.g., "customer_001")
                file_name: Target module/DLL filename (e.g., "evil.dll", "injected_lib.so")
                host_id: Optional CrowdStrike Agent ID (aid). If None, searches all hosts
                search_period: Time range to search (default: "7d"). Format: "1h", "24h", "7d", "30d"

            Returns:
                Dict with total_results count and results list containing:
                host_id, process_id, process_name, file_path, timestamp per loader process
            """
            try:
                # 1. ClientManagerを使って顧客コード毎のFalconClientを取得
                client = client_manager.get_client(customer_id)

                # 2. FileInvestigationクラスを使ってモジュールローダープロセスを取得
                file_inv = FileInvestigation(client)
                loader_processes = await file_inv.get_module_loader(
                    filename=file_name,
                    aid=host_id,
                    start=search_period
                )

                if not loader_processes:
                    return {
                        "success": False,
                        "error": f"No processes found that loaded file: {file_name}"
                    }

                # 3. プロセス情報を返す
                results = []
                for process_info in loader_processes:
                    results.append({
                        "host_id": process_info.get("aid", ""),
                        "process_id": process_info.get("ProcessId", ""),
                        "process_name": process_info.get("ProcessName", ""),
                        "file_path": process_info.get("FilePath", ""),
                        "file_name": process_info.get("FileName", ""),
                        "hash_value": process_info.get("SHA256HashData", hash_value),
                        "timestamp": process_info.get("timestamp", "")
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

        # ========================================
        # getModuleLoaderProcessByHash: ハッシュ値からモジュールローダープロセス取得ツール
        # ========================================
        @mcp.tool()
        async def getModuleLoaderProcessByHash(
            customer_id: str,
            hash_value: str,
            host_id: Optional[str] = None,
            search_period: str = "7d"
        ) -> dict:
            """
            Find processes that loaded a specific module/DLL file by SHA256 hash.

            Use this tool to track which processes loaded malicious files identified by
            hash value. This is useful when you have a known malicious hash from threat
            intelligence and need to find all processes that loaded it across your environment.

            Args:
                customer_id: Customer/tenant identifier (e.g., "customer_001")
                hash_value: SHA256 hash of the target module/DLL
                host_id: Optional CrowdStrike Agent ID (aid). If None, searches all hosts
                search_period: Time range to search (default: "7d"). Format: "1h", "24h", "7d", "30d"

            Returns:
                Dict with total_results count and results list containing:
                host_id, process_id, process_name, file_path, file_name, timestamp per loader process
            """
            try:
                # 1. ClientManagerを使って顧客コード毎のFalconClientを取得
                client = client_manager.get_client(customer_id)

                # 2. FileInvestigationクラスを使ってモジュールローダープロセスを取得
                file_inv = FileInvestigation(client)
                loader_processes = await file_inv.get_module_loader(
                    hash_value=hash_value,
                    aid=host_id,
                    start=search_period
                )

                if not loader_processes:
                    return {
                        "success": False,
                        "error": f"No processes found that loaded file with hash: {hash_value}"
                    }

                # 3. プロセス情報を返す
                results = []
                for process_info in loader_processes:
                    results.append({
                        "host_id": process_info.get("aid", ""),
                        "process_id": process_info.get("ProcessId", ""),
                        "process_name": process_info.get("ProcessName", ""),
                        "file_path": process_info.get("FilePath", ""),
                        "file_name": process_info.get("FileName", ""),
                        "hash_value": process_info.get("SHA256HashData", hash_value),
                        "timestamp": process_info.get("timestamp", "")
                    })

                return {
                    "success": True,
                    "hash_value": hash_value,
                    "total_results": len(results),
                    "results": results
                }

            except Exception as e:
                return {
                    "success": False,
                    "error": str(e)
                }

        # ========================================
        # getFileCreationProcessByFileName: ファイル名からファイル作成プロセス取得ツール
        # ========================================
        @mcp.tool()
        async def getFileCreationProcessByFileName(
            customer_id: str,
            file_name: str,
            host_id: Optional[str] = None,
            search_period: str = "7d"
        ) -> dict:
            """
            Find processes that created a specific file by filename.

            Use this tool to identify which process created a suspicious file.
            This is essential for understanding malware dropper behavior, tracking
            file origins, and identifying initial infection vectors.

            Args:
                customer_id: Customer/tenant identifier (e.g., "customer_001")
                file_name: Target filename to search for (e.g., "malware.exe", "dropper.dll")
                host_id: Optional CrowdStrike Agent ID (aid). If None, searches all hosts
                search_period: Time range to search (default: "7d"). Format: "1h", "24h", "7d", "30d"

            Returns:
                Dict with total_results count and results list containing:
                host_id, process_id, process_name, command_line, file_path, timestamp per creator process
            """
            try:
                # 1. ClientManagerを使って顧客コード毎のFalconClientを取得
                client = client_manager.get_client(customer_id)

                # 2. FileInvestigationクラスを使ってファイル作成プロセスを取得
                file_inv = FileInvestigation(client)
                creator_processes = await file_inv.get_creator_process(
                    filename=file_name,
                    aid=host_id,
                    start=search_period
                )

                if not creator_processes:
                    return {
                        "success": False,
                        "error": f"No processes found that created file: {file_name}"
                    }

                # 3. プロセス情報を返す
                results = []
                for process_info in creator_processes:
                    results.append({
                        "host_id": process_info.get("aid", ""),
                        "process_id": process_info.get("ProcessId", ""),
                        "process_name": process_info.get("ProcessName", ""),
                        "file_path": process_info.get("FilePath", ""),
                        "file_name": process_info.get("FileName", ""),
                        "hash_value": process_info.get("SHA256HashData", hash_value),
                        "timestamp": process_info.get("timestamp", "")
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

        # ========================================
        # getFileCreationProcessByHash: ハッシュ値からファイル作成プロセス取得ツール
        # ========================================
        @mcp.tool()
        async def getFileCreationProcessByHash(
            customer_id: str,
            hash_value: str,
            host_id: Optional[str] = None,
            search_period: str = "7d"
        ) -> dict:
            """
            Find processes that created a specific file by SHA256 hash.

            Use this tool when you have a known malicious hash from threat intelligence
            and need to identify which processes created files with that hash. Essential
            for tracking malware droppers and initial compromise vectors.

            Args:
                customer_id: Customer/tenant identifier (e.g., "customer_001")
                hash_value: SHA256 hash of the target file
                host_id: Optional CrowdStrike Agent ID (aid). If None, searches all hosts
                search_period: Time range to search (default: "7d"). Format: "1h", "24h", "7d", "30d"

            Returns:
                Dict with total_results count and results list containing:
                host_id, process_id, process_name, command_line, file_path, file_name, timestamp per creator process
            """
            try:
                # 1. ClientManagerを使って顧客コード毎のFalconClientを取得
                client = client_manager.get_client(customer_id)

                # 2. FileInvestigationクラスを使ってファイル作成プロセスを取得
                file_inv = FileInvestigation(client)
                creator_processes = await file_inv.get_creator_process(
                    hash_value=hash_value,
                    aid=host_id,
                    start=search_period
                )

                if not creator_processes:
                    return {
                        "success": False,
                        "error": f"No processes found that created file with hash: {hash_value}"
                    }

                # 3. プロセス情報を返す
                results = []
                for process_info in creator_processes:
                    results.append({
                        "host_id": process_info.get("aid", ""),
                        "process_id": process_info.get("ProcessId", ""),
                        "process_name": process_info.get("ProcessName", ""),
                        "file_path": process_info.get("FilePath", ""),
                        "file_name": process_info.get("FileName", ""),
                        "hash_value": process_info.get("SHA256HashData", hash_value),
                        "timestamp": process_info.get("timestamp", "")
                    })

                return {
                    "success": True,
                    "hash_value": hash_value,
                    "total_results": len(results),
                    "results": results
                }

            except Exception as e:
                return {
                    "success": False,
                    "error": str(e)
                }

        # ========================================
        # getFileExecutionProcessByFileName: ファイル名からファイル実行プロセス取得ツール
        # ========================================
        @mcp.tool()
        async def getFileExecutionProcessByFileName(
            customer_id: str,
            file_name: str,
            host_id: Optional[str] = None,
            search_period: str = "7d"
        ) -> dict:
            """
            Find processes that executed a specific file by filename.

            Use this tool to track execution of suspicious executables or scripts.
            Critical for understanding malware execution patterns, lateral movement,
            and identifying compromised hosts where malicious files were run.

            Args:
                customer_id: Customer/tenant identifier (e.g., "customer_001")
                file_name: Target executable filename (e.g., "malware.exe", "backdoor.bat")
                host_id: Optional CrowdStrike Agent ID (aid). If None, searches all hosts
                search_period: Time range to search (default: "7d"). Format: "1h", "24h", "7d", "30d"

            Returns:
                Dict with total_results count and results list containing:
                host_id, process_id, process_name, command_line, file_path, parent_process, timestamp per execution
            """
            try:
                # 1. ClientManagerを使って顧客コード毎のFalconClientを取得
                client = client_manager.get_client(customer_id)

                # 2. FileInvestigationクラスを使ってファイル実行プロセスを取得
                file_inv = FileInvestigation(client)
                executor_processes = await file_inv.get_executor_process(
                    filename=file_name,
                    aid=host_id,
                    start=search_period
                )

                if not executor_processes:
                    return {
                        "success": False,
                        "error": f"No processes found that executed file: {file_name}"
                    }

                # 3. プロセス情報を返す
                results = []
                for process_info in executor_processes:
                    results.append({
                        "host_id": process_info.get("aid", ""),
                        "process_id": process_info.get("TargetProcessId", ""),
                        "process_name": process_info.get("ProcessName", ""),
                        "process_path": process_info.get("ProcessPath", ""),
                        "command_line": process_info.get("CommandLine", ""),
                        "hash_value": process_info.get("SHA256HashData", hash_value),
                        "parent_process_name": process_info.get("ParentProcessName", ""),
                        "parent_process_id": process_info.get("ParentProcessId", ""),
                        "timestamp": process_info.get("timestamp", "")
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

        # ========================================
        # getFileExecutionProcessByHash: ハッシュ値からファイル実行プロセス取得ツール
        # ========================================
        @mcp.tool()
        async def getFileExecutionProcessByHash(
            customer_id: str,
            hash_value: str,
            host_id: Optional[str] = None,
            search_period: str = "7d"
        ) -> dict:
            """
            Find processes that executed a specific file by SHA256 hash.

            Use this tool when you have a known malicious hash and need to find all
            executions across your environment. Essential for incident response and
            determining the scope of malware execution.

            Args:
                customer_id: Customer/tenant identifier (e.g., "customer_001")
                hash_value: SHA256 hash of the target executable
                host_id: Optional CrowdStrike Agent ID (aid). If None, searches all hosts
                search_period: Time range to search (default: "7d"). Format: "1h", "24h", "7d", "30d"

            Returns:
                Dict with total_results count and results list containing:
                host_id, process_id, process_name, command_line, file_path, parent_process, timestamp per execution
            """
            try:
                # 1. ClientManagerを使って顧客コード毎のFalconClientを取得
                client = client_manager.get_client(customer_id)

                # 2. FileInvestigationクラスを使ってファイル実行プロセスを取得
                file_inv = FileInvestigation(client)
                executor_processes = await file_inv.get_executor_process(
                    hash_value=hash_value,
                    aid=host_id,
                    start=search_period
                )

                if not executor_processes:
                    return {
                        "success": False,
                        "error": f"No processes found that executed file with hash: {hash_value}"
                    }

                # 3. プロセス情報を返す
                results = []
                for process_info in executor_processes:
                    results.append({
                        "host_id": process_info.get("aid", ""),
                        "process_id": process_info.get("TargetProcessId", ""),
                        "process_name": process_info.get("ProcessName", ""),
                        "process_path": process_info.get("ProcessPath", ""),
                        "command_line": process_info.get("CommandLine", ""),
                        "hash_value": process_info.get("SHA256HashData", hash_value),
                        "parent_process_name": process_info.get("ParentProcessName", ""),
                        "parent_process_id": process_info.get("ParentProcessId", ""),
                        "timestamp": process_info.get("timestamp", "")
                    })

                return {
                    "success": True,
                    "hash_value": hash_value,
                    "total_results": len(results),
                    "results": results
                }

            except Exception as e:
                return {
                    "success": False,
                    "error": str(e)
                }

        # ========================================
        # getDownloadUrlByFileName: ファイル名からダウンロード元URL取得ツール
        # ========================================
        @mcp.tool()
        async def getDownloadUrlByFileName(
            customer_id: str,
            file_name: str,
            host_id: Optional[str] = None,
            search_period: str = "7d"
        ) -> dict:
            """
            Find download source URLs for a specific file by filename.

            Use this tool to identify where suspicious files were downloaded from.
            Essential for threat intelligence gathering, identifying malicious domains,
            and understanding initial infection vectors via web downloads.

            Args:
                customer_id: Customer/tenant identifier (e.g., "customer_001")
                file_name: Target downloaded filename (e.g., "payload.exe", "malicious.zip")
                host_id: Optional CrowdStrike Agent ID (aid). If None, searches all hosts
                search_period: Time range to search (default: "7d"). Format: "1h", "24h", "7d", "30d"

            Returns:
                Dict with total_results count and results list containing:
                host_id, file_path, download_url, timestamp per download event
            """
            try:
                # 1. ClientManagerを使って顧客コード毎のFalconClientを取得
                client = client_manager.get_client(customer_id)

                # 2. FileInvestigationクラスを使ってダウンロード元URLを取得
                file_inv = FileInvestigation(client)
                download_details = await file_inv.get_download_url(
                    filename=file_name,
                    aid=host_id,
                    start=search_period
                )

                if not download_details:
                    return {
                        "success": False,
                        "error": f"No download URLs found for file: {file_name}"
                    }

                # 3. ログ情報を返す
                results = []
                for download_info in download_details:
                    results.append({
                        "timestamp": download_info.get("timestamp", ""),
                        "event_type": download_info.get("#event_simpleName", ""),
                        "host_id": download_info.get("aid", ""),
                        "file_path": download_info.get("FilePath", ""),
                        "file_name": download_info.get("FileName", file_name),
                        "hash_value": download_info.get("SHA256HashData", ""),
                        "download_url": download_info.get("SourceURL", ""),
                        "process_name": download_info.get("ProcessName", ""),
                        "process_id": download_info.get("ProcessId", "")
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

        # ========================================
        # getDownloadUrlByHash: ハッシュ値からダウンロード元URL取得ツール
        # ========================================
        @mcp.tool()
        async def getDownloadUrlByHash(
            customer_id: str,
            hash_value: str,
            host_id: Optional[str] = None,
            search_period: str = "7d"
        ) -> dict:
            """
            Find download source URLs for a specific file by SHA256 hash.

            Use this tool when you have a known malicious hash and need to identify
            all download sources. Critical for tracking C2 infrastructure, malicious
            domains, and understanding malware distribution networks.

            Args:
                customer_id: Customer/tenant identifier (e.g., "customer_001")
                hash_value: SHA256 hash of the downloaded file
                host_id: Optional CrowdStrike Agent ID (aid). If None, searches all hosts
                search_period: Time range to search (default: "7d"). Format: "1h", "24h", "7d", "30d"

            Returns:
                Dict with total_results count and results list containing:
                host_id, file_path, file_name, download_url, timestamp per download event
            """
            try:
                # 1. ClientManagerを使って顧客コード毎のFalconClientを取得
                client = client_manager.get_client(customer_id)

                # 2. FileInvestigationクラスを使ってダウンロード元URLを取得
                file_inv = FileInvestigation(client)
                download_details = await file_inv.get_download_url(
                    hash_value=hash_value,
                    aid=host_id,
                    start=search_period
                )

                if not download_details:
                    return {
                        "success": False,
                        "error": f"No download URLs found for file with hash: {hash_value}"
                    }

                # 3. ログ情報を返す
                results = []
                for download_info in download_details:
                    results.append({
                        "timestamp": download_info.get("timestamp", ""),
                        "event_type": download_info.get("#event_simpleName", ""),
                        "host_id": download_info.get("aid", ""),
                        "file_path": download_info.get("FilePath", ""),
                        "file_name": download_info.get("FileName", ""),
                        "hash_value": download_info.get("SHA256HashData", hash_value),
                        "download_url": download_info.get("SourceURL", ""),
                        "process_name": download_info.get("ProcessName", ""),
                        "process_id": download_info.get("ProcessId", "")
                    })

                return {
                    "success": True,
                    "hash_value": hash_value,
                    "total_results": len(results),
                    "results": results
                }

            except Exception as e:
                return {
                    "success": False,
                    "error": str(e)
                }

        # ========================================
        # getCompressedFileOperation: 圧縮ファイル操作取得ツール
        # ========================================
        @mcp.tool()
        async def getCompressedFileOperation(
            customer_id: str,
            host_id: str,
            search_period: str = "1d"
        ) -> dict:
            """
            Search for compressed file operations on a specific host.

            Use this tool to identify compressed file activity (zip, rar, 7z, tar, etc.)
            on a host. This is essential for detecting data exfiltration attempts,
            malware packaging, or suspicious file compression activities that may
            indicate attacker behavior.

            Args:
                customer_id: Customer/tenant identifier (e.g., "customer_001")
                host_id: CrowdStrike Agent ID (aid) of the target host
                search_period: Time range to search (default: "1d"). Format: "1h", "24h", "7d", "30d"

            Returns:
                Dict with total_results count and results list containing:
                host_id, file_name, file_path, process_name, command_line, timestamp per compressed file operation
            """
            try:
                # 1. ClientManagerを使って顧客コード毎のFalconClientを取得
                client = client_manager.get_client(customer_id)

                # 2. FileInvestigationクラスを使って圧縮ファイル操作ログを取得
                file_inv = FileInvestigation(client)
                compressed_operations = await file_inv.search_compressed_file_operations(
                    aid=host_id,
                    start=search_period
                )

                if not compressed_operations:
                    return {
                        "success": False,
                        "error": f"No compressed file operations found on host: {host_id}"
                    }

                # 3. ログ情報を返す
                results = []
                for operation in compressed_operations:
                    results.append({
                        "timestamp": operation.get("timestamp", ""),
                        "event_type": operation.get("#event_simpleName", ""),
                        "host_id": operation.get("aid", host_id),
                        "file_name": operation.get("ProcessName", ""),
                        "file_path": operation.get("ProcessId", ""),
                        "process_name": operation.get("CompressedFile", ""),
                        "command_line": operation.get("CommandLine", "")
                    })

                return {
                    "success": True,
                    "host_id": host_id,
                    "total_results": len(results),
                    "results": results
                }

            except Exception as e:
                return {
                    "success": False,
                    "error": str(e)
                }