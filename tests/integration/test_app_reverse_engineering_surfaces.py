from __future__ import annotations

import asyncio
from pathlib import Path

from reveng.api import REVENGAPI
from reveng.agent_sdk.mcp.servers.reveng_enterprise_server import REVENGEnterpriseServer
from reveng.agent_sdk.mcp.servers.reveng_server import REVENGMCPServer


REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_CONFIG = REPO_ROOT / ".reveng" / "app_reverse_engineering_corpus.json"


def test_api_runs_selected_app_corpus_entries(tmp_path: Path):
    api = REVENGAPI()

    report = api.run_app_reverse_engineering_corpus(
        config_path=CORPUS_CONFIG,
        selected_names=["python-sample-app", "dotnet-sample-app"],
        output_dir=tmp_path / "api_corpus_out",
    )

    assert report["result_type"] == "app_reverse_engineering_corpus_report"
    assert report["summary"]["matrix_status"] == "pass"
    assert {row["name"] for row in report["rows"]} == {"python-sample-app", "dotnet-sample-app"}


def test_simple_mcp_runs_selected_app_corpus_entries(tmp_path: Path):
    server = REVENGMCPServer()

    result = asyncio.run(
        server.run_app_corpus(
            {
                "config_path": str(CORPUS_CONFIG),
                "entry_names": ["python-sample-app"],
                "output_dir": str(tmp_path / "simple_mcp_corpus_out"),
            }
        )
    )

    assert result["tool_name"] == "run_app_corpus"
    assert result["corpus_report"]["summary"]["matrix_status"] == "pass"
    assert result["corpus_report"]["rows"][0]["name"] == "python-sample-app"


def test_enterprise_mcp_runs_selected_app_corpus_entries(tmp_path: Path):
    server = REVENGEnterpriseServer(enable_rate_limiting=False, enable_audit_log=False)

    result = asyncio.run(
        server.run_app_corpus(
            {
                "config_path": str(CORPUS_CONFIG),
                "entry_names": ["dotnet-sample-app"],
                "output_dir": str(tmp_path / "enterprise_mcp_corpus_out"),
            }
        )
    )

    assert result["tool_name"] == "run_app_corpus"
    assert result["analysis_id"]
    assert result["corpus_report"]["summary"]["matrix_status"] == "pass"
    assert result["corpus_report"]["rows"][0]["name"] == "dotnet-sample-app"
