"""Wave 2: enterprise MCP tools must dual-label MCP + proprietary annotations."""

from __future__ import annotations

from reveng.agent_sdk.mcp.servers.reveng_enterprise_server import REVENGEnterpriseServer

DENYLIST = {
    "generate_exploit": {"requires_policy_acknowledgement": True},
    "recompile_binary": {"requires_policy_acknowledgement": False},
}


def test_denylist_tools_dual_label_mcp_hints():
    srv = REVENGEnterpriseServer()
    for name, expect in DENYLIST.items():
        ann = srv.tools[name].to_dict().get("annotations") or {}
        assert ann.get("destructiveHint") is True, name
        assert ann.get("readOnlyHint") is False, name
        assert ann.get("openWorldHint") is True, name
        assert ann.get("risk_level") == "high", name
        assert (
            ann.get("requires_policy_acknowledgement") is expect["requires_policy_acknowledgement"]
        ), name


def test_non_denylist_high_risk_not_auto_labeled_destructive():
    """Wave 2 must not map every risk_level=high to destructiveHint."""
    srv = REVENGEnterpriseServer()
    ann = srv.tools["analyze_memory_dump"].to_dict().get("annotations") or {}
    assert ann.get("risk_level") == "high"
    assert "destructiveHint" not in ann
