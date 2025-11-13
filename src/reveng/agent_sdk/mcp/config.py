"""
MCP Configuration Management
============================

Load and manage MCP server configurations from .mcp.json files.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class MCPServerConfig:
    """Configuration for a single MCP server"""

    command: str
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    transport: str = "stdio"  # stdio, http, in-process
    enabled: bool = True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MCPServerConfig":
        """Create from dictionary"""
        return cls(
            command=data.get("command", ""),
            args=data.get("args", []),
            env=data.get("env", {}),
            transport=data.get("transport", "stdio"),
            enabled=data.get("enabled", True),
        )


@dataclass
class MCPConfig:
    """
    MCP configuration file format.

    The .mcp.json file configures which MCP servers to run and how.

    Example .mcp.json:
        ```json
        {
          "mcpServers": {
            "database": {
              "command": "python",
              "args": ["-m", "reveng.agent_sdk.mcp.servers.database"],
              "env": {
                "DB_PATH": "./data/analysis.db"
              },
              "transport": "stdio",
              "enabled": true
            },
            "filesystem": {
              "command": "python",
              "args": ["-m", "reveng.agent_sdk.mcp.servers.filesystem"],
              "env": {
                "ROOT_PATH": "/path/to/files"
              }
            }
          }
        }
        ```
    """

    servers: Dict[str, MCPServerConfig] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MCPConfig":
        """Create from dictionary"""
        servers = {}
        for name, server_data in data.get("mcpServers", {}).items():
            servers[name] = MCPServerConfig.from_dict(server_data)
        return cls(servers=servers)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "mcpServers": {
                name: {
                    "command": server.command,
                    "args": server.args,
                    "env": server.env,
                    "transport": server.transport,
                    "enabled": server.enabled,
                }
                for name, server in self.servers.items()
            }
        }

    def get_enabled_servers(self) -> Dict[str, MCPServerConfig]:
        """Get only enabled servers"""
        return {name: server for name, server in self.servers.items() if server.enabled}


def load_mcp_config(config_path: Optional[str] = None) -> MCPConfig:
    """
    Load MCP configuration from file.

    Args:
        config_path: Path to .mcp.json file. If None, searches for .mcp.json
                    in current directory, home directory, and ~/.config/

    Returns:
        MCPConfig object

    Example:
        ```python
        config = load_mcp_config()
        for name, server in config.get_enabled_servers().items():
            print(f"Server: {name}")
            print(f"  Command: {server.command} {' '.join(server.args)}")
        ```
    """
    # Search for config file if not provided
    if config_path is None:
        search_paths = [
            Path(".mcp.json"),
            Path.home() / ".mcp.json",
            Path.home() / ".config" / "mcp.json",
            Path.home() / ".config" / "reveng" / "mcp.json",
        ]

        for path in search_paths:
            if path.exists():
                config_path = str(path)
                break

    # Return empty config if no file found
    if config_path is None or not Path(config_path).exists():
        return MCPConfig()

    # Load and parse config file
    with open(config_path, "r") as f:
        data = json.load(f)

    # Expand environment variables in config
    data = _expand_env_vars(data)

    return MCPConfig.from_dict(data)


def save_mcp_config(config: MCPConfig, config_path: str):
    """
    Save MCP configuration to file.

    Args:
        config: MCPConfig object to save
        config_path: Path where to save the config file

    Example:
        ```python
        config = MCPConfig()
        config.servers["my-server"] = MCPServerConfig(
            command="python",
            args=["-m", "my_mcp_server"],
            env={"API_KEY": "secret"}
        )
        save_mcp_config(config, ".mcp.json")
        ```
    """
    # Create parent directory if needed
    Path(config_path).parent.mkdir(parents=True, exist_ok=True)

    # Write config to file
    with open(config_path, "w") as f:
        json.dump(config.to_dict(), f, indent=2)


def _expand_env_vars(data: Any) -> Any:
    """Recursively expand environment variables in config data"""
    if isinstance(data, dict):
        return {k: _expand_env_vars(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_expand_env_vars(v) for v in data]
    elif isinstance(data, str):
        return os.path.expandvars(data)
    else:
        return data
