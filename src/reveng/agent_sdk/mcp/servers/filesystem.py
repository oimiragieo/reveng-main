"""
Filesystem MCP Server
=====================

Provides enhanced file system operations via MCP.
"""

import asyncio
import os
from pathlib import Path
from typing import Any, Dict, List

from ..server import MCPResource, MCPServer, MCPTool


class FilesystemMCPServer(MCPServer):
    """
    Filesystem MCP Server.

    Provides tools for file operations including:
    - Read/write files
    - List directories
    - Search files
    - File metadata

    Example:
        ```python
        server = FilesystemMCPServer(root_path="/path/to/files")
        await server.start(StdioTransport())
        ```

    Environment Variables:
        ROOT_PATH: Root directory for file operations (default: current dir)
        ALLOW_WRITE: Allow file write operations (default: false)
    """

    def __init__(self, root_path: str = None):
        super().__init__("filesystem-mcp", "1.0.0")

        self.root_path = Path(root_path or os.getenv("ROOT_PATH", ".")).resolve()
        self.allow_write = os.getenv("ALLOW_WRITE", "false").lower() == "true"

        # Register tools
        self.register_tool(
            MCPTool(
                name="read_file",
                description="Read contents of a file",
                input_schema={
                    "type": "object",
                    "properties": {"path": {"type": "string", "description": "Path to file"}},
                    "required": ["path"],
                },
                handler=self.read_file,
            )
        )

        self.register_tool(
            MCPTool(
                name="list_directory",
                description="List contents of a directory",
                input_schema={
                    "type": "object",
                    "properties": {"path": {"type": "string", "description": "Path to directory"}},
                    "required": ["path"],
                },
                handler=self.list_directory,
            )
        )

        self.register_tool(
            MCPTool(
                name="search_files",
                description="Search for files by pattern",
                input_schema={
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Glob pattern (e.g., **/*.py)"}
                    },
                    "required": ["pattern"],
                },
                handler=self.search_files,
            )
        )

        if self.allow_write:
            self.register_tool(
                MCPTool(
                    name="write_file",
                    description="Write content to a file",
                    input_schema={
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "Path to file"},
                            "content": {"type": "string", "description": "File content"},
                        },
                        "required": ["path", "content"],
                    },
                    handler=self.write_file,
                )
            )

    def _resolve_path(self, path: str) -> Path:
        """Resolve and validate path within root"""
        full_path = (self.root_path / path).resolve()

        # Security: ensure path is within root
        if not str(full_path).startswith(str(self.root_path)):
            raise ValueError(f"Path '{path}' is outside root directory")

        return full_path

    async def read_file(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Read file contents"""
        try:
            path = self._resolve_path(args["path"])

            if not path.exists():
                return {"content": [{"type": "text", "text": f"File not found: {args['path']}"}]}

            content = path.read_text()
            return {"content": [{"type": "text", "text": content}], "size": len(content)}

        except Exception as e:
            return {"content": [{"type": "text", "text": f"Error reading file: {str(e)}"}]}

    async def list_directory(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """List directory contents"""
        try:
            path = self._resolve_path(args["path"])

            if not path.exists():
                return {
                    "content": [{"type": "text", "text": f"Directory not found: {args['path']}"}]
                }

            if not path.is_dir():
                return {"content": [{"type": "text", "text": f"Not a directory: {args['path']}"}]}

            entries = []
            for entry in sorted(path.iterdir()):
                entry_type = "dir" if entry.is_dir() else "file"
                size = entry.stat().st_size if entry.is_file() else 0
                entries.append({"name": entry.name, "type": entry_type, "size": size})

            text = f"Directory: {args['path']}\n\n"
            for entry in entries:
                icon = "📁" if entry["type"] == "dir" else "📄"
                text += f"{icon} {entry['name']}"
                if entry["type"] == "file":
                    text += f" ({entry['size']} bytes)"
                text += "\n"

            return {"content": [{"type": "text", "text": text}], "entries": entries}

        except Exception as e:
            return {"content": [{"type": "text", "text": f"Error listing directory: {str(e)}"}]}

    async def search_files(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Search for files matching pattern"""
        try:
            pattern = args["pattern"]
            matches = list(self.root_path.glob(pattern))

            # Convert to relative paths
            files = [str(f.relative_to(self.root_path)) for f in matches if f.is_file()]

            text = f"Found {len(files)} files matching '{pattern}':\n\n"
            text += "\n".join([f"  • {f}" for f in files[:100]])

            if len(files) > 100:
                text += f"\n\n... and {len(files) - 100} more"

            return {"content": [{"type": "text", "text": text}], "files": files}

        except Exception as e:
            return {"content": [{"type": "text", "text": f"Error searching files: {str(e)}"}]}

    async def write_file(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Write content to file"""
        if not self.allow_write:
            return {"content": [{"type": "text", "text": "Write operations are disabled"}]}

        try:
            path = self._resolve_path(args["path"])
            content = args["content"]

            # Create parent directories if needed
            path.parent.mkdir(parents=True, exist_ok=True)

            path.write_text(content)

            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Successfully wrote {len(content)} bytes to {args['path']}",
                    }
                ]
            }

        except Exception as e:
            return {"content": [{"type": "text", "text": f"Error writing file: {str(e)}"}]}

    async def read_resource(self, uri: str) -> Dict[str, Any]:
        """Read a file resource by URI"""
        # URI format: file:///path/to/file
        if uri.startswith("file://"):
            file_path = uri[7:]
            result = await self.read_file({"path": file_path})
            return {"uri": uri, "mimeType": "text/plain", "text": result["content"][0]["text"]}
        return {"uri": uri, "mimeType": "text/plain", "text": f"Unsupported URI scheme: {uri}"}

    async def get_prompt(self, name: str, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get a prompt (not implemented)"""
        return []


# Main entry point
if __name__ == "__main__":
    import sys

    from ..transports import StdioTransport

    async def main():
        server = FilesystemMCPServer()
        transport = StdioTransport()
        await server.start(transport)

    asyncio.run(main())
