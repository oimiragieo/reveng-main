"""
Database MCP Server
===================

Provides database query and management capabilities via MCP.
Supports SQLite and can be extended for PostgreSQL, MySQL, etc.
"""

import asyncio
import os
import sqlite3
from typing import Any, Dict, List

from ..server import MCPServer, MCPTool


class DatabaseMCPServer(MCPServer):
    """
    Database MCP Server.

    Provides tools for SQL database operations including:
    - Execute queries (SELECT, INSERT, UPDATE, DELETE)
    - Schema inspection
    - Table listing
    - Query optimization

    Example:
        ```python
        # Run as MCP server
        server = DatabaseMCPServer(db_path="./data/analysis.db")
        await server.start(StdioTransport())
        ```

    Environment Variables:
        DB_PATH: Path to SQLite database file (default: analysis.db)
        DB_READONLY: Whether to open database in read-only mode (default: false)
    """

    def __init__(self, db_path: str = None):
        super().__init__("database-mcp", "1.0.0")

        # Get database path from environment or parameter
        self.db_path = db_path or os.getenv("DB_PATH", "analysis.db")
        self.readonly = os.getenv("DB_READONLY", "false").lower() == "true"

        # Initialize database connection
        self.db = None
        self._init_database()

        # Register tools
        self.register_tool(
            MCPTool(
                name="query_db",
                description="Execute a SQL query on the database",
                input_schema={
                    "type": "object",
                    "properties": {
                        "sql": {"type": "string", "description": "SQL query to execute"},
                        "params": {
                            "type": "array",
                            "description": "Query parameters for prepared statements",
                            "items": {"type": "string"},
                        },
                    },
                    "required": ["sql"],
                },
                handler=self.query_db,
            )
        )

        self.register_tool(
            MCPTool(
                name="list_tables",
                description="List all tables in the database",
                input_schema={"type": "object", "properties": {}},
                handler=self.list_tables,
            )
        )

        self.register_tool(
            MCPTool(
                name="describe_table",
                description="Get schema information for a table",
                input_schema={
                    "type": "object",
                    "properties": {
                        "table_name": {
                            "type": "string",
                            "description": "Name of the table to describe",
                        }
                    },
                    "required": ["table_name"],
                },
                handler=self.describe_table,
            )
        )

    def _init_database(self):
        """Initialize database connection"""
        uri = f"file:{self.db_path}?mode=ro" if self.readonly else self.db_path
        self.db = sqlite3.connect(uri, uri=self.readonly)
        self.db.row_factory = sqlite3.Row

    async def query_db(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a SQL query"""
        sql = args.get("sql", "")
        params = args.get("params", [])

        try:
            cursor = self.db.cursor()
            cursor.execute(sql, params)

            # For SELECT queries, return results
            if sql.strip().upper().startswith("SELECT"):
                rows = cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]

                return {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Query returned {len(rows)} rows\n\n"
                            + f"Columns: {', '.join(columns)}\n\n"
                            + "\n".join(
                                [
                                    " | ".join([str(row[col]) for col in columns])
                                    for row in rows[:100]  # Limit to 100 rows
                                ]
                            ),
                        }
                    ],
                    "rows": [dict(row) for row in rows],
                    "row_count": len(rows),
                }

            # For other queries (INSERT, UPDATE, DELETE), return affected rows
            else:
                self.db.commit()
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Query executed successfully. Rows affected: {cursor.rowcount}",
                        }
                    ],
                    "rows_affected": cursor.rowcount,
                }

        except sqlite3.Error as e:
            return {
                "content": [{"type": "text", "text": f"Database error: {str(e)}"}],
                "error": str(e),
            }

    async def list_tables(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """List all tables in the database"""
        try:
            cursor = self.db.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            tables = [row[0] for row in cursor.fetchall()]

            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Found {len(tables)} tables:\n\n"
                        + "\n".join([f"  • {t}" for t in tables]),
                    }
                ],
                "tables": tables,
            }

        except sqlite3.Error as e:
            return {
                "content": [{"type": "text", "text": f"Database error: {str(e)}"}],
                "error": str(e),
            }

    async def describe_table(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get schema information for a table"""
        table_name = args.get("table_name", "")

        try:
            cursor = self.db.cursor()
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()

            if not columns:
                return {"content": [{"type": "text", "text": f"Table '{table_name}' not found"}]}

            schema_text = f"Table: {table_name}\n\n"
            schema_text += "Columns:\n"
            for col in columns:
                col_info = f"  • {col[1]} ({col[2]})"
                if col[3]:  # NOT NULL
                    col_info += " NOT NULL"
                if col[5]:  # PRIMARY KEY
                    col_info += " PRIMARY KEY"
                schema_text += col_info + "\n"

            return {
                "content": [{"type": "text", "text": schema_text}],
                "columns": [
                    {
                        "name": col[1],
                        "type": col[2],
                        "not_null": bool(col[3]),
                        "primary_key": bool(col[5]),
                    }
                    for col in columns
                ],
            }

        except sqlite3.Error as e:
            return {
                "content": [{"type": "text", "text": f"Database error: {str(e)}"}],
                "error": str(e),
            }

    async def read_resource(self, uri: str) -> Dict[str, Any]:
        """Read a database resource (not implemented for database MCP)"""
        return {"uri": uri, "mimeType": "text/plain", "text": "Database resources not supported"}

    async def get_prompt(self, name: str, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get a prompt (not implemented for database MCP)"""
        return []

    def __del__(self):
        """Close database connection on cleanup"""
        if self.db:
            self.db.close()


# Main entry point for running as MCP server
if __name__ == "__main__":
    from ..transports import StdioTransport

    async def main():
        server = DatabaseMCPServer()
        transport = StdioTransport()
        await server.start(transport)

    asyncio.run(main())
