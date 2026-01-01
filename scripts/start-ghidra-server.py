#!/usr/bin/env python3
"""
REVENG Ghidra Server Starter

This script automatically starts the Ghidra Analysis Server required for
native binary disassembly. It handles:
- Checking if the server is already running
- Starting the server in the background
- Verifying the server is healthy
- Providing clear error messages if Ghidra isn't installed

Usage:
    python scripts/start-ghidra-server.py [--port PORT] [--background]

    --port PORT      Port to run on (default: 13370)
    --background     Run in background mode
    --check          Only check if server is running
    --stop           Stop the running server

Author: REVENG Team
Version: 4.0.0
"""

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

DEFAULT_PORT = 13370
SERVER_URL = f"http://127.0.0.1:{DEFAULT_PORT}"
PID_FILE = Path(__file__).parent.parent / ".ghidra-server.pid"


def check_server_running(port: int = DEFAULT_PORT) -> bool:
    """Check if Ghidra Analysis Server is already running."""
    try:
        import requests
        response = requests.get(f"http://127.0.0.1:{port}/health", timeout=2)
        if response.status_code == 200:
            data = response.json()
            return data.get("status") == "healthy"
    except Exception:
        pass
    return False


def start_server(port: int = DEFAULT_PORT, background: bool = False) -> bool:
    """Start the Ghidra Analysis Server."""

    # Check if already running
    if check_server_running(port):
        print(f"✅ Ghidra Analysis Server already running on port {port}")
        return True

    print(f"Starting Ghidra Analysis Server on port {port}...")

    # Find the server module
    server_module = "reveng.server.ghidra_analysis_server"

    # Build command
    cmd = [sys.executable, "-m", server_module, "--port", str(port)]

    if background:
        # Start in background
        try:
            if os.name == 'nt':  # Windows
                process = subprocess.Popen(
                    cmd,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:  # Unix
                process = subprocess.Popen(
                    cmd,
                    start_new_session=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

            # Save PID
            with open(PID_FILE, "w") as f:
                f.write(str(process.pid))

            # Wait for server to start
            print("Waiting for server to start...")
            for i in range(10):
                time.sleep(1)
                if check_server_running(port):
                    print(f"✅ Ghidra Analysis Server started on port {port} (PID: {process.pid})")
                    return True
                print(f"   Waiting... ({i+1}/10)")

            print("❌ Server failed to start within timeout")
            return False

        except Exception as e:
            print(f"❌ Failed to start server: {e}")
            return False
    else:
        # Start in foreground (blocking)
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nServer stopped by user")
        return True


def stop_server() -> bool:
    """Stop the running Ghidra Analysis Server."""
    if not PID_FILE.exists():
        print("No PID file found - server may not be running")
        return False

    try:
        with open(PID_FILE, "r") as f:
            pid = int(f.read().strip())

        print(f"Stopping server (PID: {pid})...")

        if os.name == 'nt':  # Windows
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
        else:  # Unix
            os.kill(pid, signal.SIGTERM)

        # Wait for process to stop
        time.sleep(2)

        # Remove PID file
        PID_FILE.unlink(missing_ok=True)

        print("✅ Server stopped")
        return True

    except Exception as e:
        print(f"❌ Failed to stop server: {e}")
        PID_FILE.unlink(missing_ok=True)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="REVENG Ghidra Server Starter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start server in background
  python scripts/start-ghidra-server.py --background

  # Start server on custom port
  python scripts/start-ghidra-server.py --port 8080

  # Check if server is running
  python scripts/start-ghidra-server.py --check

  # Stop the server
  python scripts/start-ghidra-server.py --stop

Note: For native binary analysis (PE/ELF/Mach-O), the Ghidra server is REQUIRED.
      For Java/Python/C# files, no server is needed.
"""
    )

    parser.add_argument(
        "--port", "-p",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port to run on (default: {DEFAULT_PORT})"
    )
    parser.add_argument(
        "--background", "-b",
        action="store_true",
        help="Run in background mode"
    )
    parser.add_argument(
        "--check", "-c",
        action="store_true",
        help="Only check if server is running"
    )
    parser.add_argument(
        "--stop", "-s",
        action="store_true",
        help="Stop the running server"
    )

    args = parser.parse_args()

    if args.check:
        if check_server_running(args.port):
            print(f"✅ Ghidra Analysis Server is running on port {args.port}")
            sys.exit(0)
        else:
            print(f"❌ Ghidra Analysis Server is NOT running on port {args.port}")
            sys.exit(1)

    if args.stop:
        success = stop_server()
        sys.exit(0 if success else 1)

    # Start server
    success = start_server(args.port, args.background)

    if not success:
        print()
        print("=" * 70)
        print("TROUBLESHOOTING")
        print("=" * 70)
        print()
        print("1. Make sure REVENG is installed:")
        print("   pip install -e .")
        print()
        print("2. Check if Ghidra is installed:")
        print("   - Download from https://ghidra-sre.org/")
        print("   - Extract to a known location")
        print("   - Set GHIDRA_INSTALL_DIR environment variable")
        print()
        print("3. Try the external Ghidra HTTP server:")
        print("   cd external/ghidra-server")
        print("   python ghidra_http_server.py")
        print()
        print("4. For Java/Python/C# files, no server is needed:")
        print("   reveng analyze app.jar  # Works without Ghidra")
        print()
        sys.exit(1)


if __name__ == "__main__":
    main()
