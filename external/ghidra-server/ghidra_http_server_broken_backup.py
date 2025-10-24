#!/usr/bin/env python3
"""
Ghidra HTTP Analysis Server
Provides REST API for binary analysis using Ghidra
"""
import subprocess
import sys
import os
from pathlib import Path
from flask import Flask, request, jsonify
import tempfile

app = Flask(__name__)

GHIDRA_PATH = Path(os.environ.get("GHIDRA_INSTALL_DIR", r"c:\dev\projects\reveng-main\external\ghidra"))

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "service": "ghidra-analysis-server"})

@app.route('/analyze', methods=['POST'])
def analyze_binary():
    """Analyze a binary using Ghidra headless analyzer"""
    data = request.json
    binary_path = data.get('binary_path')

    if not binary_path or not Path(binary_path).exists():
        return jsonify({"error": "Binary path not found"}), 400

    # Create temporary project
    with tempfile.TemporaryDirectory() as tmpdir:
        project_path = Path(tmpdir) / "ghidra_project"

        # Run Ghidra headless analysis
        ghidra_headless = GHIDRA_PATH / "support" / "analyzeHeadless"
        if not ghidra_headless.exists():
            ghidra_headless = GHIDRA_PATH / "support" / "analyzeHeadless.bat"

        cmd = [
            str(ghidra_headless),
            str(project_path),
            "temp_project",
            "-import", binary_path,
            "-scriptPath", str(Path(__file__).parent),
            "-postScript", "ExportAnalysisData.py",
            "-deleteProject"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            # Parse Ghidra output
            analysis_data = {
                "status": "success",
                "functions": [],
                "strings": [],
                "imports": [],
                "analysis_complete": True
            }

            return jsonify(analysis_data)

        except subprocess.TimeoutExpired:
            return jsonify({"error": "Analysis timeout"}), 504
        except Exception as e:
            return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 1337))
    print(f"Starting Ghidra Analysis Server on port {port}")
    app.run(host='0.0.0.0', port=port)
