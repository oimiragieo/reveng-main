from __future__ import annotations

import json
import py_compile
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_SAMPLES = REPO_ROOT / "test_samples"


def build_python_bytecode() -> Path:
    source_path = TEST_SAMPLES / "sample_app.py"
    output_path = TEST_SAMPLES / "sample_app.pyc"
    py_compile.compile(str(source_path), cfile=str(output_path), doraise=True)
    return output_path


def build_python_zipapp() -> Path:
    source_path = TEST_SAMPLES / "sample_app.py"
    output_path = TEST_SAMPLES / "sample_app.pyz"
    source_text = source_path.read_text(encoding="utf-8")
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("__main__.py", source_text)
        archive.writestr(
            "pkg/helpers.py",
            "def helper() -> str:\n    return 'helper-from-zipapp'\n",
        )
    return output_path


def build_java_jar() -> Path:
    class_path = TEST_SAMPLES / "HelloWorld.class"
    output_path = TEST_SAMPLES / "HelloWorld.jar"
    manifest = "\n".join(
        [
            "Manifest-Version: 1.0",
            "Main-Class: HelloWorld",
            "",
        ]
    )
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("META-INF/MANIFEST.MF", manifest)
        archive.write(class_path, arcname="HelloWorld.class")
    return output_path


def main() -> int:
    TEST_SAMPLES.mkdir(parents=True, exist_ok=True)
    outputs = {
        "python_bytecode": str(build_python_bytecode()),
        "python_zipapp": str(build_python_zipapp()),
        "java_jar": str(build_java_jar()),
    }
    print(json.dumps(outputs, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
