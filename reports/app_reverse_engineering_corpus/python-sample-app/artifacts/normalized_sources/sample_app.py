import argparse
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", default="world")
    args = parser.parse_args()
    Path("sample_output.txt").write_text(f"hello {args.name}", encoding="utf-8")


if __name__ == "__main__":
    main()
