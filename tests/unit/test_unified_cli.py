"""Tests for the unified CLI entry point."""

import sys

from reveng import cli


def test_create_parser_includes_core_commands():
    parser = cli.create_parser()
    subparsers_action = getattr(parser, "_subparsers")
    choices = subparsers_action._group_actions[0].choices

    expected = {"analyze", "serve", "ask", "ai", "triage", "generate-yara"}
    assert expected.issubset(set(choices.keys()))


def test_main_without_command_shows_help(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["reveng"])

    exit_code = cli.main()
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "usage:" in captured.out


def test_main_routes_to_analyze_handler(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["reveng", "analyze", "sample.bin"])

    called = {}

    def fake_handler(args):
        called["args"] = args
        return 0

    monkeypatch.setattr(cli, "handle_analyze_command", fake_handler)

    exit_code = cli.main()

    assert exit_code == 0
    assert called["args"].binary_path == "sample.bin"


def test_main_routes_to_serve_handler_with_defaults(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["reveng", "serve"])

    called = {}

    def fake_handler(args):
        called["args"] = args
        return 0

    monkeypatch.setattr(cli, "handle_serve_command", fake_handler)

    exit_code = cli.main()

    assert exit_code == 0
    assert called["args"].host == "localhost"
    assert called["args"].port == 3000
    assert called["args"].reload is False
