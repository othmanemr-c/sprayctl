"""
Tests unitaires pour le CLI (résolution de mot de passe, lecture users).

Focus sécurité : vérifie que l'ordre de priorité password-file > env var >
prompt est bien respecté, et que le fichier users est correctement nettoyé.
"""

import os

import pytest

from sprayctl.cli import _read_users, _resolve_password, ENV_PASSWORD_VAR, build_parser


# ------------------------------------------------------------------ #
# _read_users
# ------------------------------------------------------------------ #

class TestReadUsers:
    def test_reads_simple_list(self, tmp_path):
        f = tmp_path / "users.txt"
        f.write_text("jdupont\namartin\nsvincent\n")
        assert _read_users(str(f)) == ["jdupont", "amartin", "svincent"]

    def test_strips_whitespace(self, tmp_path):
        f = tmp_path / "users.txt"
        f.write_text("  jdupont  \n\tamartin\t\n")
        assert _read_users(str(f)) == ["jdupont", "amartin"]

    def test_ignores_empty_lines(self, tmp_path):
        f = tmp_path / "users.txt"
        f.write_text("jdupont\n\n\namartin\n")
        assert _read_users(str(f)) == ["jdupont", "amartin"]

    def test_ignores_comments(self, tmp_path):
        f = tmp_path / "users.txt"
        f.write_text("jdupont\n# ceci est un commentaire\namartin\n")
        assert _read_users(str(f)) == ["jdupont", "amartin"]

    def test_deduplicates_preserving_order(self, tmp_path):
        f = tmp_path / "users.txt"
        f.write_text("jdupont\namartin\njdupont\nsvincent\namartin\n")
        assert _read_users(str(f)) == ["jdupont", "amartin", "svincent"]

    def test_exits_on_missing_file(self, tmp_path):
        with pytest.raises(SystemExit):
            _read_users(str(tmp_path / "does_not_exist.txt"))

    def test_exits_on_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("\n\n# only comments\n\n")
        with pytest.raises(SystemExit):
            _read_users(str(f))


# ------------------------------------------------------------------ #
# _resolve_password — ordre de priorité sécurité
# ------------------------------------------------------------------ #

class FakeArgs:
    def __init__(self, password=None, password_file=None):
        self.password = password
        self.password_file = password_file


class TestResolvePassword:
    def test_password_file_has_highest_priority(self, tmp_path, monkeypatch):
        pw_file = tmp_path / "pw.txt"
        pw_file.write_text("FromFile123!\n")
        monkeypatch.setenv(ENV_PASSWORD_VAR, "FromEnv456!")

        args = FakeArgs(password="FromCLI789!", password_file=str(pw_file))
        assert _resolve_password(args) == "FromFile123!"

    def test_env_var_used_if_no_file(self, monkeypatch):
        monkeypatch.setenv(ENV_PASSWORD_VAR, "FromEnv456!")
        args = FakeArgs(password="FromCLI789!", password_file=None)
        assert _resolve_password(args) == "FromEnv456!"

    def test_cli_password_used_as_last_resort(self, monkeypatch):
        monkeypatch.delenv(ENV_PASSWORD_VAR, raising=False)
        args = FakeArgs(password="FromCLI789!", password_file=None)
        assert _resolve_password(args) == "FromCLI789!"

    def test_prompts_if_nothing_provided(self, monkeypatch):
        monkeypatch.delenv(ENV_PASSWORD_VAR, raising=False)
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "FromPrompt!")
        args = FakeArgs(password=None, password_file=None)
        assert _resolve_password(args) == "FromPrompt!"

    def test_password_file_strips_whitespace(self, tmp_path, monkeypatch):
        monkeypatch.delenv(ENV_PASSWORD_VAR, raising=False)
        pw_file = tmp_path / "pw.txt"
        pw_file.write_text("  MyPassword!  \n")
        args = FakeArgs(password_file=str(pw_file))
        assert _resolve_password(args) == "MyPassword!"

    def test_exits_on_missing_password_file(self):
        args = FakeArgs(password_file="/nonexistent/path.txt")
        with pytest.raises(SystemExit):
            _resolve_password(args)


# ------------------------------------------------------------------ #
# CLI argument parsing
# ------------------------------------------------------------------ #

class TestArgParsing:
    def test_spray_requires_protocol_choice(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["spray", "--service", "X", "--protocol", "invalid-proto",
                                "--users", "f.txt", "--threshold", "5", "--window-minutes", "30"])

    def test_spray_defaults_execute_to_false(self):
        parser = build_parser()
        args = parser.parse_args([
            "spray", "--service", "X", "--protocol", "smb", "--target", "10.0.0.1",
            "--users", "f.txt", "--threshold", "5", "--window-minutes", "30",
        ])
        assert args.execute is False

    def test_spray_yes_flag(self):
        parser = build_parser()
        args = parser.parse_args([
            "spray", "--service", "X", "--protocol", "smb", "--target", "10.0.0.1",
            "--users", "f.txt", "--threshold", "5", "--window-minutes", "30",
            "--execute", "--yes",
        ])
        assert args.execute is True
        assert args.yes is True
