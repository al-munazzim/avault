"""Tests for avault — Agent Vault."""

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

# Import the module under test
import avault


# --- Fixtures ---

@pytest.fixture(autouse=True)
def reset_json_output():
    """Reset global JSON_OUTPUT flag."""
    avault.JSON_OUTPUT = False
    yield
    avault.JSON_OUTPUT = False


@pytest.fixture
def tmp_workspace(tmp_path):
    """Create a temporary workspace with vault files."""
    # Override module-level paths
    old_workspace = avault.WORKSPACE
    old_vault = avault.VAULT_FILE
    old_nsec_enc = avault.NSEC_ENC_FILE
    old_nip46 = avault.NIP46_FILE
    old_profile = avault.PROFILE_FILE
    old_socket = avault.SOCKET_PATH
    old_pid = avault.PID_FILE

    avault.WORKSPACE = tmp_path
    avault.VAULT_FILE = tmp_path / "avault.enc"
    avault.NSEC_ENC_FILE = tmp_path / "nsec.enc"
    avault.NIP46_FILE = tmp_path / "nip46.json"
    avault.PROFILE_FILE = tmp_path / ".profile"
    avault.SOCKET_PATH = tmp_path / "avault.sock"
    avault.PID_FILE = tmp_path / "avault.pid"

    yield tmp_path

    avault.WORKSPACE = old_workspace
    avault.VAULT_FILE = old_vault
    avault.NSEC_ENC_FILE = old_nsec_enc
    avault.NIP46_FILE = old_nip46
    avault.PROFILE_FILE = old_profile
    avault.SOCKET_PATH = old_socket
    avault.PID_FILE = old_pid


@pytest.fixture
def mock_keys():
    """Create mock Keys object."""
    keys = Mock()
    keys.secret_key.return_value = Mock()
    keys.public_key.return_value = Mock()
    keys.public_key.return_value.to_bech32.return_value = "npub1test..."
    keys.public_key.return_value.to_hex.return_value = "abc123"
    return keys


@pytest.fixture
def sample_vault():
    """A sample vault dict."""
    return {
        "version": 1,
        "created": "2026-02-20T00:00:00+00:00",
        "secrets": {
            "blink": {
                "values": {"BLINK_API_KEY": "sk-test-123", "BLINK_WALLET": "wallet1"},
                "added": "2026-02-20",
                "rotated": "2026-02-20",
                "note": "Test secret",
            },
            "raindrop": {
                "values": {"RAINDROP_TOKEN": "rd-token-456"},
                "added": "2026-01-15",
                "rotated": "2026-01-15",
                "note": "",
            },
            "old_service": {
                "values": {"OLD_KEY": "old-value"},
                "added": "2025-06-01",
                "rotated": "2025-06-01",
                "note": "Very old",
            },
        },
    }


# --- Tests: Helpers ---

class TestNewVault:
    def test_creates_valid_structure(self):
        v = avault.new_vault()
        assert v["version"] == 1
        assert v["secrets"] == {}
        assert "created" in v

    def test_today_format(self):
        result = avault.today()
        # Should be YYYY-MM-DD
        datetime.strptime(result, "%Y-%m-%d")


class TestParseProfileExports:
    def test_parses_exports(self, tmp_workspace):
        avault.PROFILE_FILE.write_text(
            'export MY_TOKEN="secret123"\n'
            'export ANOTHER_KEY="value456"\n'
        )
        exports = avault.parse_profile_exports()
        assert exports["MY_TOKEN"] == "secret123"
        assert exports["ANOTHER_KEY"] == "value456"

    def test_skips_system_vars(self, tmp_workspace):
        avault.PROFILE_FILE.write_text(
            'export PATH="/usr/bin"\n'
            'export HOME="/home/test"\n'
            'export MY_SECRET="keep"\n'
        )
        exports = avault.parse_profile_exports()
        assert "PATH" not in exports
        assert "HOME" not in exports
        assert exports["MY_SECRET"] == "keep"

    def test_skips_prefixed_vars(self, tmp_workspace):
        avault.PROFILE_FILE.write_text(
            'export NVM_DIR="/home/.nvm"\n'
            'export NODE_PATH="/usr/lib"\n'
            'export SSH_AUTH_SOCK="/tmp/ssh"\n'
            'export REAL_SECRET="yes"\n'
        )
        exports = avault.parse_profile_exports()
        assert "NVM_DIR" not in exports
        assert "NODE_PATH" not in exports
        assert "SSH_AUTH_SOCK" not in exports
        assert exports["REAL_SECRET"] == "yes"

    def test_skips_nostr_nsec(self, tmp_workspace):
        avault.PROFILE_FILE.write_text(
            'export NOSTR_NSEC="nsec1abc"\n'
            'export NOSTR_CONTACTS="abc,def"\n'
        )
        exports = avault.parse_profile_exports()
        assert "NOSTR_NSEC" not in exports
        assert "NOSTR_CONTACTS" in exports

    def test_missing_profile(self, tmp_workspace):
        # Don't create .profile
        exports = avault.parse_profile_exports()
        assert exports == {}

    def test_ignores_comments_and_non_exports(self, tmp_workspace):
        avault.PROFILE_FILE.write_text(
            '# This is a comment\n'
            'MY_VAR="not exported"\n'
            'export REAL_VAR="exported"\n'
        )
        exports = avault.parse_profile_exports()
        assert "MY_VAR" not in exports
        assert exports["REAL_VAR"] == "exported"


class TestGroupExports:
    def test_groups_by_prefix(self):
        exports = {
            "BLINK_API_KEY": "sk1",
            "BLINK_WALLET": "w1",
            "RAINDROP_TOKEN": "rt1",
            "PPQ_API_KEY": "ppq1",
        }
        groups = avault.group_exports(exports)
        assert "blink" in groups
        assert len(groups["blink"]) == 2
        assert "raindrop" in groups
        assert "ppq" in groups

    def test_twitter_special_grouping(self):
        exports = {"AUTH_TOKEN": "at1", "CT0": "ct1"}
        groups = avault.group_exports(exports)
        assert "x_twitter" in groups
        assert groups["x_twitter"]["AUTH_TOKEN"] == "at1"
        assert groups["x_twitter"]["CT0"] == "ct1"

    def test_nostr_excludes_nsec(self):
        exports = {"NOSTR_CONTACTS": "abc,def"}
        groups = avault.group_exports(exports)
        assert "nostr" in groups

    def test_unknown_prefix_uses_first_part(self):
        exports = {"RANDOM_THING": "val"}
        groups = avault.group_exports(exports)
        assert "random" in groups


class TestGetNsecString:
    def test_from_env(self, tmp_workspace):
        with patch.dict(os.environ, {"NOSTR_NSEC": "nsec1fromenv"}):
            assert avault.get_nsec_string() == "nsec1fromenv"

    def test_from_profile(self, tmp_workspace):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NOSTR_NSEC", None)
            avault.PROFILE_FILE.write_text('export NOSTR_NSEC="nsec1fromprofile"\n')
            assert avault.get_nsec_string() == "nsec1fromprofile"

    def test_none_when_missing(self, tmp_workspace):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NOSTR_NSEC", None)
            # No .profile file
            assert avault.get_nsec_string() is None


# --- Tests: QR Code ---

class TestPrintQR:
    def test_prints_qr(self, capsys):
        avault._print_qr("test data")
        captured = capsys.readouterr()
        # Should have output (Unicode blocks)
        assert len(captured.out) > 0
        # Should contain block characters
        assert any(c in captured.out for c in "▀▄█")

    def test_fallback_without_qrcode(self, capsys):
        old_has = avault.HAS_QRCODE
        avault.HAS_QRCODE = False
        avault._print_qr("test data")
        captured = capsys.readouterr()
        assert "install" in captured.out
        avault.HAS_QRCODE = old_has


# --- Tests: Output helper ---

class TestOutput:
    def test_json_mode(self, capsys):
        avault.JSON_OUTPUT = True
        avault.output({"key": "value"})
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["key"] == "value"

    def test_human_mode(self, capsys):
        avault.JSON_OUTPUT = False
        avault.output({"key": "value"}, lambda d: print(f"Key is {d['key']}"))
        captured = capsys.readouterr()
        assert "Key is value" in captured.out

    def test_human_mode_no_fn(self, capsys):
        avault.JSON_OUTPUT = False
        avault.output("plain text")
        captured = capsys.readouterr()
        assert "plain text" in captured.out


# --- Tests: VaultDaemon request handling ---

class TestDaemonRequests:
    def setup_method(self):
        self.daemon = avault.VaultDaemon()
        self.daemon.keys = Mock()
        self.daemon.keys.public_key.return_value = Mock()
        self.daemon.keys.public_key.return_value.to_bech32.return_value = "npub1test"
        self.daemon.vault = {
            "version": 1,
            "secrets": {
                "blink": {
                    "values": {"BLINK_API_KEY": "sk-123"},
                    "added": "2026-02-20",
                    "rotated": "2026-02-20",
                    "note": "test",
                }
            },
        }

    def test_status(self):
        resp = self.daemon.handle_request({"cmd": "status"})
        assert resp["ok"] is True
        assert resp["data"]["running"] is True
        assert resp["data"]["secrets_count"] == 1

    def test_list(self):
        resp = self.daemon.handle_request({"cmd": "list"})
        assert resp["ok"] is True
        assert "blink" in resp["data"]
        assert "BLINK_API_KEY" in resp["data"]["blink"]["keys"]

    def test_get_all_keys(self):
        resp = self.daemon.handle_request({"cmd": "get", "name": "blink"})
        assert resp["ok"] is True
        assert resp["data"]["BLINK_API_KEY"] == "sk-123"

    def test_get_specific_key(self):
        resp = self.daemon.handle_request({"cmd": "get", "name": "blink", "key": "BLINK_API_KEY"})
        assert resp["ok"] is True
        assert resp["data"] == "sk-123"

    def test_get_missing_secret(self):
        resp = self.daemon.handle_request({"cmd": "get", "name": "nonexistent"})
        assert resp["ok"] is False
        assert "not found" in resp["error"]

    def test_get_missing_key(self):
        resp = self.daemon.handle_request({"cmd": "get", "name": "blink", "key": "NOPE"})
        assert resp["ok"] is False
        assert "not found" in resp["error"]

    @patch("avault.save_vault")
    def test_set_new_secret(self, mock_save):
        resp = self.daemon.handle_request({
            "cmd": "set", "name": "new_svc", "key": "API_KEY", "value": "new-val"
        })
        assert resp["ok"] is True
        assert "new_svc" in self.daemon.vault["secrets"]
        assert self.daemon.vault["secrets"]["new_svc"]["values"]["API_KEY"] == "new-val"
        mock_save.assert_called_once()

    @patch("avault.save_vault")
    def test_set_existing_secret(self, mock_save):
        resp = self.daemon.handle_request({
            "cmd": "set", "name": "blink", "key": "BLINK_NEW", "value": "val2"
        })
        assert resp["ok"] is True
        assert self.daemon.vault["secrets"]["blink"]["values"]["BLINK_NEW"] == "val2"
        # Original key still there
        assert self.daemon.vault["secrets"]["blink"]["values"]["BLINK_API_KEY"] == "sk-123"

    @patch("avault.save_vault")
    def test_set_with_note(self, mock_save):
        resp = self.daemon.handle_request({
            "cmd": "set", "name": "blink", "key": "X", "value": "Y", "note": "Updated"
        })
        assert resp["ok"] is True
        assert self.daemon.vault["secrets"]["blink"]["note"] == "Updated"

    def test_set_missing_fields(self):
        resp = self.daemon.handle_request({"cmd": "set", "name": "x"})
        assert resp["ok"] is False

    @patch("avault.save_vault")
    def test_delete(self, mock_save):
        resp = self.daemon.handle_request({"cmd": "delete", "name": "blink"})
        assert resp["ok"] is True
        assert "blink" not in self.daemon.vault["secrets"]
        mock_save.assert_called_once()

    def test_delete_missing(self):
        resp = self.daemon.handle_request({"cmd": "delete", "name": "nope"})
        assert resp["ok"] is False

    def test_export(self):
        resp = self.daemon.handle_request({"cmd": "export"})
        assert resp["ok"] is True
        assert resp["data"]["BLINK_API_KEY"] == "sk-123"

    def test_shutdown(self):
        resp = self.daemon.handle_request({"cmd": "shutdown"})
        assert resp["ok"] is True
        assert self.daemon.running is False

    def test_unknown_command(self):
        resp = self.daemon.handle_request({"cmd": "bogus"})
        assert resp["ok"] is False
        assert "Unknown" in resp["error"]

    def test_list_no_vault(self):
        self.daemon.vault = None
        resp = self.daemon.handle_request({"cmd": "list"})
        assert resp["ok"] is False

    def test_get_no_vault(self):
        self.daemon.vault = None
        resp = self.daemon.handle_request({"cmd": "get", "name": "x"})
        assert resp["ok"] is False


# --- Tests: Protocol ---

class TestProtocol:
    def test_send_recv_roundtrip(self):
        """Test length-prefixed JSON protocol."""
        import socket as sock_mod
        server = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "test.sock")
            server.bind(path)
            server.listen(1)

            client = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
            client.connect(path)

            conn, _ = server.accept()

            test_msg = {"cmd": "test", "data": "hello world"}
            avault.send_msg(client, test_msg)
            received = avault.recv_msg(conn)

            assert received == test_msg

            client.close()
            conn.close()
            server.close()


# --- Tests: cmd_doctor ---

class TestDoctor:
    def test_doctor_checks_structure(self, tmp_workspace, capsys):
        """Doctor should check prerequisites and report."""
        avault.JSON_OUTPUT = True

        # No files exist, nsec not in env
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NOSTR_NSEC", None)
            with pytest.raises(SystemExit):
                avault.cmd_doctor(Mock())

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "checks" in result
        assert result["all_ok"] is False
        # nostr-sdk should be OK (we imported it)
        sdk_check = next(c for c in result["checks"] if c["check"] == "nostr-sdk")
        assert sdk_check["ok"] is True


# --- Tests: cmd_stale ---

class TestStale:
    @patch("avault.daemon_running", return_value=False)
    @patch("avault.get_keys")
    @patch("avault.load_vault")
    def test_stale_detection(self, mock_load, mock_keys, mock_dr, capsys, tmp_workspace, sample_vault):
        mock_keys.return_value = Mock()
        mock_load.return_value = sample_vault

        avault.JSON_OUTPUT = True
        args = Mock()
        args.days = 30

        avault.cmd_stale(args)

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["threshold_days"] == 30

        stale_names = [s["name"] for s in result["stale"]]
        fresh_names = [s["name"] for s in result["fresh"]]

        # old_service (2025-06-01) should be stale
        assert "old_service" in stale_names
        # blink (2026-02-20) should be fresh
        assert "blink" in fresh_names

    @patch("avault.daemon_running", return_value=False)
    @patch("avault.get_keys")
    @patch("avault.load_vault")
    def test_all_fresh(self, mock_load, mock_keys, mock_dr, capsys, tmp_workspace):
        mock_keys.return_value = Mock()
        mock_load.return_value = {
            "version": 1,
            "secrets": {
                "fresh": {"values": {"K": "V"}, "added": avault.today(), "rotated": avault.today()},
            },
        }

        avault.JSON_OUTPUT = True
        args = Mock()
        args.days = 90
        avault.cmd_stale(args)

        result = json.loads(capsys.readouterr().out)
        assert len(result["stale"]) == 0
        assert len(result["fresh"]) == 1


# --- Tests: cmd_migrate --dry-run ---

class TestMigrateDryRun:
    @patch("avault.save_vault")
    @patch("avault.get_keys")
    @patch("avault.load_vault")
    def test_dry_run_no_changes(self, mock_load, mock_keys, mock_save, tmp_workspace):
        mock_keys.return_value = Mock()
        vault = avault.new_vault()
        mock_load.return_value = vault

        avault.PROFILE_FILE.write_text('export NEW_SECRET="val"\n')

        args = Mock()
        args.dry_run = True
        avault.cmd_migrate(args)

        # Vault should NOT be saved in dry-run mode
        mock_save.assert_not_called()
        # Vault should still be empty
        assert len(vault["secrets"]) == 0

    @patch("avault.save_vault")
    @patch("avault.get_keys")
    @patch("avault.load_vault")
    def test_real_migrate(self, mock_load, mock_keys, mock_save, tmp_workspace):
        mock_keys.return_value = Mock()
        vault = avault.new_vault()
        mock_load.return_value = vault

        avault.PROFILE_FILE.write_text('export BLINK_API_KEY="sk-test"\n')

        args = Mock()
        args.dry_run = False
        avault.cmd_migrate(args)

        # Vault should be saved
        mock_save.assert_called_once()
        assert "blink" in vault["secrets"]


# --- Tests: cmd_audit ---

class TestAudit:
    @patch("avault.get_keys")
    @patch("avault.load_vault")
    def test_in_sync(self, mock_load, mock_keys, capsys, tmp_workspace):
        mock_keys.return_value = Mock()
        mock_load.return_value = {
            "version": 1,
            "secrets": {
                "svc": {"values": {"MY_KEY": "val"}, "added": "2026-01-01", "rotated": "2026-01-01"},
            },
        }
        avault.PROFILE_FILE.write_text('export MY_KEY="val"\n')

        avault.JSON_OUTPUT = True
        avault.cmd_audit(Mock())

        result = json.loads(capsys.readouterr().out)
        assert result["in_sync"] is True

    @patch("avault.get_keys")
    @patch("avault.load_vault")
    def test_out_of_sync(self, mock_load, mock_keys, capsys, tmp_workspace):
        mock_keys.return_value = Mock()
        mock_load.return_value = {
            "version": 1,
            "secrets": {
                "svc": {"values": {"VAULT_ONLY": "val"}, "added": "2026-01-01", "rotated": "2026-01-01"},
            },
        }
        avault.PROFILE_FILE.write_text('export PROFILE_ONLY="val"\n')

        avault.JSON_OUTPUT = True
        avault.cmd_audit(Mock())

        result = json.loads(capsys.readouterr().out)
        assert result["in_sync"] is False
        assert "PROFILE_ONLY" in result["only_in_profile"]
        assert "VAULT_ONLY" in result["only_in_vault"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
