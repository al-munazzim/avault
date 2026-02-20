#!/usr/bin/env python3
"""
avault — Agent Vault: NIP-44 encrypted secret management with NIP-46 remote signing.

Architecture:
  avault daemon   — long-running process, holds secrets in RAM only
                    connects to Amber/signer via NIP-46 on startup
                    listens on unix socket for CLI requests
  avault <cmd>    — short-lived CLI, talks to daemon via socket
                    (falls back to local nsec if daemon not running)

Commands:
  daemon start [--foreground]          Start daemon (NIP-46 → Amber → decrypt → serve)
  daemon stop                          Stop daemon, wipe secrets from RAM
  daemon status                        Check if daemon is running

  init --signer-npub <npub>            Initialize vault + encrypt nsec for operator
  unlock                               Decrypt vault, verify access
  list                                 List secret names + metadata
  get <name> [--key KEY]               Get a secret value
  set <name> --key KEY --value VAL     Set a secret
  delete <name>                        Remove a secret
  export [--shell]                     Export all secrets as env vars
  migrate [--dry-run]                  Import secrets from ~/.profile
  audit                                Compare ~/.profile vs vault
  doctor                               Check prerequisites and config health
  stale [--days N]                     Flag secrets not rotated in N days (default: 90)

Files (all safe to commit — ciphertext or public info):
  avault.enc      — all secrets, NIP-44 encrypted (self-encrypt with agent nsec)
  nsec.enc        — agent's nsec, NIP-44 encrypted with operator's npub
  nip46.json      — NIP-46 connection info (signer npub, relay — public data)
"""

import argparse
import asyncio
import json
import os
import re
import secrets as secrets_mod
import signal
import socket
import struct
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from nostr_sdk import (
    Keys,
    Nip44Version,
    NostrConnect,
    NostrConnectUri,
    PublicKey,
    nip44_decrypt,
    nip44_encrypt,
)

# --- Config ---
WORKSPACE = Path(os.environ.get("WORKSPACE", Path.home() / "clawd"))
VAULT_FILE = WORKSPACE / "avault.enc"
NSEC_ENC_FILE = WORKSPACE / "nsec.enc"
NIP46_FILE = WORKSPACE / "nip46.json"
PROFILE_FILE = Path.home() / ".profile"
_run_dir = Path(os.environ.get("XDG_RUNTIME_DIR", f"/tmp/avault-{os.getuid()}"))
SOCKET_PATH = Path(os.environ.get("AVAULT_SOCKET", str(_run_dir / "avault.sock")))
PID_FILE = Path(os.environ.get("AVAULT_PID", str(_run_dir / "avault.pid")))

# Global flag for JSON output (set by --json)
JSON_OUTPUT = False


def output(data, human_fn=None):
    """Output data as JSON or human-readable."""
    if JSON_OUTPUT:
        print(json.dumps(data, indent=2))
    elif human_fn:
        human_fn(data)
    else:
        print(data)


SKIP_VARS = {
    "PATH", "HOME", "USER", "SHELL", "LANG", "TERM", "NOSTR_NSEC",
    "EDITOR", "VISUAL", "PAGER", "DISPLAY", "XDG_RUNTIME_DIR",
}
SKIP_PREFIXES = ("NVM_", "NODE_", "DBUS_", "XDG_", "SSH_")

# Default NIP-46 relay
DEFAULT_RELAY = "wss://relay.damus.io"

# --- Protocol ---
# CLI ↔ daemon communicate via unix socket with simple length-prefixed JSON:
#   [4 bytes big-endian length][JSON payload]
# Request:  {"cmd": "get", "name": "blink", "key": "BLINK_API_KEY"}
# Response: {"ok": true, "data": "..."}  or  {"ok": false, "error": "..."}


def send_msg(sock: socket.socket, obj: dict) -> None:
    """Send length-prefixed JSON over socket."""
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_msg(sock: socket.socket) -> dict | None:
    """Receive length-prefixed JSON from socket."""
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        return None
    length = struct.unpack(">I", raw_len)[0]
    if length > 10 * 1024 * 1024:  # 10MB sanity limit
        return None
    data = _recv_exact(sock, length)
    if not data:
        return None
    return json.loads(data)


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# --- Helpers ---

def get_nsec_string() -> str | None:
    """Read nsec from env or ~/.profile."""
    nsec = os.environ.get("NOSTR_NSEC")
    if nsec:
        return nsec
    try:
        profile = PROFILE_FILE.read_text()
        m = re.search(r'NOSTR_NSEC="?(nsec1[a-z0-9]+)"?', profile)
        if m:
            return m.group(1)
    except FileNotFoundError:
        pass
    return None


def get_keys() -> Keys | None:
    nsec = get_nsec_string()
    if not nsec:
        return None
    return Keys.parse(nsec)


def load_vault(keys: Keys) -> dict | None:
    if not VAULT_FILE.exists():
        return None
    encrypted = VAULT_FILE.read_text().strip()
    plaintext = nip44_decrypt(keys.secret_key(), keys.public_key(), encrypted)
    return json.loads(plaintext)


def save_vault(vault: dict, keys: Keys) -> None:
    plaintext = json.dumps(vault, indent=2)
    encrypted = nip44_encrypt(
        keys.secret_key(), keys.public_key(), plaintext, Nip44Version.V2
    )
    VAULT_FILE.write_text(encrypted + "\n")
    _auto_commit()


def _auto_commit() -> None:
    """Auto-commit and push vault changes (ciphertext only, safe to push)."""
    try:
        subprocess.run(
            ["git", "add", str(VAULT_FILE.name)],
            cwd=str(WORKSPACE), capture_output=True, timeout=10,
        )
        result = subprocess.run(
            ["git", "commit", "-m", "avault: vault updated"],
            cwd=str(WORKSPACE), capture_output=True, timeout=10,
        )
        if result.returncode == 0:
            # Push in background to not block the caller
            subprocess.Popen(
                ["git", "push", "origin", "main"],
                cwd=str(WORKSPACE),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
    except Exception:
        pass  # non-fatal — vault is saved locally regardless


def new_vault() -> dict:
    return {
        "version": 1,
        "created": datetime.now(timezone.utc).isoformat(),
        "secrets": {},
    }


def today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def parse_profile_exports() -> dict[str, str]:
    try:
        profile = PROFILE_FILE.read_text()
    except FileNotFoundError:
        return {}
    exports = {}
    for m in re.finditer(r'^export\s+([A-Z_][A-Z0-9_]*)="?([^"\n]*)"?$', profile, re.M):
        key, value = m.group(1), m.group(2)
        if key in SKIP_VARS or any(key.startswith(p) for p in SKIP_PREFIXES):
            continue
        exports[key] = value
    return exports


def group_exports(exports: dict[str, str]) -> dict[str, dict[str, str]]:
    groups: dict[str, dict[str, str]] = {}
    for key, value in exports.items():
        if key in ("AUTH_TOKEN", "CT0"):
            group = "x_twitter"
        elif key.startswith("BLINK_"):
            group = "blink"
        elif key.startswith("PPQ_"):
            group = "ppq"
        elif key.startswith("RAINDROP_"):
            group = "raindrop"
        elif key.startswith("FORGEJO_"):
            group = "forgejo"
        elif key.startswith("NOSTR_") and key != "NOSTR_NSEC":
            group = "nostr"
        elif key.startswith("VIKUNJA_"):
            group = "vikunja"
        elif key.startswith("GEMINI_"):
            group = "gemini"
        else:
            group = key.lower().split("_")[0]
        groups.setdefault(group, {})[key] = value
    return groups


def daemon_running() -> bool:
    """Check if daemon is running and socket exists."""
    return SOCKET_PATH.exists()


def daemon_request(req: dict, timeout: float = 5.0) -> dict:
    """Send request to daemon and return response."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(str(SOCKET_PATH))
        send_msg(sock, req)
        resp = recv_msg(sock)
        return resp or {"ok": False, "error": "Empty response from daemon"}
    except ConnectionRefusedError:
        return {"ok": False, "error": "Daemon not running (connection refused)"}
    except FileNotFoundError:
        return {"ok": False, "error": "Daemon not running (no socket)"}
    except socket.timeout:
        return {"ok": False, "error": "Daemon request timed out"}
    finally:
        sock.close()


# ============================================================
# DAEMON
# ============================================================

class VaultDaemon:
    """Holds decrypted secrets in RAM, serves requests over unix socket."""

    def __init__(self):
        self.keys: Keys | None = None         # agent's keys (from nsec)
        self.vault: dict | None = None         # decrypted vault
        self.running = False
        self.server_sock: socket.socket | None = None

    async def start_nip46(self, nip46_config: dict, timeout_secs: int = 120) -> Keys:
        """Connect to signer via NIP-46, decrypt nsec.enc, return agent Keys."""
        from datetime import timedelta

        signer_hex = PublicKey.parse(nip46_config["signer_npub"]).to_hex()
        relay = nip46_config.get("relay", DEFAULT_RELAY)

        # Use a fresh secret to force clean NIP-46 handshake.
        secret = secrets_mod.token_hex(16)

        bunker_uri = f"bunker://{signer_hex}?relay={relay}&secret={secret}"

        uri = NostrConnectUri.parse(bunker_uri)

        # For NIP-46 transport, we need app_keys. Two modes:
        # 1. If agent nsec is available (e.g. first boot, migration): use it directly
        #    Amber already trusts this pubkey from initial pairing.
        # 2. If no nsec (pure nsec-free boot): use ephemeral keys.
        #    Requires fresh Amber approval for the new pubkey.
        nsec = get_nsec_string()
        if nsec:
            app_keys = Keys.parse(nsec)
            print(f"⏳ Connecting to signer via NIP-46 (known identity)...")
        else:
            app_keys = Keys.generate()
            print(f"⏳ Connecting to signer via NIP-46 (ephemeral identity)...")
            print(f"   ⚠️  New app key — approve in your signer!")

        nc = NostrConnect(uri, app_keys, timedelta(seconds=timeout_secs), None)

        print(f"   Relay: {relay}")
        print(f"   Signer: {nip46_config['signer_npub']}")

        # get_public_key() triggers the connect handshake.
        # Already-paired signers (Amber) may respond "ack" — that's fine.
        try:
            signer_pk = await nc.get_public_key()
            print(f"✅ Connected to signer: {signer_pk.to_bech32()}")
        except Exception as e:
            if "ack" in str(e).lower():
                print(f"✅ Signer acknowledged (already paired)")
            else:
                raise

        # Read nsec.enc from disk and ask signer to decrypt it
        if not NSEC_ENC_FILE.exists():
            raise FileNotFoundError(f"No {NSEC_ENC_FILE} found")

        nsec_ciphertext = NSEC_ENC_FILE.read_text().strip()
        print("🔓 Requesting nsec decryption from signer...")

        # The nsec was encrypted FROM agent TO signer, so signer decrypts
        # with their key against agent's pubkey. But we need to know the
        # agent pubkey that was used... it's in the ciphertext's conversation key.
        # Actually: nsec.enc = nip44_encrypt(agent_sk, signer_pk, nsec_str)
        # To decrypt: nip44_decrypt(signer_sk, agent_pk, ciphertext)
        # Via NIP-46: nc.nip44_decrypt(agent_pk, ciphertext)
        # But we don't know agent_pk yet (that's what we're trying to recover!)
        #
        # Solution: store agent_npub in nip46.json (it's public info)
        agent_npub = nip46_config.get("agent_npub")
        if not agent_npub:
            raise ValueError("agent_npub missing from nip46.json — needed to decrypt nsec.enc")

        agent_pk = PublicKey.parse(agent_npub)
        nsec_str = await nc.nip44_decrypt(agent_pk, nsec_ciphertext)

        print("✅ nsec decrypted (in RAM only)")
        return Keys.parse(nsec_str)

    def decrypt_vault(self) -> None:
        """Load and decrypt vault into RAM."""
        if not self.keys:
            raise RuntimeError("No keys loaded")
        self.vault = load_vault(self.keys)
        if not self.vault:
            raise FileNotFoundError("No avault.enc found")
        count = len(self.vault["secrets"])
        print(f"✅ Vault decrypted: {count} secret(s) in RAM")

    def handle_request(self, req: dict) -> dict:
        """Process a single CLI request."""
        cmd = req.get("cmd", "")

        if cmd == "status":
            return {
                "ok": True,
                "data": {
                    "running": True,
                    "secrets_count": len(self.vault["secrets"]) if self.vault else 0,
                    "agent_npub": self.keys.public_key().to_bech32() if self.keys else None,
                    "vault_version": self.vault.get("version") if self.vault else None,
                },
            }

        if cmd == "list":
            if not self.vault:
                return {"ok": False, "error": "Vault not loaded"}
            result = {}
            for name, entry in self.vault["secrets"].items():
                result[name] = {
                    "keys": list(entry.get("values", {}).keys()),
                    "added": entry.get("added", "-"),
                    "rotated": entry.get("rotated", "-"),
                    "note": entry.get("note", ""),
                }
            return {"ok": True, "data": result}

        if cmd == "get":
            if not self.vault:
                return {"ok": False, "error": "Vault not loaded"}
            name = req.get("name")
            entry = self.vault["secrets"].get(name)
            if not entry:
                return {"ok": False, "error": f'Secret "{name}" not found'}
            key = req.get("key")
            if key:
                val = entry.get("values", {}).get(key)
                if val is None:
                    return {"ok": False, "error": f'Key "{key}" not found in "{name}"'}
                return {"ok": True, "data": val}
            return {"ok": True, "data": entry.get("values", {})}

        if cmd == "set":
            if not self.vault or not self.keys:
                return {"ok": False, "error": "Vault not loaded"}
            name, key, value = req.get("name"), req.get("key"), req.get("value")
            note = req.get("note")
            if not all([name, key, value]):
                return {"ok": False, "error": "Missing name, key, or value"}
            if name not in self.vault["secrets"]:
                self.vault["secrets"][name] = {
                    "values": {},
                    "added": today(),
                    "rotated": today(),
                }
            self.vault["secrets"][name]["values"][key] = value
            self.vault["secrets"][name]["rotated"] = today()
            if note:
                self.vault["secrets"][name]["note"] = note
            # Re-encrypt and save to disk
            save_vault(self.vault, self.keys)
            return {"ok": True, "data": f"Set {name}.{key}"}

        if cmd == "delete":
            if not self.vault or not self.keys:
                return {"ok": False, "error": "Vault not loaded"}
            name = req.get("name")
            if name not in self.vault["secrets"]:
                return {"ok": False, "error": f'Secret "{name}" not found'}
            del self.vault["secrets"][name]
            save_vault(self.vault, self.keys)
            return {"ok": True, "data": f'Deleted "{name}"'}

        if cmd == "export":
            if not self.vault:
                return {"ok": False, "error": "Vault not loaded"}
            all_vars = {}
            for entry in self.vault["secrets"].values():
                all_vars.update(entry.get("values", {}))
            return {"ok": True, "data": all_vars}

        if cmd == "shutdown":
            self.running = False
            return {"ok": True, "data": "Shutting down"}

        return {"ok": False, "error": f"Unknown command: {cmd}"}

    def handle_client(self, conn: socket.socket) -> None:
        """Handle a single client connection."""
        try:
            conn.settimeout(10)
            req = recv_msg(conn)
            if not req:
                return
            resp = self.handle_request(req)
            send_msg(conn, resp)
        except Exception as e:
            try:
                send_msg(conn, {"ok": False, "error": str(e)})
            except Exception:
                pass
        finally:
            conn.close()

    def serve(self) -> None:
        """Listen on unix socket and serve requests."""
        # Ensure run directory exists
        SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(SOCKET_PATH.parent), 0o700)

        # Cleanup stale socket
        if SOCKET_PATH.exists():
            SOCKET_PATH.unlink()

        self.server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_sock.bind(str(SOCKET_PATH))
        # Restrict to owner only
        os.chmod(str(SOCKET_PATH), 0o600)
        self.server_sock.listen(5)
        self.server_sock.settimeout(1.0)  # so we can check self.running

        self.running = True
        print(f"🔌 Listening on {SOCKET_PATH}")
        print(f"   PID: {os.getpid()}")

        # Write PID file
        PID_FILE.write_text(str(os.getpid()))

        while self.running:
            try:
                conn, _ = self.server_sock.accept()
                # Handle in thread to not block
                t = threading.Thread(target=self.handle_client, args=(conn,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

        # Cleanup
        print("\n🧹 Wiping secrets from RAM...")
        self.vault = None
        self.keys = None
        if SOCKET_PATH.exists():
            SOCKET_PATH.unlink()
        if PID_FILE.exists():
            PID_FILE.unlink()
        print("👋 Daemon stopped.")


async def daemon_start(foreground: bool = True, timeout: int = 120) -> None:
    """Start the vault daemon with NIP-46 unlock."""
    if daemon_running():
        # Check if actually alive
        resp = daemon_request({"cmd": "status"})
        if resp.get("ok"):
            print("Daemon already running.")
            return
        # Stale socket
        SOCKET_PATH.unlink()

    # Load NIP-46 config
    if not NIP46_FILE.exists():
        sys.exit(
            f"No {NIP46_FILE} found. Run 'avault init --signer-npub <npub>' first,\n"
            "then 'avault nip46-setup' to configure the connection."
        )

    nip46_config = json.loads(NIP46_FILE.read_text())

    daemon = VaultDaemon()

    # Connect to signer and get keys
    daemon.keys = await daemon.start_nip46(nip46_config, timeout_secs=timeout)

    # Decrypt vault
    daemon.decrypt_vault()

    # Handle signals
    def handle_stop(signum, frame):
        print("\n⚡ Signal received, shutting down...")
        daemon.running = False

    signal.signal(signal.SIGTERM, handle_stop)
    signal.signal(signal.SIGINT, handle_stop)

    if foreground:
        daemon.serve()
    else:
        # Fork to background
        pid = os.fork()
        if pid > 0:
            # Parent
            print(f"Daemon started in background (PID {pid})")
            return
        # Child — detach
        os.setsid()
        # Close stdin/stdout/stderr
        sys.stdin.close()
        devnull = open(os.devnull, "w")
        sys.stdout = devnull
        sys.stderr = devnull
        daemon.serve()


# ============================================================
# CLI COMMANDS (talk to daemon or fallback to local nsec)
# ============================================================

def cli_or_daemon(req: dict, fallback_fn=None) -> None:
    """Try daemon first, fall back to local nsec if not running."""
    if daemon_running():
        resp = daemon_request(req)
        if resp.get("ok"):
            return resp
        print(f"Error: {resp.get('error')}", file=sys.stderr)
        sys.exit(1)

    if fallback_fn:
        return fallback_fn()

    sys.exit("Daemon not running. Start with: avault daemon start\n"
             "Or use with local nsec (set NOSTR_NSEC or add to ~/.profile)")


def cmd_daemon(args: argparse.Namespace) -> None:
    subcmd = args.daemon_cmd

    if subcmd == "start":
        asyncio.run(daemon_start(
            foreground=args.foreground,
            timeout=args.timeout,
        ))

    elif subcmd == "stop":
        if not daemon_running():
            print("Daemon not running.")
            return
        resp = daemon_request({"cmd": "shutdown"})
        if resp.get("ok"):
            print("✅ Daemon stopping...")
        else:
            # Try PID file
            if PID_FILE.exists():
                pid = int(PID_FILE.read_text().strip())
                try:
                    os.kill(pid, signal.SIGTERM)
                    print(f"Sent SIGTERM to PID {pid}")
                except ProcessLookupError:
                    print("Daemon already dead. Cleaning up...")
                    if SOCKET_PATH.exists():
                        SOCKET_PATH.unlink()
                    PID_FILE.unlink()

    elif subcmd == "status":
        if not daemon_running():
            print("Daemon: not running")
            return
        resp = daemon_request({"cmd": "status"})
        if resp.get("ok"):
            d = resp["data"]
            print(f"Daemon: running (PID {PID_FILE.read_text().strip() if PID_FILE.exists() else '?'})")
            print(f"Agent:  {d.get('agent_npub', '?')}")
            print(f"Vault:  {d.get('secrets_count', 0)} secret(s)")
        else:
            print(f"Daemon: socket exists but not responding ({resp.get('error')})")


def cmd_init(args: argparse.Namespace) -> None:
    signer_pubkey = PublicKey.parse(args.signer_npub)

    keys = get_keys()
    nsec_str = get_nsec_string()

    if keys:
        print("Agent nsec found in environment.")
    else:
        print("No nsec found. Generating new keypair...")
        keys = Keys.generate()
        nsec_str = keys.secret_key().to_bech32()
        with open(PROFILE_FILE, "a") as f:
            f.write(f'\nexport NOSTR_NSEC="{nsec_str}"\n')
        print("New keypair generated. nsec written to ~/.profile")

    # Encrypt nsec with operator's pubkey
    nsec_encrypted = nip44_encrypt(
        keys.secret_key(), signer_pubkey, nsec_str, Nip44Version.V2
    )
    NSEC_ENC_FILE.write_text(nsec_encrypted + "\n")
    print("nsec.enc created (encrypted to operator's npub)")

    # Create empty vault if needed
    if VAULT_FILE.exists():
        print("avault.enc already exists. Skipping vault creation.")
    else:
        save_vault(new_vault(), keys)
        print("avault.enc created (empty vault)")

    # Save NIP-46 connection config (no secret — pairing is done via QR/approve in signer)
    nip46_config = {
        "signer_npub": args.signer_npub,
        "agent_npub": keys.public_key().to_bech32(),
        "relay": DEFAULT_RELAY,
    }
    NIP46_FILE.write_text(json.dumps(nip46_config, indent=2) + "\n")
    print(f"nip46.json created (connection config)")

    agent_npub = keys.public_key().to_bech32()
    print(f"\nAgent npub:    {agent_npub}")
    print(f"Operator npub: {args.signer_npub}")
    print(f"\nFiles created:")
    print(f"  {VAULT_FILE}    (ciphertext)")
    print(f"  {NSEC_ENC_FILE}      (ciphertext)")
    print(f"  {NIP46_FILE}     (public config)")
    print(f"\nNext: start daemon with 'avault daemon start'")
    print(f"      (operator scans QR or approves in Amber)")


def cmd_unlock(_args: argparse.Namespace) -> None:
    if daemon_running():
        resp = daemon_request({"cmd": "status"})
        if resp.get("ok"):
            d = resp["data"]
            print(f"Vault unlocked via daemon. {d['secrets_count']} secret(s).")
            return

    keys = get_keys()
    if not keys:
        sys.exit("No nsec found and daemon not running.")
    vault = load_vault(keys)
    if not vault:
        sys.exit("No avault.enc found.")
    print(f"Vault unlocked. Version {vault['version']}, {len(vault['secrets'])} secret(s).")


def cmd_list(_args: argparse.Namespace) -> None:
    def fallback():
        keys = get_keys()
        if not keys:
            sys.exit("No nsec found and daemon not running.")
        vault = load_vault(keys)
        if not vault:
            sys.exit("No avault.enc found.")
        return {"ok": True, "data": {
            name: {
                "keys": list(e.get("values", {}).keys()),
                "added": e.get("added", "-"),
                "rotated": e.get("rotated", "-"),
                "note": e.get("note", ""),
            }
            for name, e in vault["secrets"].items()
        }}

    resp = cli_or_daemon({"cmd": "list"}, fallback)
    data = resp["data"]

    def human(d):
        if not d:
            print("Vault is empty.")
            return
        print(f"{'Name':<20} {'Keys':<30} {'Added':<12} {'Rotated':<12} Note")
        print("─" * 100)
        for name, info in d.items():
            keys_str = ", ".join(info["keys"])
            print(f"{name:<20} {keys_str:<30} {info['added']:<12} {info['rotated']:<12} {info.get('note', '')}")

    output(data, human)


def cmd_get(args: argparse.Namespace) -> None:
    def fallback():
        keys = get_keys()
        if not keys:
            sys.exit("No nsec found and daemon not running.")
        vault = load_vault(keys)
        if not vault:
            sys.exit("No avault.enc found.")
        entry = vault["secrets"].get(args.name)
        if not entry:
            sys.exit(f'Secret "{args.name}" not found.')
        if args.key:
            val = entry.get("values", {}).get(args.key)
            if val is None:
                sys.exit(f'Key "{args.key}" not found in "{args.name}".')
            return {"ok": True, "data": val}
        return {"ok": True, "data": entry.get("values", {})}

    req = {"cmd": "get", "name": args.name}
    if args.key:
        req["key"] = args.key
    resp = cli_or_daemon(req, fallback)
    data = resp["data"]

    def human(d):
        if isinstance(d, str):
            print(d)
        else:
            for k, v in d.items():
                print(f"{k}={v}")

    output(data, human)


def cmd_set(args: argparse.Namespace) -> None:
    def fallback():
        keys = get_keys()
        if not keys:
            sys.exit("No nsec found and daemon not running.")
        vault = load_vault(keys)
        if not vault:
            sys.exit("No avault.enc found.")
        if args.name not in vault["secrets"]:
            vault["secrets"][args.name] = {"values": {}, "added": today(), "rotated": today()}
        vault["secrets"][args.name]["values"][args.key] = args.value
        vault["secrets"][args.name]["rotated"] = today()
        if args.note:
            vault["secrets"][args.name]["note"] = args.note
        save_vault(vault, keys)
        return {"ok": True, "data": f"Set {args.name}.{args.key}"}

    req = {"cmd": "set", "name": args.name, "key": args.key, "value": args.value}
    if args.note:
        req["note"] = args.note
    resp = cli_or_daemon(req, fallback)
    print(f"{resp['data']} ✓")


def cmd_delete(args: argparse.Namespace) -> None:
    def fallback():
        keys = get_keys()
        if not keys:
            sys.exit("No nsec found and daemon not running.")
        vault = load_vault(keys)
        if not vault:
            sys.exit("No avault.enc found.")
        if args.name not in vault["secrets"]:
            sys.exit(f'Secret "{args.name}" not found.')
        del vault["secrets"][args.name]
        save_vault(vault, keys)
        return {"ok": True, "data": f'Deleted "{args.name}"'}

    resp = cli_or_daemon({"cmd": "delete", "name": args.name}, fallback)
    print(f"{resp['data']} ✓")


def cmd_export(args: argparse.Namespace) -> None:
    def fallback():
        keys = get_keys()
        if not keys:
            sys.exit("No nsec found and daemon not running.")
        vault = load_vault(keys)
        if not vault:
            sys.exit("No avault.enc found.")
        all_vars = {}
        for entry in vault["secrets"].values():
            all_vars.update(entry.get("values", {}))
        return {"ok": True, "data": all_vars}

    resp = cli_or_daemon({"cmd": "export"}, fallback)
    data = resp["data"]
    if args.shell:
        for k, v in data.items():
            # Shell-safe export
            escaped = v.replace("'", "'\\''")
            print(f"export {k}='{escaped}'")
    else:
        for k, v in data.items():
            print(f"{k}={v}")


def cmd_migrate(args: argparse.Namespace) -> None:
    dry_run = getattr(args, "dry_run", False)

    # Migrate always needs local keys (it's a setup operation)
    keys = get_keys()
    if not keys:
        sys.exit("No nsec found.")
    vault = load_vault(keys)
    if not vault:
        sys.exit("No avault.enc found. Run: avault init")

    exports = parse_profile_exports()
    groups = group_exports(exports)

    migrated = 0
    results = []
    for group, values in groups.items():
        if group in vault["secrets"]:
            results.append({"group": group, "status": "skipped", "reason": "already in vault"})
            print(f"⏭  {group}: already in vault, skipping")
            continue
        if dry_run:
            results.append({"group": group, "status": "would_migrate", "keys": list(values.keys())})
            print(f"🔍 {group}: would migrate {', '.join(values.keys())}")
        else:
            vault["secrets"][group] = {
                "values": values,
                "added": today(),
                "rotated": today(),
                "note": "Migrated from ~/.profile",
            }
            results.append({"group": group, "status": "migrated", "keys": list(values.keys())})
            print(f"✓  {group}: {', '.join(values.keys())}")
        migrated += 1

    if not dry_run:
        save_vault(vault, keys)
        print(f"\nMigrated {migrated} secret group(s). Vault re-encrypted.")
    else:
        print(f"\n[DRY RUN] Would migrate {migrated} secret group(s). No changes made.")

    if JSON_OUTPUT:
        output({"migrated": migrated, "dry_run": dry_run, "groups": results})


def cmd_audit(_args: argparse.Namespace) -> None:
    keys = get_keys()
    if not keys:
        sys.exit("No nsec found.")
    vault = load_vault(keys)
    if not vault:
        sys.exit("No avault.enc found.")

    vault_keys = set()
    for entry in vault["secrets"].values():
        vault_keys.update(entry.get("values", {}).keys())

    profile_keys = list(parse_profile_exports().keys())
    not_in_vault = [k for k in profile_keys if k not in vault_keys]
    only_in_vault = [k for k in vault_keys if k not in profile_keys]

    result = {
        "in_sync": not not_in_vault and not only_in_vault,
        "only_in_profile": not_in_vault,
        "only_in_vault": only_in_vault,
    }

    def human(r):
        if r["in_sync"]:
            print("✓ All secrets in sync.")
        else:
            if r["only_in_profile"]:
                print("In ~/.profile but NOT in vault:")
                for k in r["only_in_profile"]:
                    print(f"  ⚠  {k}")
            if r["only_in_vault"]:
                print("\nIn vault but NOT in ~/.profile:")
                for k in r["only_in_vault"]:
                    print(f"  ℹ  {k}")

    output(result, human)


def cmd_doctor(_args: argparse.Namespace) -> None:
    """Check prerequisites and config health."""
    checks = []

    # 1. nostr-sdk importable
    try:
        import nostr_sdk  # noqa: F401
        checks.append({"check": "nostr-sdk", "ok": True, "detail": "installed"})
    except ImportError:
        checks.append({"check": "nostr-sdk", "ok": False, "detail": "pip install nostr-sdk"})

    # 2. nsec available
    nsec = get_nsec_string()
    checks.append({
        "check": "nsec",
        "ok": bool(nsec),
        "detail": "found in env/profile" if nsec else "not found (set NOSTR_NSEC or add to ~/.profile)",
    })

    # 3. Vault file exists
    checks.append({
        "check": "avault.enc",
        "ok": VAULT_FILE.exists(),
        "detail": str(VAULT_FILE) if VAULT_FILE.exists() else "not found — run: avault init",
    })

    # 4. nsec.enc exists
    checks.append({
        "check": "nsec.enc",
        "ok": NSEC_ENC_FILE.exists(),
        "detail": str(NSEC_ENC_FILE) if NSEC_ENC_FILE.exists() else "not found — run: avault init",
    })

    # 5. nip46.json exists and valid
    nip46_ok = False
    nip46_detail = "not found"
    if NIP46_FILE.exists():
        try:
            cfg = json.loads(NIP46_FILE.read_text())
            if cfg.get("signer_npub") and cfg.get("agent_npub"):
                nip46_ok = True
                nip46_detail = f"signer={cfg['signer_npub'][:20]}..."
            else:
                nip46_detail = "missing signer_npub or agent_npub"
        except json.JSONDecodeError:
            nip46_detail = "invalid JSON"
    checks.append({"check": "nip46.json", "ok": nip46_ok, "detail": nip46_detail})

    # 6. Vault decryptable (only if nsec + vault exist)
    if nsec and VAULT_FILE.exists():
        try:
            keys = Keys.parse(nsec)
            v = load_vault(keys)
            if v:
                checks.append({
                    "check": "vault_decrypt",
                    "ok": True,
                    "detail": f"{len(v['secrets'])} secret(s), version {v.get('version', '?')}",
                })
            else:
                checks.append({"check": "vault_decrypt", "ok": False, "detail": "decrypt returned None"})
        except Exception as e:
            checks.append({"check": "vault_decrypt", "ok": False, "detail": str(e)})
    else:
        checks.append({"check": "vault_decrypt", "ok": False, "detail": "skipped (no nsec or vault)"})

    # 7. Daemon running
    if daemon_running():
        resp = daemon_request({"cmd": "status"})
        checks.append({
            "check": "daemon",
            "ok": resp.get("ok", False),
            "detail": f"{resp['data']['secrets_count']} secret(s) in RAM" if resp.get("ok") else resp.get("error", "not responding"),
        })
    else:
        checks.append({"check": "daemon", "ok": False, "detail": "not running"})

    # 8. Git repo (for auto-commit)
    git_ok = (WORKSPACE / ".git").is_dir()
    checks.append({
        "check": "git_repo",
        "ok": git_ok,
        "detail": "workspace is a git repo" if git_ok else "no .git — auto-commit won't work",
    })

    # Output
    all_ok = all(c["ok"] for c in checks)

    def human(cs):
        for c in cs:
            icon = "✅" if c["ok"] else "❌"
            print(f"  {icon} {c['check']:<20} {c['detail']}")
        print()
        if all_ok:
            print("All checks passed. ✓")
        else:
            failed = sum(1 for c in cs if not c["ok"])
            print(f"{failed} check(s) need attention.")

    output({"checks": checks, "all_ok": all_ok}, lambda d: human(d["checks"]))

    if not all_ok:
        sys.exit(1)


def cmd_stale(args: argparse.Namespace) -> None:
    """Flag secrets not rotated within threshold."""
    days = args.days

    def get_vault():
        if daemon_running():
            resp = daemon_request({"cmd": "list"})
            if resp.get("ok"):
                return resp["data"]
        keys = get_keys()
        if not keys:
            sys.exit("No nsec found and daemon not running.")
        vault = load_vault(keys)
        if not vault:
            sys.exit("No avault.enc found.")
        return {
            name: {
                "keys": list(e.get("values", {}).keys()),
                "added": e.get("added", "-"),
                "rotated": e.get("rotated", "-"),
                "note": e.get("note", ""),
            }
            for name, e in vault["secrets"].items()
        }

    data = get_vault()
    today_dt = datetime.now(timezone.utc).date()
    stale = []
    fresh = []

    for name, info in data.items():
        rotated = info.get("rotated", info.get("added", "-"))
        if rotated == "-":
            stale.append({"name": name, "rotated": rotated, "age_days": None})
            continue
        try:
            rot_date = datetime.strptime(rotated, "%Y-%m-%d").date()
            age = (today_dt - rot_date).days
            if age > days:
                stale.append({"name": name, "rotated": rotated, "age_days": age})
            else:
                fresh.append({"name": name, "rotated": rotated, "age_days": age})
        except ValueError:
            stale.append({"name": name, "rotated": rotated, "age_days": None})

    result = {"threshold_days": days, "stale": stale, "fresh": fresh}

    def human(r):
        if r["stale"]:
            print(f"⚠  Secrets not rotated in {r['threshold_days']}+ days:")
            for s in r["stale"]:
                age_str = f"{s['age_days']}d ago" if s["age_days"] is not None else "unknown"
                print(f"  🔴 {s['name']:<20} rotated: {s['rotated']:<12} ({age_str})")
        else:
            print(f"✅ All secrets rotated within {r['threshold_days']} days.")
        if r["fresh"]:
            print(f"\n  Fresh ({len(r['fresh'])}):")
            for s in r["fresh"]:
                print(f"  🟢 {s['name']:<20} rotated: {s['rotated']:<12} ({s['age_days']}d ago)")

    output(result, human)


# --- CLI ---

def main():
    parser = argparse.ArgumentParser(
        prog="avault",
        description="Agent Vault — NIP-44 encrypted secrets with NIP-46 remote signing",
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    sub = parser.add_subparsers(dest="command")

    # daemon
    p_daemon = sub.add_parser("daemon", help="Manage the vault daemon")
    daemon_sub = p_daemon.add_subparsers(dest="daemon_cmd")
    p_start = daemon_sub.add_parser("start", help="Start daemon")
    p_start.add_argument("--foreground", "-f", action="store_true", default=True,
                         help="Run in foreground (default)")
    p_start.add_argument("--background", "-b", action="store_true",
                         help="Fork to background")
    p_start.add_argument("--timeout", type=int, default=120,
                         help="NIP-46 connection timeout in seconds")
    daemon_sub.add_parser("stop", help="Stop daemon")
    daemon_sub.add_parser("status", help="Check daemon status")

    # init
    p_init = sub.add_parser("init", help="Initialize vault")
    p_init.add_argument("--signer-npub", required=True, help="Operator's npub")

    # unlock
    sub.add_parser("unlock", help="Verify vault access")

    # list
    sub.add_parser("list", help="List secrets")

    # get
    p_get = sub.add_parser("get", help="Get a secret")
    p_get.add_argument("name", help="Secret name")
    p_get.add_argument("--key", help="Specific key within the secret")

    # set
    p_set = sub.add_parser("set", help="Set a secret")
    p_set.add_argument("name", help="Secret name")
    p_set.add_argument("--key", required=True, help="Key name")
    p_set.add_argument("--value", required=True, help="Value")
    p_set.add_argument("--note", help="Optional note")

    # delete
    p_del = sub.add_parser("delete", help="Remove a secret")
    p_del.add_argument("name", help="Secret name")

    # export
    p_export = sub.add_parser("export", help="Export all secrets as env vars")
    p_export.add_argument("--shell", action="store_true", help="Output as shell export statements")

    # migrate
    p_migrate = sub.add_parser("migrate", help="Import secrets from ~/.profile")
    p_migrate.add_argument("--dry-run", action="store_true", help="Show what would be migrated without making changes")

    # audit
    sub.add_parser("audit", help="Compare ~/.profile vs vault")

    # doctor
    sub.add_parser("doctor", help="Check prerequisites and config health")

    # stale
    p_stale = sub.add_parser("stale", help="Flag secrets not rotated recently")
    p_stale.add_argument("--days", type=int, default=90, help="Staleness threshold in days (default: 90)")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Set global JSON flag
    global JSON_OUTPUT
    JSON_OUTPUT = getattr(args, "json", False)

    # Handle --background flag for daemon start
    if args.command == "daemon" and getattr(args, "background", False):
        args.foreground = False

    commands = {
        "daemon": cmd_daemon,
        "init": cmd_init,
        "unlock": cmd_unlock,
        "list": cmd_list,
        "get": cmd_get,
        "set": cmd_set,
        "delete": cmd_delete,
        "export": cmd_export,
        "migrate": cmd_migrate,
        "audit": cmd_audit,
        "doctor": cmd_doctor,
        "stale": cmd_stale,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
