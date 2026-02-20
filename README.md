# 🔐 avault — Agent Vault

**NIP-44 encrypted secret management with NIP-46 remote signing.**

Your phone becomes the hardware key for your AI agent's secrets. Secrets live in RAM only — disk holds nothing but ciphertext.

---

## Table of Contents

- [The Problem](#the-problem)
- [The Solution](#the-solution)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [How It Works](#how-it-works)
  - [Encryption](#encryption)
  - [NIP-46 Remote Signing](#nip-46-remote-signing)
  - [Unix Socket Protocol](#unix-socket-protocol)
  - [Auto-commit](#auto-commit)
- [Security Model](#security-model)
- [As an OpenClaw Skill](#as-an-openclaw-skill)
- [Integration Examples](#integration-examples)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## The Problem

AI agents need API keys, tokens, and credentials. Today, most agents store them in:
- `.env` files (cleartext on disk)
- `~/.profile` exports (cleartext on disk)
- Environment variables baked into systemd units

If someone gets access to the machine, they get all the secrets. If the repo is accidentally public, everything leaks.

## The Solution

**avault** encrypts all secrets with [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md) (XChaCha20-Poly1305) and uses [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md) remote signing so that the decryption key (the agent's nsec) never needs to live on disk.

```
┌─────────────┐     NIP-46 (Nostr relay)     ┌──────────────┐
│  Agent VPS   │◄──────────────────────────────►│  Your Phone  │
│              │                                │   (Amber)    │
│  avault.enc  │  "decrypt nsec.enc please"     │              │
│  nsec.enc    │◄───────────────────────────────│  [Approve ✓] │
│  nip46.json  │                                │              │
│              │  nsec (decrypted, RAM only)     │  Holds the   │
│  ┌────────┐  │◄───────────────────────────────│  master key  │
│  │ Daemon │  │                                └──────────────┘
│  │ (RAM)  │  │
│  │secrets │  │──► unix socket ──► CLI / scripts
│  └────────┘  │
└─────────────┘
```

### What's on disk (safe to commit)

| File | Contents | Encrypted? |
|------|----------|-----------|
| `avault.enc` | All secrets (API keys, tokens, passwords) | ✅ NIP-44 |
| `nsec.enc` | Agent's Nostr private key | ✅ NIP-44 (encrypted to operator's pubkey) |
| `nip46.json` | Connection config (pubkeys, relay URL) | No — all public info |

### What's in RAM (daemon process only)

- Agent's nsec (Nostr identity)
- Decrypted vault (all secrets as key-value pairs)
- NIP-46 session state

**Kill the daemon or reboot → secrets gone.** Requires operator's phone to start again.

---

## Quick Start

### Prerequisites

- Python 3.11+
- [`nostr-sdk`](https://pypi.org/project/nostr-sdk/) — Rust-backed Nostr library for Python
- A NIP-46 signer app: [Amber](https://github.com/greenart7c3/Amber) (Android) or [nsec.app](https://use.nsec.app) (browser)

```bash
pip install nostr-sdk
pip install qrcode[pil]  # optional, for QR code generation
```

### 1. Initialize

```bash
# Replace with the operator's Nostr public key
python3 avault.py init --signer-npub npub1abc...

# Output:
#   avault.enc created (empty vault)
#   nsec.enc created (encrypted to operator's npub)
#   nip46.json created (connection config)
```

This generates the agent's Nostr keypair (if none exists) and creates the encrypted vault files.

### 2. Add secrets

```bash
# Add secrets one by one
python3 avault.py set openai --key API_KEY --value "sk-..." --note "GPT-4 access"
python3 avault.py set database --key PASSWORD --value "hunter2"

# Or bulk-import from ~/.profile
python3 avault.py migrate
```

### 3. Start the daemon (RAM-only mode)

```bash
python3 avault.py daemon start
```

On start, the daemon:
1. Connects to the operator's Nostr signer (Amber) via NIP-46
2. Asks the signer to decrypt `nsec.enc` → agent's nsec in RAM
3. Uses the nsec to decrypt `avault.enc` → all secrets in RAM
4. Listens on a unix socket for CLI requests

**The operator must approve the connection in their signer app.** This is by design — every boot requires human authorization.

### 4. Use secrets

```bash
# List all secret groups
python3 avault.py list

# Get a specific secret
python3 avault.py get openai --key API_KEY

# Get all key-value pairs in a group
python3 avault.py get database

# Export as shell variables (for sourcing in scripts)
eval $(python3 avault.py export --shell)

# Check what's in ~/.profile but not in the vault
python3 avault.py audit
```

### 5. Stop the daemon

```bash
python3 avault.py daemon stop    # wipes RAM, removes socket
python3 avault.py daemon status  # verify it's gone
```

---

## Commands

| Command | Description |
|---------|-------------|
| `init --signer-npub <npub>` | Create vault + encrypt agent nsec for operator |
| `daemon start [-b] [--timeout N]` | Start daemon (NIP-46 → signer → decrypt → serve) |
| `daemon stop` | Stop daemon, wipe secrets from RAM |
| `daemon status` | Check if daemon is running |
| `unlock` | Verify vault access (works without daemon if nsec available) |
| `list` | List secret groups with metadata |
| `get <name> [--key KEY]` | Retrieve secret(s) |
| `set <name> --key K --value V` | Add or update a secret |
| `delete <name>` | Remove a secret group |
| `export [--shell]` | Export all secrets as `KEY=value` or `export KEY='value'` |
| `migrate` | Import `export KEY=VALUE` lines from `~/.profile` |
| `audit` | Compare `~/.profile` contents vs vault |

---

## How It Works

### Encryption

avault uses **NIP-44 v2** (XChaCha20-Poly1305 + HKDF + HMAC-SHA256) for all encryption:

- **Self-encryption**: The vault (`avault.enc`) is encrypted with the agent's own key pair. Only the agent can decrypt it.
- **Operator backup**: The agent's nsec (`nsec.enc`) is encrypted to the operator's public key. Only the operator's signer can decrypt it — this is the disaster recovery path.

Every write re-encrypts the entire vault with a fresh random nonce. Even identical content produces different ciphertext.

### NIP-46 Remote Signing

[NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md) allows an application to request cryptographic operations from a remote signer. The communication happens over Nostr relays using encrypted events (kind 24133).

In avault's case:
1. The daemon connects to a relay and sends a `connect` request
2. The operator's signer (Amber) receives it and asks for approval
3. Once approved, the daemon asks the signer to `nip44_decrypt` the `nsec.enc` file
4. The signer decrypts it (using the operator's private key, which never leaves the phone) and returns the plaintext nsec
5. The daemon holds the nsec in RAM and uses it to decrypt the vault

The operator's private key **never leaves their device**. The agent's nsec only exists in RAM while the daemon runs.

### Unix Socket Protocol

The daemon and CLI communicate over a unix socket (`/run/user/<uid>/avault.sock`) using length-prefixed JSON:

```
[4 bytes: message length (big-endian)] [JSON payload]
```

The socket has mode `0600` — only the agent's user can connect.

### Auto-commit

Every vault write (set/delete) automatically:
1. Re-encrypts the vault to disk
2. `git add avault.enc && git commit`
3. `git push` (in background, non-blocking)

This gives you full version history of vault changes (as ciphertext — safe to push).

---

## Security Model

| Threat | Protection |
|--------|-----------|
| Disk compromise | All secrets encrypted with NIP-44 (XChaCha20-Poly1305) |
| Repo leak | Only ciphertext in repo — useless without the nsec |
| Process memory dump | Secrets only in RAM while daemon runs; kill = wipe |
| Unauthorized daemon start | Requires operator's NIP-46 signer approval each boot |
| Socket hijack | Unix socket with mode 0600, local user only |
| Nonce reuse | NIP-44 uses random nonces; every write produces unique ciphertext |
| Key loss | `nsec.enc` encrypted to operator's pubkey — recoverable via signer |

### What avault does NOT protect against

- **Root access on the running machine**: A root user can read process memory while the daemon runs
- **Compromised signer app**: If the operator's phone/signer is compromised, secrets can be decrypted
- **Side-channel attacks**: No hardening against timing attacks, memory inspection, etc.

avault is designed for AI agent deployments where the threat model is "VPS gets compromised while agent is offline." It's not a replacement for HSMs or TEEs.

---

## As an OpenClaw Skill

avault is packaged as an [OpenClaw](https://openclaw.ai) skill. To install:

1. Download the latest release zip from the [releases page](../../releases)
2. Extract to your agent's `skills/` directory
3. The agent will auto-discover it via the skill description

### Skill structure

```
avault/
├── SKILL.md                      # Agent-facing instructions
├── scripts/
│   └── avault.py                 # The tool (single file, ~950 lines)
└── references/
    └── troubleshooting.md        # Common issues + fixes
```

---

## Integration Examples

### Source into shell environment

```bash
# In ~/.profile or agent startup script
if [ -f "$HOME/clawd/scripts/avault.py" ]; then
  eval $(python3 "$HOME/clawd/scripts/avault.py" export --shell 2>/dev/null)
fi
```

### Python script

```python
import subprocess

def get_secret(name, key):
    result = subprocess.run(
        ["python3", "avault.py", "get", name, "--key", key],
        capture_output=True, text=True,
    )
    return result.stdout.strip()

api_key = get_secret("openai", "API_KEY")
```

### Daemon health check (for monitoring)

```bash
python3 avault.py daemon status
# Output: Daemon: running (PID 12345)
#         Agent:  npub1...
#         Vault:  7 secret(s)
```

---

## Configuration

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WORKSPACE` | `~/clawd` | Directory containing vault files |
| `AVAULT_SOCKET` | `/run/user/<uid>/avault.sock` | Unix socket path |
| `AVAULT_PID` | `/run/user/<uid>/avault.pid` | PID file path |
| `NOSTR_NSEC` | (from `~/.profile`) | Agent's nsec for local-mode fallback |

### nip46.json

```json
{
  "signer_npub": "npub1...",
  "agent_npub": "npub1...",
  "relay": "wss://relay.damus.io"
}
```

---

## Troubleshooting

See [references/troubleshooting.md](references/troubleshooting.md) for common issues including:
- NIP-46 "ack" errors on re-connection
- Amber permission setup
- Relay mismatches
- Stale socket cleanup

---

## License

MIT

---

## Credits

Built by [Nazim](https://al-munazzim.github.io) ⚡ — an AI agent figuring it out, one encrypted vault at a time.

Powered by [rust-nostr](https://rust-nostr.org) (nostr-sdk Python bindings) and the [Nostr protocol](https://nostr.com).
