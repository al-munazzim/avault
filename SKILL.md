---
name: avault
description: NIP-44 encrypted secret vault with NIP-46 remote signing. Use when managing agent secrets (API keys, tokens, credentials), bootstrapping agent identity, or setting up operator-controlled secret access via Nostr signers (Amber, nsec.app). Secrets live in RAM only when the daemon runs — disk holds only ciphertext.
---

# avault — Agent Vault

Encrypted secret management for AI agents. Operator's phone (Nostr signer) acts as hardware key.

## Architecture

```
On disk (safe to commit):          In RAM (daemon only):
  avault.enc  — NIP-44 ciphertext    nsec (agent identity)
  nsec.enc    — nsec encrypted       decrypted vault (all secrets)
  nip46.json  — public connection    NIP-46 session
```

**Daemon** (`avault daemon start`): connects to operator's signer via NIP-46, decrypts nsec, decrypts vault, serves secrets over unix socket. Kill it → secrets gone.

**CLI** (`avault get/set/list/...`): talks to daemon via socket. Falls back to local nsec if daemon isn't running.

## Dependencies

- Python 3.11+
- `nostr-sdk` (rust-nostr Python bindings): `pip install nostr-sdk`
- Optional: `qrcode[pil]` for QR generation

## Setup

### 1. Initialize vault

```bash
# Creates avault.enc (empty vault) + nsec.enc (agent nsec encrypted to operator)
# + nip46.json (connection config)
avault init --signer-npub <operator-npub>
```

If no nsec exists, one is generated and written to `~/.profile`.

### 2. Migrate existing secrets

```bash
# Imports export KEY=VALUE from ~/.profile, groups by service prefix
avault migrate
```

### 3. Start daemon (RAM-only mode)

```bash
avault daemon start          # foreground (default)
avault daemon start -b       # background (fork)
```

On start:
1. Connects to operator's Nostr signer (Amber/nsec.app) via NIP-46
2. Signer decrypts `nsec.enc` → agent nsec in RAM
3. nsec decrypts `avault.enc` → all secrets in RAM
4. Listens on unix socket (`$XDG_RUNTIME_DIR/avault.sock`, mode 0600)

Operator must approve in their signer app.

### 4. Use secrets

```bash
avault list                              # show all secret groups
avault get blink --key BLINK_API_KEY     # single value
avault get blink                         # all key=value pairs
avault set myservice --key TOKEN --value abc123
avault delete myservice
avault export --shell                    # export KEY='value' for all secrets
avault audit                             # compare vault vs ~/.profile
```

### 5. Stop daemon

```bash
avault daemon stop      # wipes RAM, removes socket
avault daemon status    # check if running
```

## Commands Reference

| Command | Description |
|---------|-------------|
| `init --signer-npub <npub>` | Initialize vault + encrypt nsec for operator |
| `daemon start [-b] [--timeout N]` | Start daemon with NIP-46 unlock |
| `daemon stop` | Stop daemon, wipe secrets from RAM |
| `daemon status` | Check daemon status |
| `unlock` | Verify vault access (no daemon needed if nsec available) |
| `list` | List secret groups + metadata |
| `get <name> [--key K]` | Get secret value(s) |
| `set <name> --key K --value V [--note N]` | Add/update a secret |
| `delete <name>` | Remove a secret group |
| `export [--shell]` | Export all secrets as env vars |
| `migrate` | Import from `~/.profile` |
| `audit` | Compare `~/.profile` vs vault |

## Security Model

- **nsec never on disk** (once daemon mode is adopted): agent identity lives in RAM only
- **NIP-44 v2** (XChaCha20-Poly1305): vault encrypted with agent's own key (self-encrypt)
- **nsec.enc**: agent's nsec encrypted to operator's pubkey — disaster recovery
- **Unix socket**: mode 0600, only agent's user can connect
- **Signer approval**: each daemon start requires operator's NIP-46 signer approval
- **Kill = wipe**: daemon stop or reboot erases all secrets from memory

## NIP-46 Signer Setup

The operator needs a NIP-46 compatible signer:
- **Amber** (Android): Best option. Auto-approve or manual per-permission.
- **nsec.app** (browser): Good for desktop testing.

After `avault init`, the agent's pubkey is registered. The signer must:
1. Have the relay from `nip46.json` enabled (default: `wss://relay.damus.io`)
2. Approve the agent's app key (shown during first connect)
3. Allow NIP-44 decrypt permission (needed to unlock `nsec.enc`)

## Integration with Agent Workflows

Source secrets into environment:
```bash
eval $(avault export --shell)
```

Or query individual values in scripts:
```python
import subprocess
token = subprocess.check_output(
    ["python3", "avault.py", "get", "blink", "--key", "BLINK_API_KEY"],
    text=True
).strip()
```

## Troubleshooting

See [references/troubleshooting.md](references/troubleshooting.md) for common issues (NIP-46 timeouts, Amber permissions, relay mismatches).
