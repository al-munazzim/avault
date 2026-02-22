---
name: avault-unlock
description: "Start avault daemon and request NIP-46 vault unlock from operator's signer (Amber)"
metadata:
  {
    "openclaw":
      {
        "emoji": "🔐",
        "events": ["gateway:startup"],
        "requires": { "bins": ["python3"], "config": ["workspace.dir"] },
      },
  }
---

# avault Unlock Hook

Starts the avault daemon on gateway startup and initiates NIP-46 unlock flow.
The operator must approve the decrypt request in their Nostr signer (Amber/nsec.app).

## What it does

1. Checks if avault daemon is already running (skip if so)
2. Starts `avault daemon start` in background
3. Daemon connects to relay, sends NIP-46 decrypt request to operator's signer
4. Operator approves → agent's nsec decrypted in RAM → vault unlocked
5. Secrets available via unix socket until daemon stops or reboot

## Requirements

- `avault.enc` — encrypted vault (in workspace)
- `nsec.enc` — agent nsec encrypted to operator's npub
- `nip46.json` — NIP-46 connection config (signer npub, relay)
- `scripts/avault.py` — the vault CLI
- Operator's Nostr signer must be online to approve

## If operator doesn't approve

Agent runs without secrets. Scripts that need API keys degrade gracefully.
Next gateway restart will try again.
