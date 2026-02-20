# NIP-46 Flow with Amber — Complete Walkthrough

## Overview

avault uses NIP-46 (Nostr Connect) to let an operator's phone (running Amber signer)
act as a hardware key for the agent's vault. The agent never stores its nsec in
plaintext on disk — it's encrypted, and only the operator's signer can decrypt it.

## Prerequisites

1. **Amber** installed on operator's phone (Android) — [github.com/greenart7c3/Amber](https://github.com/greenart7c3/Amber)
2. Operator's Nostr keypair loaded in Amber
3. Agent and Amber share at least one relay (default: `wss://relay.damus.io`)

## First-Time Setup

### 1. Initialize the vault

```bash
avault init --signer-npub npub1... --agent-name "Nazim"
```

This creates:
- `avault.enc` — empty vault, encrypted with agent's nsec (self-encrypt)
- `nsec.enc` — agent's nsec, encrypted TO the operator's npub
- `nip46.json` — connection config (public: signer npub, agent npub, agent name, relay)

### 2. Start the daemon

```bash
avault daemon start
```

The daemon:
1. Reads `nip46.json` for connection parameters
2. Connects to relay
3. Sends NIP-46 `connect` request to operator's signer
4. **Operator approves in Amber** (first time: "New app wants to connect")
5. Sends NIP-44 decrypt request for `nsec.enc`
6. **Operator approves decrypt in Amber** (or set to auto-approve)
7. Receives decrypted nsec → holds in RAM
8. Decrypts `avault.enc` using nsec
9. Serves secrets over unix socket

### 3. Amber Permissions (Recommended)

In Amber → App Permissions → avault (or your agent name):
- **NIP-44 decrypt**: Set to "Auto-approve" (so daemon can start unattended)
- **Connect**: "Auto-approve"
- Everything else: "Always ask" or "Reject"

## Subsequent Boots

On daemon restart, the flow is the same but Amber already has the app
paired, so it sends an "ack" instead of a full connect response. avault
handles this gracefully.

## Ephemeral Mode (No nsec on disk)

If no `NOSTR_NSEC` is available (fresh agent, nsec-free deployment):

1. Daemon generates ephemeral keypair
2. Displays a **QR code** in the terminal
3. Operator scans QR with Amber → approves new app
4. Daemon receives the nsec via NIP-46 decrypt of `nsec.enc`
5. Agent identity only exists in RAM while daemon runs

```
avault daemon start

⏳ Connecting to signer via NIP-46 (ephemeral identity)...
   ⚠️  New app key — approve in your signer!

📱 Scan this QR code with your Nostr signer (Amber):

   ▀█▀▄█▀▄▀█▀▄ ...
   ...

   Or paste this URI manually:
   nostrconnect://abc123...?relay=wss://relay.damus.io&secret=...&metadata={"name":"Nazim"}
```

## Troubleshooting

See [troubleshooting.md](troubleshooting.md) for common errors:
- "ack" response handling
- NIP-44 decrypt timeout
- Relay mismatch
- Stale socket cleanup

## Security Model

```
┌─────────────────────────────────────────────────┐
│                  DISK (safe to commit)           │
│                                                  │
│  avault.enc ← NIP-44(agent_sk, agent_pk, vault) │
│  nsec.enc   ← NIP-44(agent_sk, signer_pk, nsec) │
│  nip46.json ← {signer_npub, agent_npub, relay}  │
└─────────────────────────────────────────────────┘
                        │
                   daemon start
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│              RELAY (transport only)              │
│                                                  │
│  NIP-46 connect request → Amber                 │
│  NIP-46 nip44_decrypt(nsec.enc) → Amber         │
└─────────────────────────────────────────────────┘
                        │
                  Amber approves
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│                RAM ONLY (daemon)                 │
│                                                  │
│  nsec (decrypted) → Keys                        │
│  vault (decrypted) → dict of secrets             │
│  unix socket → CLI access (owner-only, 0600)     │
└─────────────────────────────────────────────────┘
```

**What an attacker with disk access gets:** Two ciphertext blobs and a public config file.
Without the operator's signer, they cannot decrypt anything.

**What an attacker with RAM access gets:** Everything — but that requires root on the
running machine, at which point you have bigger problems.
