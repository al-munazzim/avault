# Troubleshooting

## "Unexpected response: method=connect, expected=, received=ack"

Amber already has a pairing for this app key. Two fixes:
1. Use the agent's existing nsec as app_keys (daemon does this automatically when nsec is available)
2. Generate a fresh secret in the bunker URI to force a new handshake

## NIP-44 decrypt timeout

Amber needs to approve the decrypt operation. Check:
- Amber → app permissions → NIP-44 decrypt → set to "auto-approve" or manually approve the pending request
- Ensure the relay in `nip46.json` matches Amber's relay list

## Relay mismatch

Both agent and signer must share at least one relay. Default: `wss://relay.damus.io`.
Edit `nip46.json` to change. Amber must have the same relay enabled.

## "Permission denied" on socket

Default socket path: `$XDG_RUNTIME_DIR/avault.sock` or `/tmp/avault-<uid>/avault.sock`.
Override with: `AVAULT_SOCKET=/path/to/avault.sock`

## Daemon won't start (stale socket)

If the daemon crashed without cleanup:
```bash
rm /tmp/avault-$(id -u)/avault.sock
avault daemon start
```

## No nsec and no daemon

In pure nsec-free mode, the daemon generates ephemeral transport keys.
The operator must scan a new QR code (or approve a new app in their signer) on each boot.
This is the most secure mode — agent identity only exists while daemon runs.
