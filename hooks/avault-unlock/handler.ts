/**
 * avault-unlock hook — starts avault daemon on gateway startup.
 *
 * Flow:
 * 1. gateway:startup event fires
 * 2. Check if daemon already running (socket exists + responds)
 * 3. If not: spawn `avault daemon start` in background
 * 4. Daemon does NIP-46 handshake with operator's Amber
 * 5. On success: secrets available, notify operator
 * 6. On timeout/failure: agent runs without secrets
 */

import { execFile, spawn } from "node:child_process";
import { access } from "node:fs/promises";
import path from "node:path";
import net from "node:net";

// Types — keep it simple, just match the hook handler signature
type HookHandler = (event: {
  type: string;
  action: string;
  sessionKey: string;
  timestamp: Date;
  messages: string[];
  context: {
    workspaceDir?: string;
    cfg?: any;
  };
}) => Promise<void>;

const SOCKET_NAME = "avault.sock";
const DAEMON_TIMEOUT_SECS = 300;

function getSocketPath(): string {
  const xdg = process.env.XDG_RUNTIME_DIR || `/run/user/${process.getuid?.() ?? 1000}`;
  return path.join(xdg, SOCKET_NAME);
}

function isDaemonRunning(socketPath: string): Promise<boolean> {
  return new Promise((resolve) => {
    const client = net.createConnection({ path: socketPath }, () => {
      // Send a status request
      const req = JSON.stringify({ cmd: "status" });
      const lenBuf = Buffer.alloc(4);
      lenBuf.writeUInt32BE(req.length);
      client.write(lenBuf);
      client.write(req);
    });

    let data = Buffer.alloc(0);
    client.on("data", (chunk) => {
      data = Buffer.concat([data, chunk]);
      if (data.length >= 4) {
        const msgLen = data.readUInt32BE(0);
        if (data.length >= 4 + msgLen) {
          try {
            const resp = JSON.parse(data.subarray(4, 4 + msgLen).toString());
            resolve(resp.ok === true);
          } catch {
            resolve(false);
          }
          client.destroy();
        }
      }
    });

    client.on("error", () => resolve(false));
    client.setTimeout(2000, () => {
      client.destroy();
      resolve(false);
    });
  });
}

const handler: HookHandler = async (event) => {
  if (event.type !== "gateway" || event.action !== "startup") {
    return;
  }

  const workspaceDir = event.context.workspaceDir;
  if (!workspaceDir) {
    console.log("[avault-unlock] No workspace dir, skipping");
    return;
  }

  const avaultScript = path.join(workspaceDir, "scripts", "avault.py");
  const avaultEnc = path.join(workspaceDir, "avault.enc");

  // Check prerequisites
  try {
    await access(avaultScript);
    await access(avaultEnc);
  } catch {
    console.log("[avault-unlock] avault.py or avault.enc not found, skipping");
    return;
  }

  const socketPath = getSocketPath();

  // Check if already running
  if (await isDaemonRunning(socketPath)) {
    console.log("[avault-unlock] Daemon already running, skipping");
    return;
  }

  console.log("[avault-unlock] Starting avault daemon (NIP-46 unlock)...");
  console.log("[avault-unlock] Waiting for operator approval in Nostr signer...");

  // Spawn daemon in background — it will block until Amber approves or timeout
  const daemon = spawn("python3", [
    avaultScript, "daemon", "start", "--foreground",
    "--timeout", String(DAEMON_TIMEOUT_SECS),
  ], {
    cwd: workspaceDir,
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
    env: { ...process.env },
  });

  // Don't let the daemon keep the gateway alive
  daemon.unref();

  // Wait for daemon to become ready (poll socket) or timeout
  const startTime = Date.now();
  const pollInterval = 2000; // 2 seconds
  const maxWait = (DAEMON_TIMEOUT_SECS + 10) * 1000;

  const waitForDaemon = (): Promise<boolean> => {
    return new Promise((resolve) => {
      const check = async () => {
        if (Date.now() - startTime > maxWait) {
          resolve(false);
          return;
        }
        if (await isDaemonRunning(socketPath)) {
          resolve(true);
          return;
        }
        setTimeout(check, pollInterval);
      };
      check();
    });
  };

  // Log daemon output
  daemon.stdout?.on("data", (data: Buffer) => {
    const lines = data.toString().trim().split("\n");
    lines.forEach((line: string) => console.log(`[avault-unlock] ${line}`));
  });
  daemon.stderr?.on("data", (data: Buffer) => {
    const lines = data.toString().trim().split("\n");
    lines.forEach((line: string) => console.log(`[avault-unlock] ${line}`));
  });

  // Fire and forget — don't block gateway startup
  waitForDaemon().then((success) => {
    if (success) {
      console.log("[avault-unlock] ✅ Vault unlocked! Secrets available.");
      event.messages.push("🔓 Vault unlocked — all secrets loaded into RAM.");
    } else {
      console.log("[avault-unlock] ⚠️ Vault unlock timed out. Running without secrets.");
      event.messages.push("⚠️ Vault unlock timed out — running without secrets. Restart gateway to retry.");
    }
  });
};

export default handler;
