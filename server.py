import os
import ssl
import time
import json
import base64
import hashlib
import requests
import threading
import subprocess
import pymem as pm
import psutil as ps
from urllib.parse import parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# ----------------------------------------------------------------
# You can grab the pubkey via x64dbg - or anything that can
# View strings during runtime
# Pro tip: x64dbg , all strings references , regex [a-zA-Z0-9]{64}
# ----------------------------------------------------------------
# Grab the pubkey offset via Cheat Engine.
# I won't be reading the entire mem just for this.
# ----------------------------------------------------------------

os.system("cls||clear")

# Hozinum has blacklisted process names, need to check
blacklist_proc = {
    "snippingtool.exe",
    "snipping tool",
    "x64dbg",
    "x32dbg",
    "ollydbg",
    "windbg",
    "dbgview",
    "ida",
    "idag",
    "idaw",
    "idau",
    "idaq",
    "idaq64",
    "immunitydebugger",
    "gdb",
    "lldb",
    "radare2",
    "r2",
    "r2ghidra",
    "dnSpy",
    "ilspy",
    "de4dot",
    "dbx",
    "edb-debugger",
    "ghidra",
    "cutter",
    "retdec",
    "snowman",
    "binja",
    "binaryninja",
    "hexrays",
    "jd-gui",
    "bytecode-viewer",
    "fernflower",
    "procyon",
    "cfr",
    "jadx",
    "apktool",
    "cheatengine",
    "cheat engine",
    "artmoney",
    "gamehacking",
    "squalr",
    "scanmem",
    "memhack",
    "memoryedit",
    "scylla",
    "scylla_x64",
    "scylla_x86",
    "extremedumper",
    "memed",
    "memwrite",
    "hacksaw",
    "memscanner",
    "gameconqueror",
    "bit slicer",
    "processhacker",
    "procexp",
    "procexp64",
    "procmon",
    "procmon64",
    "injector",
    "extremeinjector",
    "processinjector",
    "dllinjector",
    "xinject",
    "winject",
    "gh-injector",
    "manualmap",
    "kernelmapper",
    "xprocess",
    "sysinternals",
    "processlasso",
    "injectx",
    "remoteinjector",
    "reshacker",
    "resourcehacker",
    "hxd",
    "hexeditor",
    "universalpatcher",
    "patcher",
    "cracktool",
    "crackme",
    "serialmaker",
    "keygen",
    "keygenme",
    "sn0int",
    "patchengine",
    "crackz",
    "reverseme",
    "upx",
    "peid",
    "lordpe",
    "pe-explorer",
    "die",
    "detectiteasy",
    "exeinfope",
    "cracklib",
    "fiddler",
    "wireshark",
    "httpdebugger",
    "httpanalyzer",
    "charles",
    "mitmproxy",
    "burpsuite",
    "zaproxy",
    "owasp",
    "netmon",
    "tcpdump",
    "networkminer",
    "ettercap",
    "cain",
    "nmap",
    "zenmap",
    "sandboxie",
    "vbox",
    "vboxservice",
    "vboxtray",
    "vmware",
    "vmtools",
    "vmsrvc",
    "vmusrvc",
    "parallels",
    "qemu",
    "virtualpc",
    "hyper-v",
    "xen",
    "bochs",
    "anubis",
    "cuckoo",
    "joebox",
    "buster",
    "sandbox",
    "megadumper",
    "pe-bear",
    "pestudio",
    "xanalyzer",
    "xanalyzer64",
    "processdump",
    "dumpit",
    "memdump",
    "volatility",
    "rekall",
    "autopsy",
    "xways",
    "ftk",
    "encase",
    "binwalk",
    "foremost",
    "sleuthkit",
    "processmonitor",
    "resmon",
    "frida",
    "gameguardian",
    "lucky patcher",
    "creack",
    "crk",
    "reverser",
    "decompiler",
    "unpacker",
    "upx-unpack",
    "deobfuscator",
    "dex2jar",
    "smali",
    "baksmali",
    "obadiah",
    "angr",
    "pin",
    "dynamorio",
    "valgrind",
    "ghidra-server",
    "r2pipe",
    "capstone",
    "keystone",
    "debugview",
    "ida pro",
    "ida free",
    "immunity debugger",
    "dnspy",
    "edb debugger",
    "binary ninja",
    "hex-rays",
    "bytecode viewer",
    "memory editor",
    "extreme dumper",
    "game conqueror",
    "process hacker",
    "process explorer",
    "process monitor",
    "extreme injector",
    "process injector",
    "dll injector",
    "gh injector",
    "manual map",
    "kernel mapper",
    "process lasso",
    "sysinternals suite",
    "remote injector",
    "resource hacker",
    "hex editor",
    "universal patcher",
    "crack tool",
    "serial maker",
    "patch engine",
    "reverse me",
    "pe explorer",
    "detect it easy",
    "exeinfo pe",
    "http debugger",
    "http analyzer",
    "charles proxy",
    "burp suite",
    "owasp zap",
    "network monitor",
    "network miner",
    "cain and abel",
    "virtualbox",
    "vmware workstation",
    "parallels desktop",
    "virtual pc",
    "anubis sandbox",
    "cuckoo sandbox",
    "joe sandbox",
    "buster sandbox",
    "mega dumper",
    "process dumper",
    "memory dumper",
    "x-ways forensics",
    "ftk imager",
    "sleuth kit",
    "resource monitor",
    "game guardian",
    "ghidra server",
    "obfuscator",
    "reverse engineering",
}
for proc in ps.process_iter(['name']):
    for blacklisted in blacklist_proc:
        if proc.info['name'].startswith(blacklisted):
            print(f"[!!!!] {blacklisted} is a blacklisted process by Hozinium - please terminate it.\nIf it is a service - make sure to stop it.\nPress enter to continue once it is terminated.")
            xt = input("")

def config_gen():
    print("[#] Creating config file")
    OWNER_ID = str(input("owner_id => "))
    VERSION_NUM = str(input("version_number => "))
    OFFSET_PATCH = str(input("pubkey offset => "))
    ORIG_PUBKEY = str(input("pubkey => "))
    if not len(ORIG_PUBKEY) == int(64):
        print(f"[!] Public key invalid (Length: {len(ORIG_PUBKEY)}, expected: 64)")
        time.sleep(1.5)
        exit()
    PROC_PATH = str(input("process path (drag&drop) => "))
    if not os.path.basename(PROC_PATH).endswith(".exe"):
        print("[!] Invalid process path")
        time.sleep(1.5)
        exit()
    data = {"OWNER_ID": OWNER_ID, "OFFSET_PATCH": OFFSET_PATCH, "ORIG_PUBKEY": ORIG_PUBKEY, "PROC_PATH": PROC_PATH}
    with open("config.json", "w") as f:
        json.dump(data, f)
            

if os.path.isfile("config.json"):
    with open("config.json", "r") as f:
        fr = json.load(f)
        try:
            OFFSET_PATCH = fr["OFFSET_PATCH"]
            ORIG_PUBKEY = fr["ORIG_PUBKEY"]
            PROC_PATH = fr["PROC_PATH"]
            OWNER_ID = fr["OWNER_ID"]
            VERSION_NUM = fr["VERSION_NUM"]
        except KeyError:
            print("[!] Config invalid - regenerating")
            config_gen()
else:
    config_gen()

OFFSET_PATCH = int(OFFSET_PATCH, 16)
PROC_NAME = os.path.basename(PROC_PATH)
USERS = requests.get("https://hozinum.cc/download/external/alpha.txt").text
BLOCKHOST = "keyauth.win"
HOST = "0.0.0.0"
HTTP_PORT = 80
HTTPS_PORT = 443
USERPROFILE = os.getenv("USERPROFILE")
SCRIPTDIR = os.path.dirname(os.path.abspath(__file__))
print("ENTER ONE OF THESE USERS IN THE CHEAT:\n", USERS, "\n\n")

##### Requirements
print("[dbg] Making content files")
if not os.path.isdir("served"):
    os.makedirs("served")
with open("served\\content_init.txt", "w") as f:
    f.write(f"""{{
	"success": true,
	"code": 68,
	"message": "Initialized",
	"sessionid": "5844600e",
	"appinfo": {{
		"numUsers": "N/A - Use fetchStats() function in latest example",
		"numOnlineUsers": "N/A - Use fetchStats() function in latest example",
		"numKeys": "N/A - Use fetchStats() function in latest example",
		"version": "0.1",
		"customerPanelLink": "https://keyauth.cc/panel/Bar/Hozinum/"
	}},
	"newSession": true,
	"nonce": "669a9492-8f3a-4e91-8cb1-1a6be2ae66b8",
	"ownerid": "{OWNER_ID}"
}}""")

with open("served\\content_login.txt", "w") as f:
    f.write(f"""{{
	"success": true,
	"code": 68,
	"message": "Logged in!",
	"info": {{
		"username": "test",
		"subscriptions": [
			{{
				"subscription": "default",
				"key": null,
				"expiry": "1754003700",
				"timeleft": 861902
			}}
		],
		"ip": "185.209.198.214",
		"hwid": "S-1-5-21-911834250-3872903066-1339797541-500",
		"createdate": "1753136110",
		"lastlogin": "1753141798"
	}},
	"nonce": "9a4fa680-2f5d-4fab-b54a-80aded6e790b",
	"ownerid": "{OWNER_ID}"
}}""")

with open("served\\content_check.txt", "w") as f:
    f.write(f"""
{{
	"success": true,
	"code": 68,
	"message": "Session is validated.",
	"nonce": "67277bf6-502d-4c78-a268-803b4d30d286",
	"role": "not_checked",
	"ownerid": "{OWNER_ID}"
}}
""")

##### Patcher
with open(f"{USERPROFILE}\\Documents\\hozinumcert\\ed.key", "rb") as f:
    privkey = serialization.load_pem_private_key(f.read(), password=None)
pubkey = privkey.public_key()
pubkey_bytes = pubkey.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
NEW_PUBKEY = pubkey_bytes.hex().encode()
ORIG_PUBKEY = ORIG_PUBKEY.encode()
print("[dbg] NEW_PUBKEY -> ", NEW_PUBKEY, "\n[dbg] ORIG_PUBKEY -> ", ORIG_PUBKEY)
def find_proc(procname):
    for process in ps.process_iter(['pid', 'name']):
        if process.info['name'] == procname:
            return process
    return None

def writemem(proc_con, addr, new, expect_len):
    if len(new) != expect_len:
        print("[!] Value mismatch - cannot write memory.\n[!] Make sure you have the correct public key...\n\n")
    try:
        proc_con.write_bytes(addr, new, len(new))
        readback = proc_con.read_bytes(addr, len(new))
        if readback == new:
            return True
        else:
            return False
    except pm.exception.MemoryWriteError:
        return False
    except Exception as e:
        return False

##### Server
 
print("Backing up HOSTS file")
open(os.path.join(os.environ['TEMP'], 'hosts.bak'), 'wb').write(open(r'C:\Windows\System32\drivers\etc\hosts', 'rb').read())

print("Sigging initialization request")
with open("served\\content_init.txt", "rb") as f:
    init_body = f.read()
init_sigt = str(int(time.time()))
signature = privkey.sign(init_sigt.encode() + init_body)
init_sigx = signature.hex()
print("[dbg} init_sigt -> ", init_sigt, "\n[dbg] init_sigx -> ", init_sigx)
 
print("Modifying HOSTS file")
with open(r"C:\Windows\System32\drivers\etc\hosts", "w") as f:
    f.write(f"127.0.0.1 {BLOCKHOST}")
 
class ReqHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode()
        print(f"""
\n=== New POST Request ===
Path: {self.path}
Body:\n{body}
""")
 
        post_data = parse_qs(body)
        req_type = post_data.get("type", [None])[0]
 
        if req_type == "init":
            filepath = "served\\content_init.txt"
        elif req_type == "login":
            filepath = "served\\content_login.txt"
        elif req_type == "check":
            filepath = "served\\content_check.txt"
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"[!] Invalid type parameter [!]")
            return
 
        try:
            with open(filepath, "rb") as f:
                content = f.read()
            timestamp = str(int(time.time()))
            sig = privkey.sign(timestamp.encode() + content)
            sig_hex = sig.hex()
 
            print("[dbg] ReqSigX ->", sig_hex)
            print("[dbg] ReqSigT ->", timestamp)
 
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("x-signature-ed25519", sig_hex)
            self.send_header("x-signature-timestamp", timestamp)
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()
            print("[!] Could not find content file")
            self.wfile.write(b"Content file not found")
 
    def do_GET(self):
        print("[!] Attempted GET request")
        self.send_response(400)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(b"[!] Invalid request [!]")
 
def run_http():
    httpd = HTTPServer((HOST, HTTP_PORT), ReqHandler)
    print(f"\nHTTP running - PORT: {HTTP_PORT}")
    httpd.serve_forever()
 
def run_https():
    httpd = HTTPServer((HOST, HTTPS_PORT), ReqHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=f"{USERPROFILE}\\Documents\\hozinumcert\\tls.crt", keyfile=f"{USERPROFILE}\\Documents\\hozinumcert\\tls.key")
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print(f"HTTPS running - PORT: {HTTPS_PORT}\n-------------------------\n")
    httpd.serve_forever()
 
threading.Thread(target=run_http, daemon=True).start()
threading.Thread(target=run_https, daemon=True).start()

len_origkey = len(ORIG_PUBKEY)
try:
    while True:
        target = find_proc(PROC_NAME)
        if not target:
            print(f"Starting {PROC_NAME}")
            try:
                subprocess.Popen([PROC_PATH])
                target = find_proc(PROC_NAME)
                if not target:
                    print(f"Failed to start {PROC_NAME}... Retrying in 5 seconds...")
                    time.sleep(5)
                    continue
            except Exception as e:
                break
        proc_con = None
        try:
            proc_con = pm.Pymem(target.pid)
            base_addr = proc_con.process_base.lpBaseOfDll
            addr_origkey = base_addr + OFFSET_PATCH
            writemem(proc_con, addr_origkey, NEW_PUBKEY, len_origkey)
        except pm.exception.PymemError as e:
            pass
        except Exception as e:
            pass
        finally:
            if proc_con:
                try:
                    proc_con.close_process()
                except Exception as e:
                    pass
except KeyboardInterrupt:
    print("Reverting HOSTS file")
    open(r'C:\Windows\System32\drivers\etc\hosts', 'wb').write(open(os.path.join(os.environ['TEMP'], 'hosts.bak'), 'rb').read())
    print("\nGoodbye.")
    time.sleep(1.5)
