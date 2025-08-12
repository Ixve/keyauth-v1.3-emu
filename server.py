import os
import ssl
import time
import json
import hashlib
import requests
import threading
from urllib.parse import urlparse, parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

os.system("cls||clear")

OWNER_ID = None
VERSION_NUM = None
APP_NAME = None
USER_HWID = ""
SERVER_READY = False
privkey = None

BLOCKHOST = "keyauth.win"
HOST = "0.0.0.0"
HTTP_PORT = 80
HTTPS_PORT = 443
USERPROFILE = os.getenv("USERPROFILE")

try:
    with open(f"{USERPROFILE}\\Documents\\cert\\ed.key", "rb") as f:
        privkey = serialization.load_pem_private_key(f.read(), password=None)
    print("Private key loaded successfully.")
except FileNotFoundError:
    print("[ERROR] Private key not found at expected location!")
    exit(1)

print("Backing up HOSTS file")
open(os.path.join(os.environ['TEMP'], 'hosts.bak'), 'wb').write(open(r'C:\Windows\System32\drivers\etc\hosts', 'rb').read())

print("Modifying HOSTS file")
with open(r"C:\Windows\System32\drivers\etc\hosts", "w") as f:
    f.write(f"127.0.0.1 {BLOCKHOST}")

def create_served_files():
    global OWNER_ID, VERSION_NUM, APP_NAME
    
    print("[dbg] Writing data to serve...")
    
    if not os.path.isdir("served"):
        os.makedirs("served")
    
    ipaddr = requests.get("http://api.ipify.org/").text

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
                    "version": "{VERSION_NUM}",
                    "customerPanelLink": "https://keyauth.cc/panel/"
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
                    "ip": "{ipaddr}",
                    "hwid": "{USER_HWID}",
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

class ReqHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_POST(self):
        global OWNER_ID, VERSION_NUM, APP_NAME, SERVER_READY
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode()
        host = self.headers.get('Host', '').lower()
        path = self.path

        if 'keyauth.win' in host:
            post_data = parse_qs(body)
            req_type = post_data.get("type", [None])[0]
            
            if req_type == "init" and not SERVER_READY:
                
                OWNER_ID = post_data.get("ownerid", [None])[0]
                VERSION_NUM = post_data.get("ver", [None])[0]
                APP_NAME = post_data.get("name", [None])[0]
                
                if not OWNER_ID or not VERSION_NUM or not APP_NAME:
                    print("[dbg] Failed to extract required data from request")
                    print(f"[dbg] Request data: {post_data}")
                    self.send_response(400)
                    self.end_headers()
                    return
                else:
                    print("[dbg] Extracted required data")
                    print(f"[dbg] Owner ID: {OWNER_ID}\n[dbg] Version: {VERSION_NUM}\n[dbg] Application Name: {APP_NAME}")
                    create_served_files()
                    SERVER_READY = True
                    print("[dbg] Server is fully ready")
                    print("\n-------------------------\n")
            
            if SERVER_READY:
                filepath = ""

                if req_type == "init":
                    print("[KeyAuth - POST] Initialization request received, serving data...")
                    filepath = "served\\content_init.txt"
                elif req_type == "login" or req_type == "license":
                    print("[KeyAuth - POST] Login request received, serving data...")
                    filepath = "served\\content_login.txt"
                elif req_type == "check":
                    print("[KeyAuth - POST] Check request received, serving data...")
                    filepath = "served\\content_check.txt"
                else:
                    print(f"[KeyAuth - POST] Invalid type parameter was received ( {req_type} )")
                    self.send_response(400)
                    self.end_headers()
                    return

                try:
                    with open(filepath, "rb") as f:
                        content = f.read()
                    timestamp = str(int(time.time()))
                    sig = privkey.sign(timestamp.encode() + content)
                    sig_hex = sig.hex()

                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.send_header("Content-Length", str(len(content)))
                    self.send_header("x-signature-ed25519", sig_hex)
                    self.send_header("x-signature-timestamp", timestamp)
                    self.end_headers()
                    self.wfile.write(content)
                except FileNotFoundError:
                    print(f"[dbg] File not found: {filepath}")
                    self.send_response(404)
                    self.end_headers()
            else:
                temp_response = json.dumps({
                    "success": False,
                    "message": "-- Server Uninitialized --"
                }).encode()
                
                self.send_response(503)
                self.send_header("Content-type", "application/json")
                self.send_header("Content-Length", str(len(temp_response)))
                self.end_headers()
                self.wfile.write(temp_response)
            return

        else:
            print("[POST] Non-KeyAuth request made to localhost:")
            print(f"Host: {host}")
            print(f"Body: {body}")
            self.send_response(400)
            self.end_headers()
            return

    def do_GET(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode() if content_length else ''
        host = self.headers.get('Host', '').lower()
        path = self.path
        query = urlparse(self.path).query
        params = parse_qs(query)

        if 'keyauth.win' in host:
            print(f"[KeyAuth - GET] Invalid GET request attempted, path: {path}")
            self.send_response(400)
            self.end_headers()
            return

        else:
            print("[GET] Non-KeyAuth request made to localhost:")
            print(f"Host: {host}")
            if body:
                print(f"Body: {body}")
            self.send_response(400)
            self.end_headers()
            return

def sni_callback(ssl_socket, server_name, ssl_context):
    if server_name == 'keyauth.win':
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            certfile=f"{USERPROFILE}\\Documents\\cert\\tls.crt",
            keyfile=f"{USERPROFILE}\\Documents\\cert\\tls.key"
        )
        ssl_socket.context = context

def run_http():
    httpd = HTTPServer((HOST, HTTP_PORT), ReqHandler)
    httpd.serve_forever()

def run_https():
    httpd = HTTPServer((HOST, HTTPS_PORT), ReqHandler)
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile=f"{USERPROFILE}\\Documents\\cert\\tls.crt",
        keyfile=f"{USERPROFILE}\\Documents\\cert\\tls.key"
    )
    context.sni_callback = sni_callback
    
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()

if __name__ == "__main__":
    try:
        print(f"\nHTTP running - PORT: {HTTP_PORT}")
        print(f"HTTPS running - PORT: {HTTPS_PORT}")
        print("\n-------------------------\n")
        
        threading.Thread(target=run_http, daemon=True).start()
        threading.Thread(target=run_https, daemon=True).start()
        
        while True:
            time.sleep(0.5)
            
    except KeyboardInterrupt:
        print("Reverting HOSTS file")
        open(r'C:\Windows\System32\drivers\etc\hosts', 'wb').write(open(os.path.join(os.environ['TEMP'], 'hosts.bak'), 'rb').read())
        print("\nGoodbye.")
        time.sleep(1.5)
    except ssl.SSLEOFError:
        pass
