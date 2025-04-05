from http.server import BaseHTTPRequestHandler, HTTPServer
from zoautil_py import datasets # IBM ZOWE PYTHON UTILITIES UNDER USS (UNIX SYSTEM SERVICES)
import hashlib
import json
from socketserver import ThreadingMixIn
import urllib.parse

USER_DB = "Z64305.USERDB"

# Init DB
try:
    datasets.read(USER_DB)
except Exception:
    datasets.write(USER_DB, "", replace=True)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests using threads."""

class AuthHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = urllib.parse.parse_qs(self.rfile.read(content_length).decode())
        
        username = post_data.get('username', [''])[0]
        password = post_data.get('password', [''])[0]
        
        if self.path == '/create_user':
            self.handle_create_user(username, password)
        elif self.path == '/login':
            self.handle_login(username, password)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

    def handle_create_user(self, username, password):
        users = datasets.read(USER_DB).split('\n')
        for user in users:
            if user.startswith(f"{username}="):
                self.send_response(409)
                self.end_headers()
                self.wfile.write(b'User exists')
                return

        datasets.write(USER_DB, f"{username}={hash_password(password)}\n", append=True)
        self.send_response(201)
        self.end_headers()
        self.wfile.write(b'User created')

    def handle_login(self, username, password):
        users = datasets.read(USER_DB).split('\n')
        for user in users:
            if user.startswith(f"{username}="):
                if hash_password(password) == user.split('=')[1]:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'Login success')
                    return

        self.send_response(401)
        self.end_headers()
        self.wfile.write(b'Login failed')

if __name__ == '__main__':
    server = ThreadedHTTPServer(('0.0.0.0', 5000), AuthHandler)
    print("Server started on http://0.0.0.0:5000")
    server.serve_forever()