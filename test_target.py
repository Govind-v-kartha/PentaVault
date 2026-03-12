"""
Deliberately vulnerable test web application for PentaVault scanner demo.
DO NOT deploy this in production — it contains intentional security flaws.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import html
import json

HOST, PORT = "127.0.0.1", 9999


class VulnHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/":
            self._serve_index()
        elif path == "/search":
            self._serve_search(params)
        elif path == "/user":
            self._serve_user(params)
        elif path == "/redirect":
            self._serve_redirect(params)
        elif path == "/admin":
            self._serve_admin()
        elif path == "/login":
            self._serve_login()
        elif path == "/api/data":
            self._serve_api(params)
        elif path == "/robots.txt":
            self._text_response("User-agent: *\nAllow: /\n")
        else:
            self._html_response("<h1>404</h1>", 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        params = parse_qs(body)
        parsed = urlparse(self.path)

        if parsed.path == "/login":
            self._handle_login(params)
        elif parsed.path == "/comment":
            self._handle_comment(params)
        else:
            self._html_response("<h1>404</h1>", 404)

    # ── Pages ────────────────────────────────────────────────────

    def _serve_index(self):
        self._html_response("""
        <html><head><title>Test Vulnerable App</title></head><body>
        <h1>Welcome to Test App</h1>
        <nav>
          <a href="/search?q=test">Search</a> |
          <a href="/user?id=1">User Profile</a> |
          <a href="/admin">Admin</a> |
          <a href="/login">Login</a> |
          <a href="/api/data?format=json">API</a>
        </nav>

        <h2>Search</h2>
        <form action="/search" method="GET">
          <input name="q" placeholder="Search..." />
          <button type="submit">Go</button>
        </form>

        <h2>Login</h2>
        <form action="/login" method="POST">
          <input name="username" placeholder="Username" />
          <input name="password" type="password" placeholder="Password" />
          <button type="submit">Login</button>
        </form>

        <h2>Leave a Comment</h2>
        <form action="/comment" method="POST">
          <textarea name="comment" rows="3" cols="40"></textarea><br/>
          <button type="submit">Submit</button>
        </form>

        <h2>Redirect Test</h2>
        <a href="/redirect?url=http://example.com">External Redirect</a>
        </body></html>
        """)

    def _serve_search(self, params):
        q = params.get("q", [""])[0]
        # Intentional XSS: reflects user input without escaping
        self._html_response(f"""
        <html><head><title>Search Results</title></head><body>
        <h1>Results for: {q}</h1>
        <p>No results found for "{q}".</p>
        <a href="/">Back</a>
        </body></html>
        """)

    def _serve_user(self, params):
        uid = params.get("id", ["1"])[0]
        # Intentional IDOR: no auth check on user ID
        # Intentional SQLi simulation: reflects parameter in "query"
        self._html_response(f"""
        <html><head><title>User Profile</title></head><body>
        <h1>User Profile #{uid}</h1>
        <p>Username: user{uid}</p>
        <p>Email: user{uid}@example.com</p>
        <!-- Debug: SELECT * FROM users WHERE id={uid} -->
        <a href="/">Back</a>
        </body></html>
        """)

    def _serve_redirect(self, params):
        target = params.get("url", [""])[0]
        if target:
            # Intentional Open Redirect: no validation
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
        else:
            self._html_response("<p>Missing url parameter</p>")

    def _serve_admin(self):
        # Missing auth — accessible to anyone
        self._html_response("""
        <html><head><title>Admin Panel</title></head><body>
        <h1>Admin Panel</h1>
        <p>Server: Apache/2.4.41</p>
        <p>PHP Version: 7.4.3</p>
        <p>Debug Mode: ON</p>
        <a href="/">Back</a>
        </body></html>
        """)

    def _serve_login(self):
        self._html_response("""
        <html><head><title>Login</title></head><body>
        <h1>Login</h1>
        <form action="/login" method="POST">
          <input name="username" placeholder="Username" /><br/>
          <input name="password" type="password" placeholder="Password" /><br/>
          <button type="submit">Login</button>
        </form>
        </body></html>
        """)

    def _serve_api(self, params):
        fmt = params.get("format", ["json"])[0]
        data = {"users": [{"id": 1, "name": "admin"}, {"id": 2, "name": "guest"}]}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        # Missing security headers intentionally
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _handle_login(self, params):
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]
        # Intentional SQLi: echoes back username unsanitized
        self._html_response(f"""
        <html><body>
        <h1>Login Result</h1>
        <p>Attempted login as: {username}</p>
        <!-- Query: SELECT * FROM users WHERE user='{username}' AND pass='{password}' -->
        <a href="/">Back</a>
        </body></html>
        """)

    def _handle_comment(self, params):
        comment = params.get("comment", [""])[0]
        # Intentional Stored XSS: reflects comment without escaping
        self._html_response(f"""
        <html><body>
        <h1>Comment Posted</h1>
        <div class="comment">{comment}</div>
        <a href="/">Back</a>
        </body></html>
        """)

    # ── Helpers ──────────────────────────────────────────────────

    def _html_response(self, body, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # Intentionally missing security headers:
        # No X-Content-Type-Options
        # No X-Frame-Options
        # No Content-Security-Policy
        # No Strict-Transport-Security
        self.end_headers()
        self.wfile.write(body.encode())

    def _text_response(self, body, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, fmt, *args):
        pass  # Suppress request logs


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), VulnHandler)
    print(f"[*] Vulnerable test target running on http://{HOST}:{PORT}")
    server.serve_forever()
