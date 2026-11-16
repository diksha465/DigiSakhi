
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import parse_qs, urlsplit
from http.cookies import SimpleCookie
import os
import hashlib
import secrets
import hmac
import html

from database import get_connection

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)

SESSIONS = {}

PAGES = {
    "/": "/templates/home.html",
    "/home.html": "/templates/home.html",
    "/register": "/templates/register.html",
    "/register.html": "/templates/register.html",
    "/login": "/templates/login.html",
    "/login.html": "/templates/login.html",
    "/dashboard": "/templates/dashboard.html",
    "/dashboard.html": "/templates/dashboard.html",
    "/modules": "/templates/modules.html",
    "/modules.html": "/templates/modules.html",
    "/lesson": "/templates/lesson.html",
    "/lesson.html": "/templates/lesson.html",
    "/quiz": "/templates/quiz.html",
    "/quiz.html": "/templates/quiz.html",
    "/results": "/templates/results.html",
    "/results.html": "/templates/results.html",
    "/progress": "/templates/progress.html",
    "/progress.html": "/templates/progress.html",
    "/admin-login": "/templates/admin_login.html",
    "/admin_login.html": "/templates/admin_login.html",
    "/admin-dashboard": "/templates/admin_dashboard.html",
    "/admin_dashboard.html": "/templates/admin_dashboard.html"
}


# Securely hash password
def hash_password(password):
    salt = secrets.token_hex(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        200000
    ).hex()

    return salt + "$" + hashed


# Verify password
def verify_password(password, stored):
    try:
        salt, old_hash = stored.split("$")

        new_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            200000
        ).hex()

        return hmac.compare_digest(new_hash, old_hash)

    except (ValueError, TypeError):
        return False


class DigiSakhiHandler(SimpleHTTPRequestHandler):

    # Display error or information message
    def show_message(self, message, link="/"):
        page = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>DigiSakhi</title>
            <link rel="stylesheet" href="/static/style.css">
        </head>
        <body>
            <div class="form-box">
                <h2>{html.escape(message)}</h2>
                <p><a href="{html.escape(link, quote=True)}">Continue</a></p>
            </div>
        </body>
        </html>
        """

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(page.encode("utf-8"))

    # Redirect page
    def redirect(self, location):
        self.send_response(303)
        self.send_header("Location", location)
        self.end_headers()

    # Get logged-in user
    def get_session(self):
        cookie = SimpleCookie()

        try:
            cookie.load(self.headers.get("Cookie", ""))
            session_id = cookie["session_id"].value
            return SESSIONS.get(session_id)
        except Exception:
            return None

    # Read submitted form data
    def read_form(self):
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length).decode("utf-8")
        return parse_qs(data)

    # GET requests
    def do_GET(self):
        path = urlsplit(self.path).path

        # Logout
        if path == "/logout":
            cookie = SimpleCookie()

            try:
                cookie.load(self.headers.get("Cookie", ""))
                session_id = cookie["session_id"].value
                SESSIONS.pop(session_id, None)
            except Exception:
                pass

            self.send_response(303)
            self.send_header("Location", "/login")
            self.send_header(
                "Set-Cookie",
                "session_id=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
            )
            self.end_headers()
            return

        # Protect user pages
        protected = [
            "/dashboard", "/dashboard.html",
            "/modules", "/modules.html",
            "/lesson", "/lesson.html",
            "/quiz", "/quiz.html",
            "/results", "/results.html",
            "/progress", "/progress.html"
        ]

        if path in protected and not self.get_session():
            self.redirect("/login")
            return

        # Display requested page
        if path in PAGES:
            self.path = PAGES[path]

        super().do_GET()

    # POST requests
    def do_POST(self):
        path = urlsplit(self.path).path

        print("Form submitted:", path)

        if path == "/register":
            self.register_user()

        elif path == "/login":
            self.login_user()

        else:
            self.send_error(404, "Page not found")

    # Registration
    def register_user(self):
        form = self.read_form()

        name = form.get("name", [""])[0].strip()
        email = form.get("email", [""])[0].strip().lower()
        password = form.get("password", [""])[0]
        confirm = form.get("confirm_password", [""])[0]

        if not name or not email or not password:
            self.show_message("Please fill all fields.", "/register")
            return

        if len(password) < 8:
            self.show_message(
                "Password must contain at least 8 characters.",
                "/register"
            )
            return

        if password != confirm:
            self.show_message("Passwords do not match.", "/register")
            return

        conn = None

        try:
            conn = get_connection()

            if conn is None:
                self.show_message("Could not connect to MySQL.", "/register")
                return

            cursor = conn.cursor()

            query = """
                INSERT INTO users (name, email, password)
                VALUES (%s, %s, %s)
            """

            cursor.execute(
                query,
                (name, email, hash_password(password))
            )

            conn.commit()

            print("Registration saved in MySQL:", email)

            self.redirect("/login")

        except Exception as error:
            print("Registration error:", error)

            if "Duplicate entry" in str(error):
                self.show_message(
                    "This email is already registered. Please login.",
                    "/login"
                )
            else:
                self.show_message(
                    "Registration failed. Check the VS Code terminal.",
                    "/register"
                )

        finally:
            if conn:
                conn.close()

    # Login
    def login_user(self):
        form = self.read_form()

        email = form.get("email", [""])[0].strip().lower()
        password = form.get("password", [""])[0]

        if not email or not password:
            self.show_message("Enter email and password.", "/login")
            return

        conn = None

        try:
            conn = get_connection()

            if conn is None:
                self.show_message("Could not connect to MySQL.", "/login")
                return

            cursor = conn.cursor(dictionary=True)

            cursor.execute(
                """
                SELECT id, name, email, password
                FROM users
                WHERE email = %s
                """,
                (email,)
            )

            user = cursor.fetchone()

            if user and verify_password(password, user["password"]):
                session_id = secrets.token_urlsafe(32)

                SESSIONS[session_id] = {
                    "user_id": user["id"],
                    "name": user["name"],
                    "email": user["email"]
                }

                self.send_response(303)
                self.send_header("Location", "/dashboard")
                self.send_header(
                    "Set-Cookie",
                    f"session_id={session_id}; Path=/; HttpOnly; SameSite=Lax"
                )
                self.end_headers()

                print("Login successful:", email)

            else:
                self.show_message(
                    "Invalid email or password.",
                    "/login"
                )

        except Exception as error:
            print("Login error:", error)
            self.show_message("Login failed. Check terminal.", "/login")

        finally:
            if conn:
                conn.close()


# Start server
if __name__ == "__main__":

    print("Checking MySQL connection...")

    conn = get_connection()

    if conn is None:
        print("MySQL connection failed. Check database.py.")
        raise SystemExit

    conn.close()

    print("MySQL connected successfully!")

    server = HTTPServer(("localhost", 8000), DigiSakhiHandler)

    print("DigiSakhi running at http://localhost:8000")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Server stopped.")
        server.server_close()
