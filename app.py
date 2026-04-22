import os
import sqlite3
from urllib.parse import urlencode

from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware


def load_env_file() -> None:
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.exists(env_path):
        return

    with open(env_path, "r", encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


load_env_file()


SECRET_KEY = os.environ.get("SECRET_KEY", "your_secret_key")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:3000")
BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000")

app = FastAPI(title="Cyber Defense Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)


oauth = OAuth()
oauth.register(
    name="google",
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)
oauth.register(
    name="github",
    client_id=os.environ.get("GITHUB_CLIENT_ID"),
    client_secret=os.environ.get("GITHUB_CLIENT_SECRET"),
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "user:email"},
)


def init_db() -> None:
    conn = sqlite3.connect("users.db")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            fullname TEXT,
            username TEXT UNIQUE,
            password TEXT,
            oauth_provider TEXT,
            oauth_id TEXT
        )
        """
    )
    conn.commit()
    conn.close()


init_db()


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return "<h1>Backend is running</h1>"


@app.get("/signup", response_class=HTMLResponse)
async def signup_page() -> str:
    return "<h1>Signup endpoint is available</h1>"


@app.post("/signup")
async def signup(request: Request):
    form = await request.form()
    fullname = (form.get("fullname") or "").strip()
    username = (form.get("username") or "").strip()
    password = (form.get("password") or "")

    if not fullname or not username or not password:
        return JSONResponse(
            {"success": False, "message": "All fields are required"},
            status_code=400,
        )

    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO users (fullname, username, password) VALUES (?, ?, ?)",
            (fullname, username, password),
        )
        conn.commit()
        conn.close()
        return RedirectResponse(url="/login", status_code=302)
    except sqlite3.IntegrityError:
        return JSONResponse(
            {"success": False, "message": "Username already exists"},
            status_code=409,
        )


@app.get("/login", response_class=HTMLResponse)
async def login_page() -> str:
    return "<h1>Login endpoint is available</h1>"


@app.post("/login")
async def login(request: Request):
    form = await request.form()
    username = (form.get("username") or "").strip()
    password = (form.get("password") or "")

    if not username or not password:
        return JSONResponse(
            {"success": False, "message": "Username and password are required"},
            status_code=400,
        )

    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password),
    ).fetchone()
    conn.close()

    if user:
        request.session["username"] = user["username"]
        request.session["fullname"] = user["fullname"]
        return RedirectResponse(url="/home", status_code=302)

    return JSONResponse(
        {"success": False, "message": "Invalid credentials"},
        status_code=401,
    )


@app.post("/api/signup")
async def api_signup(request: Request):
    data = await request.json()
    fullname = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not fullname or not email or not password:
        return JSONResponse(
            {"success": False, "message": "Name, email, and password are required"},
            status_code=400,
        )

    conn = None
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO users (fullname, username, password) VALUES (?, ?, ?)",
            (fullname, email, password),
        )
        conn.commit()
        return JSONResponse(
            {"success": True, "message": "Account created successfully"},
            status_code=201,
        )
    except sqlite3.IntegrityError:
        return JSONResponse(
            {
                "success": False,
                "message": "An account with this email already exists. Please login.",
            },
            status_code=409,
        )
    except Exception:
        return JSONResponse(
            {"success": False, "message": "Internal server error"},
            status_code=500,
        )
    finally:
        if conn:
            conn.close()


@app.post("/api/login")
async def api_login(request: Request):
    data = await request.json()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return JSONResponse(
            {"success": False, "message": "Email and password are required"},
            status_code=400,
        )

    conn = None
    try:
        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (email, password),
        ).fetchone()

        if not user:
            return JSONResponse(
                {
                    "success": False,
                    "message": "Incorrect email or password. Please try again.",
                },
                status_code=401,
            )

        request.session["username"] = user["username"]
        request.session["fullname"] = user["fullname"]

        return JSONResponse(
            {
                "success": True,
                "user": {"name": user["fullname"], "email": user["username"]},
            }
        )
    except Exception:
        return JSONResponse(
            {"success": False, "message": "Internal server error"},
            status_code=500,
        )
    finally:
        if conn:
            conn.close()


@app.get("/home")
async def home(request: Request):
    if "username" in request.session:
        return JSONResponse(
            {
                "username": request.session.get("username"),
                "fullname": request.session.get("fullname"),
            }
        )
    return RedirectResponse(url="/login", status_code=302)


@app.get("/logout")
async def logout(request: Request):
    request.session.pop("username", None)
    request.session.pop("fullname", None)
    return RedirectResponse(url="/login", status_code=302)


@app.get("/auth/google")
async def google_login(request: Request):
    redirect_uri = f"{BACKEND_URL}/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/auth/google/callback")
async def google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get("userinfo")

        if not user_info:
            user_info = (await oauth.google.get("https://openidconnect.googleapis.com/v1/userinfo", token=token)).json()

        oauth_id = user_info.get("sub")
        email = user_info.get("email")
        name = user_info.get("name", email.split("@")[0])

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE oauth_provider=? AND oauth_id=?",
            ("google", oauth_id),
        ).fetchone()

        if not user:
            existing = conn.execute(
                "SELECT * FROM users WHERE username=?",
                (email,),
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE users SET oauth_provider=?, oauth_id=? WHERE username=?",
                    ("google", oauth_id, email),
                )
                user = existing
            else:
                conn.execute(
                    "INSERT INTO users (fullname, username, oauth_provider, oauth_id) VALUES (?, ?, ?, ?)",
                    (name, email, "google", oauth_id),
                )
                user = conn.execute(
                    "SELECT * FROM users WHERE username=?",
                    (email,),
                ).fetchone()

        conn.commit()
        conn.close()

        request.session["username"] = user["username"]
        request.session["fullname"] = user["fullname"]

        params = urlencode(
            {
                "name": user["fullname"],
                "email": user["username"],
                "provider": "google",
            }
        )
        return RedirectResponse(url=f"{FRONTEND_URL}/oauth/success?{params}", status_code=302)
    except Exception as exc:
        params = urlencode({"error": str(exc)})
        return RedirectResponse(url=f"{FRONTEND_URL}/login?{params}", status_code=302)


@app.get("/api/auth/google/callback")
async def api_google_callback(request: Request):
    try:
        code = request.query_params.get("code")
        if not code:
            return JSONResponse(
                {"success": False, "message": "No authorization code provided"},
                status_code=400,
            )

        token = await oauth.google.authorize_access_token(request)
        user_info = token.get("userinfo")

        if not user_info:
            user_info = (await oauth.google.get("https://openidconnect.googleapis.com/v1/userinfo", token=token)).json()

        oauth_id = user_info.get("sub")
        email = user_info.get("email")
        name = user_info.get("name", email.split("@")[0])

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE oauth_provider=? AND oauth_id=?",
            ("google", oauth_id),
        ).fetchone()

        if not user:
            existing = conn.execute(
                "SELECT * FROM users WHERE username=?",
                (email,),
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE users SET oauth_provider=?, oauth_id=? WHERE username=?",
                    ("google", oauth_id, email),
                )
                user = existing
            else:
                conn.execute(
                    "INSERT INTO users (fullname, username, oauth_provider, oauth_id) VALUES (?, ?, ?, ?)",
                    (name, email, "google", oauth_id),
                )
                user = conn.execute(
                    "SELECT * FROM users WHERE username=?",
                    (email,),
                ).fetchone()

        conn.commit()
        conn.close()

        request.session["username"] = user["username"]
        request.session["fullname"] = user["fullname"]

        return JSONResponse(
            {
                "success": True,
                "user": {"name": user["fullname"], "email": user["username"]},
            }
        )
    except Exception as exc:
        return JSONResponse(
            {"success": False, "message": str(exc)},
            status_code=500,
        )


@app.get("/auth/github")
async def github_login(request: Request):
    redirect_uri = f"{BACKEND_URL}/auth/github/callback"
    return await oauth.github.authorize_redirect(request, redirect_uri)


@app.get("/auth/github/callback")
async def github_callback(request: Request):
    try:
        token = await oauth.github.authorize_access_token(request)

        resp = await oauth.github.get("user", token=token)
        user_info = resp.json()

        oauth_id = str(user_info.get("id"))
        username = user_info.get("login")
        name = user_info.get("name") or username

        email_resp = await oauth.github.get("user/emails", token=token)
        emails = email_resp.json()
        email = next((e["email"] for e in emails if e.get("primary")), f"{username}@github.local")

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE oauth_provider=? AND oauth_id=?",
            ("github", oauth_id),
        ).fetchone()

        if not user:
            existing = conn.execute(
                "SELECT * FROM users WHERE username=?",
                (username,),
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE users SET oauth_provider=?, oauth_id=? WHERE username=?",
                    ("github", oauth_id, username),
                )
                user = existing
            else:
                conn.execute(
                    "INSERT INTO users (fullname, username, oauth_provider, oauth_id) VALUES (?, ?, ?, ?)",
                    (name, username, "github", oauth_id),
                )
                user = conn.execute(
                    "SELECT * FROM users WHERE username=?",
                    (username,),
                ).fetchone()

        conn.commit()
        conn.close()

        request.session["username"] = user["username"]
        request.session["fullname"] = user["fullname"]

        params = urlencode(
            {
                "name": user["fullname"],
                "email": email,
                "provider": "github",
            }
        )
        return RedirectResponse(url=f"{FRONTEND_URL}/oauth/success?{params}", status_code=302)
    except Exception as exc:
        params = urlencode({"error": str(exc)})
        return RedirectResponse(url=f"{FRONTEND_URL}/login?{params}", status_code=302)


@app.get("/api/auth/github/callback")
async def api_github_callback(request: Request):
    try:
        code = request.query_params.get("code")
        if not code:
            return JSONResponse(
                {"success": False, "message": "No authorization code provided"},
                status_code=400,
            )

        token = await oauth.github.authorize_access_token(request)

        resp = await oauth.github.get("user", token=token)
        user_info = resp.json()

        oauth_id = str(user_info.get("id"))
        username = user_info.get("login")
        name = user_info.get("name") or username

        email_resp = await oauth.github.get("user/emails", token=token)
        emails = email_resp.json()
        email = next((e["email"] for e in emails if e.get("primary")), f"{username}@github.local")

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE oauth_provider=? AND oauth_id=?",
            ("github", oauth_id),
        ).fetchone()

        if not user:
            existing = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

            if existing:
                conn.execute(
                    "UPDATE users SET oauth_provider=?, oauth_id=? WHERE username=?",
                    ("github", oauth_id, username),
                )
                user = existing
            else:
                conn.execute(
                    "INSERT INTO users (fullname, username, oauth_provider, oauth_id) VALUES (?, ?, ?, ?)",
                    (name, username, "github", oauth_id),
                )
                user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        conn.commit()
        conn.close()

        request.session["username"] = user["username"]
        request.session["fullname"] = user["fullname"]

        return JSONResponse(
            {
                "success": True,
                "user": {"name": user["fullname"], "email": email},
            }
        )
    except Exception as exc:
        return JSONResponse(
            {"success": False, "message": str(exc)},
            status_code=500,
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
