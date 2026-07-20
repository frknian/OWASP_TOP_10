# PORT: 8005
import os
import sqlite3
from contextlib import asynccontextmanager

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

DB_PATH = "accounts.db"
SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY", "dev-only-insecure-secret-change-me")
password_hasher = PasswordHasher()
templates = Jinja2Templates(directory="templates")
# Python 3.14 + Jinja2 bug workaround (pallets/jinja#2180): template cache'ini kapat.
templates.env.cache = None

# Seed kullanıcıları modül seviyesinde tek kaynakta tutuyoruz — hem ilk seed'de
# hem de test amaçlı /reset-db'de aynı listeyi kullanabilmek için (Senaryo 1/2 ile
# birebir aynı alice/bob/admin verisi).
SEED_USERS = [
    {
        "username": "alice",
        "email": "alice@example.com",
        "password": "AliceStrongPass!23",
        "balance": 2500,
        "phone_number": "+90 532 000 00 01",
        "role": "user",
    },
    {
        "username": "bob",
        "email": "bob@example.com",
        "password": "BobStrongPass!45",
        "balance": 750,
        "phone_number": "+90 532 000 00 02",
        "role": "user",
    },
    {
        "username": "admin",
        "email": "admin@example.com",
        "password": "AdminStrongPass!67",
        "balance": 0,
        "phone_number": "+90 532 000 00 09",
        "role": "admin",
    },
]


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            hashed_password TEXT NOT NULL,
            balance INTEGER NOT NULL DEFAULT 0,
            phone_number TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def hash_password(plain_password: str) -> str:
    return password_hasher.hash(plain_password)


def _insert_seed_users(conn: sqlite3.Connection) -> None:
    for user in SEED_USERS:
        conn.execute(
            """
            INSERT INTO users (username, email, hashed_password, balance, phone_number, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            """,
            (
                user["username"],
                user["email"],
                hash_password(user["password"]),
                user["balance"],
                user["phone_number"],
                user["role"],
            ),
        )
    conn.commit()


def seed_db() -> None:
    conn = get_db_connection()
    row_count = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
    if row_count > 0:
        conn.close()
        return
    _insert_seed_users(conn)
    conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed_db()
    yield


app = FastAPI(lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY)


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(credentials: LoginRequest, request: Request):
    conn = get_db_connection()
    user = conn.execute(
        "SELECT id, hashed_password FROM users WHERE username = ?",
        (credentials.username,),
    ).fetchone()
    conn.close()

    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    try:
        password_hasher.verify(user["hashed_password"], credentials.password)
    except VerifyMismatchError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    request.session["user_id"] = user["id"]
    return {"message": "login successful"}


def get_current_user(request: Request) -> sqlite3.Row:
    user_id = request.session.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    conn = get_db_connection()
    # Rolü DB'den taze okuyoruz — frontend'de gizlenen "Delete" butonunun rol mantığı
    # bu değerden besleniyor; ama asıl güvenlik kararı (Senaryo 2'deki gibi) sunucuda
    # verilmeli. Bu vulnerable sürümde DELETE endpoint'i bu role bilgisini KULLANMIYOR.
    user = conn.execute(
        "SELECT id, username, email, balance, phone_number, role FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    conn.close()

    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    return user


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    # Basit login formu — tarayıcıdan test edebilmek için. POST /login'e fetch ile
    # istek atıp başarılıysa /dashboard'a yönlendirir.
    # Starlette imzası: TemplateResponse(request, name, context) — request ilk arg olmalı.
    return templates.TemplateResponse(request, "index.html")


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, current_user: sqlite3.Row = Depends(get_current_user)):
    # Sayfa yalnızca giriş yapmış kullanıcıya kendi bilgisini gösterir. current_user["role"]
    # değerini template'e geçiriyoruz; "Delete User" paneli SADECE bu değer "admin" ise
    # JS tarafından gösterilecek (aşağıdaki dashboard.html'e bakınız). Bu, güvenliğin
    # yalnızca client'ta uygulandığı — yani asıl açığın kaynağı olan — noktadır.
    # Starlette imzası: TemplateResponse(request, name, context). context'e ayrıca
    # "request" koymaya gerek yok — Starlette onu otomatik ekliyor (context.setdefault).
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"user": dict(current_user)},
    )


@app.delete("/api/admin/users/{user_id}")
def delete_user(user_id: int, current_user: sqlite3.Row = Depends(get_current_user)):
    # BİLİNÇLİ ZAFİYET — Client-Side Enforcement of Server-Side Security (CWE-602):
    # Bu endpoint SADECE authentication kontrolü yapıyor (Depends(get_current_user)),
    # ama ROL kontrolü YOK. "Sadece adminler silebilir" kuralı yalnızca frontend'de,
    # butonu gizleyerek uygulanmış. Oysa butonun DOM'da olmaması, endpoint'in var
    # olmadığı anlamına gelmez: alice/bob gibi normal bir kullanıcı, geçerli session'ı
    # ile (curl / DevTools / Burp Repeater üzerinden) doğrudan bu endpoint'e DELETE
    # isteği atıp herhangi bir kullanıcıyı silebilir. Client-side gizleme bir güvenlik
    # kontrolü değil, sadece bir UX detayıdır.
    conn = get_db_connection()
    target = conn.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        conn.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return {"message": f"user {target['username']} (id={user_id}) deleted"}


@app.post("/reset-db")
def reset_db():
    # TEST-ONLY: Silme testleri DB'yi kalıcı olarak boşaltmasın diye, tabloyu temizleyip
    # seed kullanıcılarını (alice/bob/admin) yeniden ekler. Gerçek bir uygulamada böyle
    # bir endpoint ASLA bulunmamalı — sadece bu lab'da tekrar tekrar test yapabilmek için.
    conn = get_db_connection()
    conn.execute("DELETE FROM users")
    # AUTOINCREMENT sayacını da sıfırlıyoruz ki seed her seferinde aynı ID'lerle
    # (alice=1, bob=2, admin=3) gelsin — tekrarlı testlerin deterministik olması için.
    conn.execute("DELETE FROM sqlite_sequence WHERE name = 'users'")
    conn.commit()
    _insert_seed_users(conn)
    conn.close()
    return {"message": "database reset to seed state"}
