# PORT: 8004
import os
import sqlite3
from contextlib import asynccontextmanager

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

DB_PATH = "accounts.db"
SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY", "dev-only-insecure-secret-change-me")
password_hasher = PasswordHasher()


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
            -- Senaryo 2 için eklenen kolon: yetki seviyesini (yatay değil, DİKEY yetki)
            -- taşıyor. Default "user" olması, ileride kolon eklense bile mevcut/yeni
            -- kayıtların kazara admin olmamasını (fail-safe/least-privilege) garanti eder.
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def hash_password(plain_password: str) -> str:
    return password_hasher.hash(plain_password)


def seed_db() -> None:
    conn = get_db_connection()
    row_count = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
    if row_count > 0:
        conn.close()
        return

    seed_users = [
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
            # Senaryo 2 için eklenen admin kullanıcısı. /api/admin/users endpoint'ine
            # SADECE bu rol erişebilmeli — fixed sürümde bu kısıt aşağıda gerçekten uygulanır.
            "username": "admin",
            "email": "admin@example.com",
            "password": "AdminStrongPass!67",
            "balance": 0,
            "phone_number": "+90 532 000 00 09",
            "role": "admin",
        },
    ]

    for user in seed_users:
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
    # DÜZELTME (1/2): Dependency artık `role` alanını da SELECT ediyor. Yetkilendirme
    # kararı, client'ın gönderebileceği hiçbir veriye değil, DOĞRUDAN veritabanındaki
    # güncel role değerine dayanmalı — bu yüzden rolü session'dan değil, her istekte
    # DB'den taze okuyoruz (kullanıcının rolü iptal/degrade edilirse anında yansır).
    user = conn.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    return user


@app.get("/api/admin/users")
def list_all_users(current_user: sqlite3.Row = Depends(get_current_user)):
    # DÜZELTME (2/2): Function-level access control artık SUNUCUDA uygulanıyor.
    # 1) Depends(get_current_user) → anonim/oturumsuz istekler daha buraya varmadan 401 alır
    #    (authentication katmanı).
    # 2) Aşağıdaki rol kontrolü → giriş yapmış ama admin OLMAYAN kullanıcılar 403 alır
    #    (authorization / dikey yetki katmanı). İki kontrol birbirinden bağımsızdır:
    #    kimlik doğrulama tek başına yeterli değildir, ayrıca yetki de gerekir.
    if current_user["role"] != "admin":
        # 403 (401 değil): İstek zaten kimliği doğrulanmış bir kullanıcıdan geliyor;
        # sorun "kim olduğunun bilinmemesi" değil, "bu fonksiyona yetkisinin olmaması".
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")

    conn = get_db_connection()
    users = conn.execute(
        "SELECT id, username, email, balance, phone_number, role FROM users ORDER BY id"
    ).fetchall()
    conn.close()

    return [dict(user) for user in users]
