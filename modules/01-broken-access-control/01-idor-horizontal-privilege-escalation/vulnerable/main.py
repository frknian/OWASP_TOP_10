# PORT: 8000
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
        },
        {
            "username": "bob",
            "email": "bob@example.com",
            "password": "BobStrongPass!45",
            "balance": 750,
            "phone_number": "+90 532 000 00 02",
        },
    ]

    for user in seed_users:
        conn.execute(
            """
            INSERT INTO users (username, email, hashed_password, balance, phone_number, created_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            """,
            (
                user["username"],
                user["email"],
                hash_password(user["password"]),
                user["balance"],
                user["phone_number"],
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
    user = conn.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    return user


@app.get("/api/accounts/{account_id}")
def get_account(account_id: int, current_user: sqlite3.Row = Depends(get_current_user)):
    conn = get_db_connection()
    account = conn.execute(
        "SELECT id, username, email, balance, phone_number FROM users WHERE id = ?",
        (account_id,),
    ).fetchone()
    conn.close()

    if account is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")

    return dict(account)
