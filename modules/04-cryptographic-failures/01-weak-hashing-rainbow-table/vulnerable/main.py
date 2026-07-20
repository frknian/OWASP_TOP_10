# CWE-327 (Broken/Risky Crypto Algorithm) + CWE-759 (Missing Salt) + CWE-916
# (Insufficient Computational Effort): parolalar TUZSUZ MD5 ile hash'lenir.
"""
Modül 04 — Cryptographic Failures
Senaryo 1: Weak/Unsalted Password Hashing + Rainbow Table Crack (VULNERABLE)

Zafiyet: Parola hash'i, tuzsuz ve kriptografik olarak zayıf/çok hızlı bir algoritma
(MD5) ile üretilir. Tuz olmadığı için aynı parola her kullanıcıda AYNI hash'i verir;
MD5 saniyede milyarlarca deneme yapılabilecek kadar hızlı olduğundan, önceden
hesaplanmış bir sözlük/rainbow table ile hash'ler anında kırılır.

Ek olarak, unutulmuş bir "debug" endpoint'i (GET /debug/dump-hashes) tüm
username+hash çiftlerini dışarı verir — yani saldırganın hash'lere erişimi için
DB'yi ele geçirmesine bile gerek kalmaz.

NOT: Bu, Modül 01'in kullanıcı sisteminden BAĞIMSIZ, izole bir demodur (kendi
`weak_users.db` dosyası). Amaç yalnızca zayıf hash + rainbow table dersini vermektir.

Çalıştırma: uvicorn main:app --port 8090
"""
# PORT: 8090
import hashlib
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

DB_PATH = "weak_users.db"

# Bilinçli olarak ZAYIF/YAYGIN parolalar — rainbow table dersinin çalışması için.
SEED_USERS = [
    {"username": "alice", "password": "123456"},
    {"username": "bob", "password": "password"},
    {"username": "carol", "password": "qwerty"},
    {"username": "dave", "password": "letmein"},
]


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(plain_password: str) -> str:
    # ZAFIYET: Tuzsuz MD5. Tuz yok → aynı parola = aynı hash; MD5 çok hızlı →
    # önceden hesaplanmış tabloyla anında geri çevrilir.
    return hashlib.md5(plain_password.encode("utf-8")).hexdigest()


def init_db() -> None:
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def seed_db() -> None:
    conn = get_db_connection()
    row_count = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
    if row_count > 0:
        conn.close()
        return
    for user in SEED_USERS:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (user["username"], hash_password(user["password"])),
        )
    conn.commit()
    conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed_db()
    yield


app = FastAPI(lifespan=lifespan)


@app.get("/status")
def status():
    return {"status": "up", "hash_algorithm": "md5-unsalted", "scenario": "weak-hashing"}


@app.post("/login")
def login(username: str, password: str):
    # Doğrulama da aynı zayıf hash ile yapılır (sabit-zamanlı karşılaştırma bile yok).
    conn = get_db_connection()
    row = conn.execute(
        "SELECT username, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    if row is None or row["password_hash"] != hash_password(password):
        raise HTTPException(status_code=401, detail="Geçersiz kimlik bilgileri")
    return {"authenticated": True, "username": username}


@app.get("/debug/dump-hashes")
def dump_hashes():
    # ZAFIYET: Unutulmuş debug endpoint'i — kimlik doğrulama yok, tüm hash'leri döker.
    # Saldırgan bu çıktıyı doğrudan rainbow table'a besleyebilir.
    conn = get_db_connection()
    rows = conn.execute("SELECT username, password_hash FROM users").fetchall()
    conn.close()
    return {"users": [{"username": r["username"], "password_hash": r["password_hash"]} for r in rows]}
