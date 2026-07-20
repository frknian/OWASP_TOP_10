# FIX (CWE-327/759/916): parolalar argon2id ile hash'lenir — otomatik rastgele TUZ,
# adaptif/yavaş maliyet. Ayrıca /debug/dump-hashes endpoint'i kaldırıldı (404).
"""
Modül 04 — Cryptographic Failures
Senaryo 1: Weak/Unsalted Password Hashing (FIXED)

Remediation (iki katman):
  1) ALGORİTMA: MD5 yerine argon2id (argon2-cffi). Her hash'te kütüphane rastgele bir
     TUZ üretir ve hash'e gömer → aynı parola farklı kullanıcılarda farklı hash verir,
     yani önceden hesaplanmış rainbow table işe yaramaz (CWE-759). Argon2 ayrıca
     bellek-zorlu ve yavaştır → kaba kuvvet ekonomik olmaktan çıkar (CWE-916).
  2) SALDIRI YÜZEYİ: Unutulmuş /debug/dump-hashes endpoint'i tamamen kaldırıldı;
     istek 404 döner. Hash'ler artık normal yollarla dışarı sızmaz.

Aynı crack_demo.py bu sürümün hash'lerine karşı çalıştırıldığında: (a) dump endpoint'i
404 olduğu için hash bile çekilemez; (b) hash'ler MD5 değil argon2 olduğundan MD5
sözlüğüyle eşleşme imkânsızdır.

Çalıştırma: uvicorn main:app --port 8091
"""
# PORT: 8091
import sqlite3
from contextlib import asynccontextmanager

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import FastAPI, HTTPException

DB_PATH = "strong_users.db"
password_hasher = PasswordHasher()

# Aynı zayıf parolalar kullanılır — amaç, DOĞRU hash'lemenin bu zayıf parolaları bile
# rainbow table'a karşı nasıl koruduğunu göstermek (zayıf parola ≠ zayıf hash).
SEED_USERS = [
    {"username": "alice", "password": "123456"},  # nosec B105
    {"username": "bob", "password": "password"},  # nosec B105
    {"username": "carol", "password": "qwerty"},  # nosec B105
    {"username": "dave", "password": "letmein"},  # nosec B105
]


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(plain_password: str) -> str:
    # FIX: argon2id — tuz otomatik ve rastgele, maliyet adaptif.
    return password_hasher.hash(plain_password)


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
    return {"status": "up", "hash_algorithm": "argon2id", "scenario": "weak-hashing-fixed"}


@app.post("/login")
def login(username: str, password: str):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT username, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=401, detail="Geçersiz kimlik bilgileri")
    try:
        password_hasher.verify(row["password_hash"], password)
    except VerifyMismatchError:
        raise HTTPException(status_code=401, detail="Geçersiz kimlik bilgileri")
    return {"authenticated": True, "username": username}


# NOT: /debug/dump-hashes endpoint'i BİLİNÇLİ olarak yoktur (vulnerable'da vardı).
# Tanımsız olduğu için FastAPI otomatik 404 döner — hash sızdıran yüzey kapatıldı.
