# CWE-89 (SQL Injection): kullanıcı girdisi SQL sorgusuna string olarak gömülür.
"""
Modül 05 — Injection
Senaryo 1: SQL Injection / String Concatenation (VULNERABLE)

Zafiyet: `GET /api/accounts?id=...` endpoint'i, gelen `id` parametresini f-string ile
doğrudan SQL sorgusuna gömer. Girdi "veri" olarak değil, sorgunun bir parçası olarak
ele alındığından, saldırgan sorgunun yapısını değiştirebilir. Örn. `1' OR '1'='1`
payload'ı WHERE koşulunu her zaman doğru yapar ve TÜM hesaplar döner.

Çalıştırma: uvicorn main:app --port 8120
"""
# PORT: 8120
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI

DB_PATH = "accounts.db"

# Sahte hesaplar (Modül 01 seed deseniyle tutarlı).
SEED_ACCOUNTS = [
    {"name": "Alice", "email": "alice@example.com", "balance": 2500},
    {"name": "Bob", "email": "bob@example.com", "balance": 750},
    {"name": "Carol", "email": "carol@example.com", "balance": 4200},
]


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            balance INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    conn.commit()
    conn.close()


def seed_db() -> None:
    conn = get_db_connection()
    row_count = conn.execute("SELECT COUNT(*) AS count FROM accounts").fetchone()["count"]
    if row_count > 0:
        conn.close()
        return
    for acc in SEED_ACCOUNTS:
        conn.execute(
            "INSERT INTO accounts (name, email, balance) VALUES (?, ?, ?)",
            (acc["name"], acc["email"], acc["balance"]),
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
    return {"status": "up", "scenario": "sql-injection-string-concat"}


@app.get("/api/accounts")
def get_accounts(id: str):
    # ZAFIYET: id kullanıcı girdisi olduğu halde sorguya f-string ile gömülüyor.
    # Parametreleme yok → girdi, verinin değil SORGUNUN bir parçası olarak yorumlanıyor.
    # Örn. id = "1' OR '1'='1" → WHERE koşulu her zaman doğru → tüm hesaplar sızar.
    query = f"SELECT id, name, email, balance FROM accounts WHERE id = '{id}'"
    conn = get_db_connection()
    rows = conn.execute(query).fetchall()
    conn.close()
    return {"query": query, "results": [dict(r) for r in rows]}
