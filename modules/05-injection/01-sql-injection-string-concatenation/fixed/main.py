# FIX (CWE-89): kullanıcı girdisi parametreli sorgu (placeholder) ile geçirilir.
"""
Modül 05 — Injection
Senaryo 1: SQL Injection / String Concatenation (FIXED)

Remediation: Sorgu, kullanıcı girdisini `?` placeholder ile parametreli olarak alır.
Sürücü, girdiyi her zaman TEK BİR DEĞER (veri) olarak bağlar; asla SQL'in yapısal
parçası olarak yorumlamaz. Böylece `1' OR '1'='1` gibi bir girdi, sorguyu bozmak yerine
"id'si tam olarak bu string olan hesap" araması olur ve hiçbir satır dönmez.

Çalıştırma: uvicorn main:app --port 8121
"""
# PORT: 8121
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI

DB_PATH = "accounts.db"

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
    return {"status": "up", "scenario": "sql-injection-fixed"}


@app.get("/api/accounts")
def get_accounts(id: str):
    # FIX: Parametreli sorgu. `?` placeholder + değer tuple'ı → girdi yalnızca DEĞER
    # olarak bağlanır, sorgunun yapısını değiştiremez. Aynı payload artık zararsız.
    query = "SELECT id, name, email, balance FROM accounts WHERE id = ?"
    conn = get_db_connection()
    rows = conn.execute(query, (id,)).fetchall()
    conn.close()
    return {"query": query, "results": [dict(r) for r in rows]}
