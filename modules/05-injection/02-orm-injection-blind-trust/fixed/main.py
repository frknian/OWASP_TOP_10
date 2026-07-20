# FIX (CWE-89): AYNI MiniORM sınıfının parametreli filter() metodu kullanılır.
"""
Modül 05 — Injection
Senaryo 2: ORM/Parametrik Sorgu Yanlış Kullanımı — "Blind Trust in Frameworks" (FIXED)

Remediation: MiniORM sınıfı DEĞİŞMEDİ — aynı sınıf, aynı iki metot. Değişen tek şey,
endpoint'in artık GÜVENSİZ `raw()` yerine GÜVENLİ `filter()` metodunu kullanması.
Ders: ORM/framework kullanmak otomatik güvenlik sağlamaz; güvenliği sağlayan, girdinin
parametreli (veri olarak) geçirilmesidir. Aynı `x' OR '1'='1` payload'ı artık yalnızca
"name'i tam olarak bu string olan kayıt" araması olur ve hiçbir satır dönmez.

Çalıştırma: uvicorn main:app --port 8131
"""
# PORT: 8131
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI

DB_PATH = "accounts.db"

SEED_ACCOUNTS = [
    {"name": "Alice", "email": "alice@example.com", "balance": 2500},
    {"name": "Bob", "email": "bob@example.com", "balance": 750},
    {"name": "Carol", "email": "carol@example.com", "balance": 4200},
]


class MiniORM:
    """Öğretici, minimal bir sorgu soyutlaması. İki farklı kullanım şekli sunar."""

    def __init__(self, conn: sqlite3.Connection, table: str):
        self.conn = conn
        self.table = table

    def raw(self, where_fragment: str):
        # GÜVENSİZ: WHERE fragment'i doğrudan sorguya gömülüyor.
        query = f"SELECT id, name, email, balance FROM {self.table} WHERE {where_fragment}"  # nosec B608
        rows = self.conn.execute(query).fetchall()
        return [dict(r) for r in rows], query

    def filter(self, column: str, value):
        # GÜVENLİ: değer parametreli (`?`) bağlanır; kolon adı geliştirici kontrolündedir.
        query = f"SELECT id, name, email, balance FROM {self.table} WHERE {column} = ?"  # nosec B608
        rows = self.conn.execute(query, (value,)).fetchall()
        return [dict(r) for r in rows], query


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
    return {"status": "up", "scenario": "orm-injection-fixed"}


@app.get("/api/search")
def search(term: str):
    # FIX: AYNI MiniORM, ama GÜVENLİ filter() metodu. term parametreli bağlanır;
    # sorgunun yapısını değiştiremez. Sınıf değişmedi — kullanım şekli değişti.
    conn = get_db_connection()
    orm = MiniORM(conn, "accounts")
    results, query = orm.filter("name", term)
    conn.close()
    return {"query": query, "results": results}
