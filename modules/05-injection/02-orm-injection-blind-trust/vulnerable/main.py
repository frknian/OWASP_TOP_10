# CWE-89 (SQL Injection): ORM/soyutlama katmanı YANLIŞ kullanılınca da enjekte edilebilir.
"""
Modül 05 — Injection
Senaryo 2: ORM/Parametrik Sorgu Yanlış Kullanımı — "Blind Trust in Frameworks" (VULNERABLE)

Zafiyet: Uygulama bir "MiniORM" soyutlama katmanı kullanıyor — ama ORM kullanmak tek
başına güvenlik sağlamaz. MiniORM'un İKİ metodu var:
  - raw(where_fragment): fragment'i sorguya string olarak gömer (GÜVENSİZ)
  - filter(column, value): parametreli çalışır (GÜVENLİ)
Bu vulnerable sürüm, `raw()`'ı kullanıcı girdisiyle çağırır → framework'e "körü körüne
güven" (blind trust) sonucu klasik SQL injection. `x' OR '1'='1` payload'ı tüm kayıtları döndürür.

Çalıştırma: uvicorn main:app --port 8130
"""
# PORT: 8130
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
        # GÜVENSİZ: WHERE fragment'i doğrudan sorguya gömülüyor. Çağıran taraf buraya
        # kullanıcı girdisi koyarsa, ORM'un varlığı hiçbir koruma sağlamaz.
        query = f"SELECT id, name, email, balance FROM {self.table} WHERE {where_fragment}"
        rows = self.conn.execute(query).fetchall()
        return [dict(r) for r in rows], query

    def filter(self, column: str, value):
        # GÜVENLİ: değer parametreli (`?`) bağlanır; kolon adı geliştirici kontrolündedir.
        query = f"SELECT id, name, email, balance FROM {self.table} WHERE {column} = ?"
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
    return {"status": "up", "scenario": "orm-injection-blind-trust"}


@app.get("/api/search")
def search(term: str):
    # ZAFIYET: MiniORM'un GÜVENSİZ raw() metodu, kullanıcı girdisiyle çağrılıyor.
    # "ORM kullanıyoruz, güvendeyiz" yanılgısı — girdi yine sorguya gömülüyor.
    conn = get_db_connection()
    orm = MiniORM(conn, "accounts")
    results, query = orm.raw(f"name = '{term}'")
    conn.close()
    return {"query": query, "results": results}
