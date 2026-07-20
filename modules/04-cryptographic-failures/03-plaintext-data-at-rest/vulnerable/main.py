# CWE-311 (Missing Encryption of Sensitive Data) + CWE-312 (Cleartext Storage of
# Sensitive Information): hassas kimlik alanı DB'ye düz metin yazılır.
"""
Modül 04 — Cryptographic Failures
Senaryo 3: Plaintext Sensitive Data at Rest (VULNERABLE)

Zafiyet: Müşteri kaydındaki hassas alan (sahte "TC Kimlik No" benzeri `national_id`)
hiçbir şifreleme olmadan, düz metin olarak veritabanına yazılır. Uygulama katmanında
"erişim kontrolü var" gibi görünse de, veriyi at-rest koruyan hiçbir şey yoktur:
DB dosyasına, yedeğe, disk imajına veya bir SQLi'ye erişen herkes kimlik numaralarını
doğrudan okur.

/admin/db-dump endpoint'i, DB'de saklanan ham satırları göstererek verinin gerçekten
düz metin olduğunu kanıtlar (aynı şeyi `sqlite3 customers_vuln.db "SELECT * FROM
customers"` ile de görebilirsiniz).

Çalıştırma: uvicorn main:app --port 8110
"""
# PORT: 8110
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

DB_PATH = "customers_vuln.db"


class Customer(BaseModel):
    name: str
    national_id: str  # hassas alan (sahte TC Kimlik No benzeri)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            national_id TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(lifespan=lifespan)


@app.get("/status")
def status():
    return {"status": "up", "at_rest_protection": "none-plaintext", "scenario": "plaintext-at-rest"}


@app.post("/customers")
def create_customer(customer: Customer):
    # ZAFIYET: national_id düz metin olarak yazılıyor.
    conn = get_db_connection()
    cur = conn.execute(
        "INSERT INTO customers (name, national_id) VALUES (?, ?)",
        (customer.name, customer.national_id),
    )
    conn.commit()
    customer_id = cur.lastrowid
    conn.close()
    return {"id": customer_id, "name": customer.name, "national_id": customer.national_id}


@app.get("/customers/{customer_id}")
def read_customer(customer_id: int):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT id, name, national_id FROM customers WHERE id = ?", (customer_id,)
    ).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Müşteri bulunamadı")
    return {"id": row["id"], "name": row["name"], "national_id": row["national_id"]}


@app.get("/admin/db-dump")
def db_dump():
    # ZAFIYET: DB'de saklanan ham veri düz metin — kimlik numaraları açıkça görünür.
    conn = get_db_connection()
    rows = conn.execute("SELECT id, name, national_id FROM customers").fetchall()
    conn.close()
    return {
        "note": "DB'de saklanan HAM veri (at-rest). national_id düz metin.",
        "rows": [dict(r) for r in rows],
    }
