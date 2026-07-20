# FIX (CWE-311/312): hassas alan at-rest ŞİFRELENİR. Anahtar, Senaryo 2'nin dersiyle
# ortam değişkeninden gelir (kaynağa gömülmez).
"""
Modül 04 — Cryptographic Failures
Senaryo 3: Plaintext Sensitive Data at Rest (FIXED)

Remediation: Hassas alan (`national_id`) veritabanına yazılmadan önce Fernet ile
şifrelenir; DB'de yalnızca ciphertext durur. Çözme, yalnızca meşru
`GET /customers/{id}` isteğinde ve yetkili sunucu tarafında yapılır. Böylece DB
dosyasına, yedeğe veya bir SQLi'ye erişen biri yalnızca şifreli veri görür.

ANAHTAR YÖNETİMİ — modül içi anlatı bütünlüğü: Bu senaryo, Senaryo 2'de öğrenilen
DOĞRU anahtar yönetimini uygular — anahtar kaynak koda gömülmez, `ENCRYPTION_KEY`
ortam değişkeninden yüklenir. Yani "veriyi şifrele" (S3) ve "anahtarı doğru yönet"
(S2) dersleri birlikte tam korumayı oluşturur.

Anahtar üretimi/kullanımı:
    export ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    uvicorn main:app --port 8111

FAIL-SECURE: ENCRYPTION_KEY yoksa uygulama geçici anahtarla sessizce çalışmaz;
startup'ta (lifespan) net bir RuntimeError fırlatıp başlamayı reddeder — Modül 02'nin
"fail secure" davranışıyla tutarlı.
"""
# PORT: 8111
import os
import sqlite3
from contextlib import asynccontextmanager

from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

DB_PATH = "customers_fixed.db"

# Anahtar ortamdan (S2 dersi). Fernet, doğrulamadan sonra lifespan içinde kurulur.
fernet: Fernet | None = None


def _load_fernet() -> Fernet:
    """Anahtarı ortamdan yükler. Yoksa fail-secure: hata fırlatıp başlatmayı reddeder."""
    key = os.environ.get("ENCRYPTION_KEY")
    if not key:
        raise RuntimeError(
            "ENCRYPTION_KEY environment variable is required and was not set. "
            "Refusing to start with an insecure temporary key."
        )
    return Fernet(key.encode("utf-8"))


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
            national_id_enc TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global fernet
    # Fail-secure: anahtar yoksa burada RuntimeError yükselir ve süreç başlamaz.
    fernet = _load_fernet()
    init_db()
    yield


app = FastAPI(lifespan=lifespan)


@app.get("/status")
def status():
    return {"status": "up", "at_rest_protection": "fernet-encrypted", "key_source": "environment-variable"}


@app.post("/customers")
def create_customer(customer: Customer):
    # FIX: national_id şifrelenerek yazılır; DB'de yalnızca ciphertext durur.
    enc = fernet.encrypt(customer.national_id.encode("utf-8")).decode("utf-8")
    conn = get_db_connection()
    cur = conn.execute(
        "INSERT INTO customers (name, national_id_enc) VALUES (?, ?)",
        (customer.name, enc),
    )
    conn.commit()
    customer_id = cur.lastrowid
    conn.close()
    return {"id": customer_id, "name": customer.name, "national_id": customer.national_id}


@app.get("/customers/{customer_id}")
def read_customer(customer_id: int):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT id, name, national_id_enc FROM customers WHERE id = ?", (customer_id,)
    ).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Müşteri bulunamadı")
    # Çözme yalnızca yetkili sunucu tarafında, meşru istekte.
    national_id = fernet.decrypt(row["national_id_enc"].encode("utf-8")).decode("utf-8")
    return {"id": row["id"], "name": row["name"], "national_id": national_id}


@app.get("/admin/db-dump")
def db_dump():
    # FIX: Aynı dump artık yalnızca ciphertext gösterir — at-rest veri korunmuş.
    conn = get_db_connection()
    rows = conn.execute("SELECT id, name, national_id_enc FROM customers").fetchall()
    conn.close()
    return {
        "note": "DB'de saklanan HAM veri (at-rest). national_id_enc şifreli (Fernet).",
        "rows": [dict(r) for r in rows],
    }
