# CWE-209 (Generation of Error Message Containing Sensitive Information) — veritabanı
# bağlamında: yakalanmayan/ham DB hataları istemciye döndürülür. Saldırgan farklı bozuk
# girdilerle FARKLI hatalar tetikleyerek şemayı (tablo/sütun adları, sorgu yapısı) adım
# adım haritalar — error-based keşif.
"""
Modül 10 — Mishandling of Exceptional Conditions
Senaryo 3: Veritabanı Hatası Üzerinden Bilgi Sızıntısı (VULNERABLE)

Zafiyet: `GET /api/orders?order_id=...` gelen değeri sorguya gömer ve oluşan sqlite
hatasının TAM METNİNİ istemciye döndürür. Farklı bozuk girdiler farklı hata mesajları
üretir; her mesaj şemadan bir parça sızdırır (tablo adı, sütun adları, sorgu yapısı).

Modül 02/S3'ten farkı: orada sızan şey framework stack trace'i ve kütüphane sürümleriydi
(genel uygulama hataları). Burada sızan şey VERİTABANI ŞEMASI ve sorgu yapısıdır ve asıl
vurgu, saldırganın bunu BİLİNÇLİ ve TEKRARLI şekilde tetikleyerek bilgi topladığı bir
KEŞİF SÜRECİ olmasıdır.

Çalıştırma: uvicorn main:app --port 8300
"""
# PORT: 8300
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

DB_PATH = "orders.db"


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TABLE IF EXISTS customer_orders")
    conn.execute(
        """
        CREATE TABLE customer_orders (
            order_id INTEGER PRIMARY KEY,
            customer_email TEXT NOT NULL,
            product_name TEXT NOT NULL,
            total_amount REAL NOT NULL,
            internal_notes TEXT
        )
        """
    )
    conn.executemany(
        "INSERT INTO customer_orders VALUES (?, ?, ?, ?, ?)",
        [
            (1, "alice@example.com", "Laptop", 25000.0, "VIP müşteri"),
            (2, "bob@example.com", "Klavye", 750.0, None),
        ],
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
    return {"status": "up", "scenario": "database-error-info-leak"}


@app.get("/api/orders")
def get_orders(order_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Girdi sorguya gömülüyor (bu senaryonun konusu injection değil, HATA SIZINTISI).
    query = f"SELECT order_id, customer_email, product_name, total_amount FROM customer_orders WHERE order_id = {order_id}"
    try:
        rows = conn.execute(query).fetchall()
    except sqlite3.Error as e:
        # ZAFIYET: DB hatasının TAM METNİ + çalıştırılan sorgu istemciye dönüyor.
        # Saldırgan bunu tekrar tekrar tetikleyerek şemayı öğrenir.
        return JSONResponse(
            status_code=500,
            content={
                "error": "Veritabanı hatası",
                "db_error": str(e),          # ← sqlite'ın ham mesajı (sütun/tablo adları)
                "db_error_type": type(e).__name__,
                "executed_query": query,     # ← sorgu yapısı da sızıyor
            },
        )
    finally:
        conn.close()

    return {"orders": [dict(r) for r in rows], "count": len(rows)}
