# CWE-209 (Generation of Error Message Containing Sensitive Information) — FIX.
# Tüm DB hataları yakalanır ve istemciye HER ZAMAN aynı jenerik mesaj döner. Detay yalnızca
# sunucu tarafı log'a yazılır (Modül 09 prensibiyle tutarlı: log'a hassas VERİ değil, hata
# teşhisi yazılır). Ayrıca girdi doğrulaması ve parametreli sorgu ile hata hiç oluşmaz.
"""
Modül 10 — Mishandling of Exceptional Conditions
Senaryo 3: Veritabanı Hatası Üzerinden Bilgi Sızıntısı (FIXED)

İki katman:
    (1) Hata OLUŞMASINI engelle: order_id tip olarak doğrulanır (int) ve sorgu
        parametreli (?) çalıştırılır → bozuk girdi DB'ye hiç ulaşmaz.
    (2) Hata oluşursa SIZDIRMA: tüm sqlite hataları yakalanır; istemciye her durumda
        AYNI jenerik yanıt (`400 Geçersiz istek`) döner. Saldırgan farklı girdilerle
        farklı yanıtlar alamadığı için error-based keşif yapamaz (oracle kapanır).

Detaylar sunucu log'una yazılır — hata teşhisi mümkün kalır, ama istemci hiçbir şey
öğrenmez. Log'a müşteri verisi (e-posta vb.) yazılmaz.

Çalıştırma: uvicorn main:app --port 8301
"""
# PORT: 8301
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException

DB_PATH = "orders.db"
SERVER_LOG: list[str] = []  # sunucu tarafı teşhis log'u (istemciye AÇILMAZ)

GENERIC_ERROR = "Geçersiz istek"


def _log(line: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    SERVER_LOG.append(f"{ts} {line}")


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
    return {"status": "up", "scenario": "database-error-info-leak (fixed)"}


# SQLite INTEGER sınırı (64-bit işaretli). Bu aralığın dışındaki değerler sürücüde
# OverflowError üretir — sqlite3.Error DEĞİLDİR, bu yüzden ayrıca sınırlanmalıdır.
INT64_MIN, INT64_MAX = -(2**63), 2**63 - 1


@app.get("/api/orders")
def get_orders(order_id: str):
    # KATMAN 1: girdi doğrulaması — bozuk/aralık dışı değer DB'ye hiç ulaşmaz.
    try:
        parsed_id = int(order_id)
    except ValueError:
        _log(f"WARN Invalid order_id format (len={len(order_id)}) — generic error returned")
        raise HTTPException(status_code=400, detail=GENERIC_ERROR)

    # Aralık kontrolü: Python int sınırsızdır, SQLite değildir. Bu kontrol olmadan
    # devasa sayılar sürücüde OverflowError'a düşer ve 500 dönerek oracle'ı açık bırakır.
    if not (INT64_MIN <= parsed_id <= INT64_MAX):
        _log(f"WARN order_id out of range (digits={len(order_id)}) — generic error returned")
        raise HTTPException(status_code=400, detail=GENERIC_ERROR)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        # KATMAN 1b: parametreli sorgu — değer veri olarak bağlanır.
        rows = conn.execute(
            "SELECT order_id, customer_email, product_name, total_amount FROM customer_orders WHERE order_id = ?",
            (parsed_id,),
        ).fetchall()
    except Exception as e:
        # KATMAN 2: hata olsa bile istemciye AYNI jenerik mesaj; detay sadece log'a.
        # NOT: sqlite3.Error DEĞİL, Exception yakalanır — sürücü OverflowError gibi
        # sqlite3.Error olmayan istisnalar da fırlatabilir. Herhangi bir istisnanın
        # farklı bir yanıta (ör. 500) dönüşmesi, saldırgana ayırt edici sinyal verir
        # ve oracle'ı yeniden açar. Tüm hata yolları TEK bir yanıta indirgenir.
        _log(f"ERROR db {type(e).__name__}: {e}")
        raise HTTPException(status_code=400, detail=GENERIC_ERROR)
    finally:
        conn.close()

    return {"orders": [dict(r) for r in rows], "count": len(rows)}


@app.get("/server-log")
def server_log():
    # Lab görünürlüğü: hata detaylarının GERÇEKTEN loglandığını (ama istemciye
    # dönmediğini) göstermek için. Gerçek sistemde bu endpoint yetkilendirilmiş olurdu.
    return {"log_lines": SERVER_LOG, "count": len(SERVER_LOG)}
