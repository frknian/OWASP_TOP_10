# FIX (CWE-321/798): şifreleme anahtarı kaynak kodda DEĞİL, ortam değişkeninden
# (secret manager sınırı) yüklenir. /source-leak endpoint'i kaldırıldı.
"""
Modül 04 — Cryptographic Failures
Senaryo 2: Hardcoded Encryption Key (FIXED)

Remediation: Şifreleme algoritması aynı (Fernet). Değişen tek şey ANAHTAR YÖNETİMİ:
anahtar artık `ENCRYPTION_KEY` ortam değişkeninden okunur ve kaynak kodda hiç geçmez.
Böylece kaynak kod sızsa bile anahtar sızmaz; anahtar rotasyonu kod değişikliği
gerektirmez; anahtar bir gizli-yönetim sistemine (Vault, KMS, systemd/CI secret)
devredilebilir. Ayrıca /source-leak endpoint'i tamamen kaldırıldı.

Anahtar üretimi (bir kez, kaynağa YAZILMADAN) ve çalıştırma:
    export ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    uvicorn main:app --port 8101

FAIL-SECURE: ENCRYPTION_KEY ortam değişkeni yoksa uygulama SESSİZCE güvensiz bir moda
düşmez — startup'ta (lifespan) net bir RuntimeError fırlatıp süreci durdurur. Bu,
Modül 02'de kurulan "fail secure" davranışıyla tutarlıdır: eksik/yanlış yapılandırmada
hiç çalışmamak, güvensiz çalışmaktan iyidir.
"""
# PORT: 8101
import os
import sqlite3
from contextlib import asynccontextmanager

from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

DB_PATH = "notes_fixed.db"

# FIX (CWE-321): Anahtar ortamdan gelir; kaynak kodda hiçbir sabit sır yok.
# Fernet nesnesi, anahtar doğrulandıktan sonra lifespan içinde kurulur.
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


class Note(BaseModel):
    content: str


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ciphertext TEXT NOT NULL
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
    return {"status": "up", "cipher": "fernet", "key_source": "environment-variable"}


@app.post("/notes")
def create_note(note: Note):
    token = fernet.encrypt(note.content.encode("utf-8")).decode("utf-8")
    conn = get_db_connection()
    cur = conn.execute("INSERT INTO notes (ciphertext) VALUES (?)", (token,))
    conn.commit()
    note_id = cur.lastrowid
    conn.close()
    return {"id": note_id, "stored_ciphertext": token}


@app.get("/notes/{note_id}")
def read_note(note_id: int):
    conn = get_db_connection()
    row = conn.execute("SELECT ciphertext FROM notes WHERE id = ?", (note_id,)).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Not bulunamadı")
    plaintext = fernet.decrypt(row["ciphertext"].encode("utf-8")).decode("utf-8")
    return {"id": note_id, "content": plaintext}


# NOT: /source-leak endpoint'i BİLİNÇLİ olarak yoktur (vulnerable'da vardı) → 404.
# Anahtar zaten kaynakta olmadığı için kaynak sızsa bile şifreli veri güvende kalır.
