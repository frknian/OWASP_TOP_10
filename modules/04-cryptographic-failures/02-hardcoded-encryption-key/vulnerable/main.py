# CWE-321 (Use of Hardcoded Cryptographic Key) + CWE-798 (Use of Hard-coded
# Credentials): şifreleme anahtarı kaynak kodun içine gömülüdür.
"""
Modül 04 — Cryptographic Failures
Senaryo 2: Hardcoded Encryption Key (VULNERABLE)

Zafiyet: Uygulama "özel notları" Fernet (AES tabanlı authenticated encryption) ile
şifreler — yani şifreleme DOĞRU yapılır. Kusur ALGORİTMADA değil, ANAHTAR YÖNETİMİNDE:
anahtar doğrudan kaynak kodun içinde sabit bir string olarak durur. Kaynağa erişen
herkes (repo, container image, decompile, ya da aşağıdaki /source-leak endpoint'i)
anahtarı elde eder ve tüm şifreli veriyi çözer. Şifreleme, anahtar gizli değilse
hiçbir şey korumaz.

/source-leak endpoint'i (Modül 02'nin "kaynak/directory exposure" temasına gönderme),
anahtarın pratikte nasıl keşfedilebileceğini somut olarak gösterir.

Çalıştırma: uvicorn main:app --port 8100
"""
# PORT: 8100
import base64
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

DB_PATH = "notes_vuln.db"

# ZAFIYET (CWE-321): Anahtar kaynak koda GÖMÜLÜ. 32 baytlık sabit sır, geçerli bir
# Fernet anahtarına (url-safe base64) çevriliyor — ama sır kaynakta açıkça duruyor.
_HARDCODED_SECRET = b"hardcoded-demo-key-32-bytes-lo!!"  # tam 32 bayt
ENCRYPTION_KEY = base64.urlsafe_b64encode(_HARDCODED_SECRET)
fernet = Fernet(ENCRYPTION_KEY)


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
    init_db()
    yield


app = FastAPI(lifespan=lifespan)


@app.get("/status")
def status():
    return {"status": "up", "cipher": "fernet", "key_source": "hardcoded-in-source"}


@app.post("/notes")
def create_note(note: Note):
    # Şifreleme kendisi güvenli; sorun anahtarın gizli olmaması.
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


@app.get("/source-leak", response_class=PlainTextResponse)
def source_leak():
    # ZAFIYET: Uygulamanın kaynak kodunu dışarı verir. _HARDCODED_SECRET burada
    # görünür → saldırgan anahtarı çıkarıp DB'deki tüm notları çözebilir.
    return Path(__file__).read_text(encoding="utf-8")
