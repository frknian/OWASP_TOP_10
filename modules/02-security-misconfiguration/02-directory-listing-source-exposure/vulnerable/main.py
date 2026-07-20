"""
Modül 02 — Security Misconfiguration
Senaryo 2: Directory Listing → Source Exposure (VULNERABLE)

Zafiyet: `files/` klasörünün içeriğini listeleyen custom bir directory-listing
endpoint'i (`GET /files/`) ve bu klasördeki HERHANGİ bir dosyayı ham olarak servis
eden bir endpoint (`GET /files/{filename}`). Klasörde masum bir readme.txt'in yanında,
canlı DB parolası ve bir IDOR tasarım kusurunu ifşa eden yorum içeren, unutulmuş bir
`old_admin_utils.py` kaynak dosyası var.

Not: FastAPI'de directory listing varsayılan olarak YOKTUR; buradaki liste os.listdir
ile bilinçli olarak üretildi (gerçekte StaticFiles(html=...) yanlış yapılandırması veya
web sunucusunda autoindex açık kalması ile aynı sonuç doğar).

Çalıştırma: uvicorn main:app --port 8020
"""
# PORT: 8020
import os

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse

app = FastAPI()

FILES_DIR = os.path.join(os.path.dirname(__file__), "files")


@app.get("/")
def index():
    return {"app": "Acme Widgets API", "status": "running"}


@app.get("/files/", response_class=HTMLResponse)
def list_files():
    # ZAFIYET: Klasörün tüm içeriği herkese listeleniyor. Saldırgan, dosya isimlerini
    # tahmin etmeye bile gerek kalmadan `old_admin_utils.py` gibi unutulmuş dosyaları
    # doğrudan görüyor (bilgi ifşası + saldırı yüzeyi keşfi).
    entries = os.listdir(FILES_DIR)
    links = "".join(f'<li><a href="/files/{name}">{name}</a></li>' for name in sorted(entries))
    return f"<h2>Index of /files/</h2><ul>{links}</ul>"


@app.get("/files/{filename}", response_class=PlainTextResponse)
def get_file(filename: str):
    # ZAFIYET: Klasördeki her dosya, tür/whitelist ayrımı yapılmadan ham içerikle servis
    # ediliyor. `.py` kaynak dosyası dahi (yorumlanmadan) düz metin olarak dönüyor —
    # böylece hardcoded credential ve IDOR yorumu doğrudan okunabiliyor.
    file_path = os.path.join(FILES_DIR, filename)
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()
