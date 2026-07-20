"""
Modül 02 — Security Misconfiguration
Senaryo 2: Directory Listing → Source Exposure (FIXED)

Remediation:
  1. `GET /files/` directory-listing endpoint'i tamamen KALDIRILDI — klasör içeriği
     artık dışarıya listelenmiyor.
  2. Dosyalar `os.path.join(FILES_DIR, filename)` ile serbestçe açılmıyor; yalnızca
     açıkça izin verilmiş (whitelist) dosyalar servis ediliyor. `old_admin_utils.py`
     diskte hâlâ dursa bile whitelist'te olmadığı için erişilemez (404).

Önemli tasarım noktası: `old_admin_utils.py` dosyası fixed sürümde de diskte
BIRAKILDI. Amaç, düzeltmenin "dosyayı sildik" değil "erişimi doğru kısıtladık"
olduğunu göstermek — dosya var olduğu halde artık web'den ulaşılamıyor. (İdealde bu
dosya webroot'tan da çıkarılır; burada erişim kontrolünün tek başına yeterliliğini
göstermek için bilinçli olarak duruyor.)

Çalıştırma: uvicorn main:app --port 8021
"""
# PORT: 8021
import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse

app = FastAPI()

FILES_DIR = os.path.join(os.path.dirname(__file__), "files")

# Yalnızca müşteriyle paylaşılması amaçlanan, bilinen dosyalar açıkça izinli.
ALLOWED_FILES = {"readme.txt"}


@app.get("/")
def index():
    return {"app": "Acme Widgets API", "status": "running"}


# NOT: /files/ directory-listing endpoint'i burada kasıtlı olarak YOKTUR.
# Klasör içeriğinin dışarıya listelenmesi tamamen kaldırıldı.


@app.get("/files/{filename}", response_class=PlainTextResponse)
def get_file(filename: str):
    # Fix: serbest dosya açma yerine whitelist. İzin listesinde olmayan hiçbir dosya
    # (örn. old_admin_utils.py) servis edilmez — dosya diskte var olsa bile 404 döner.
    # Bu aynı zamanda path traversal (../) denemelerini de etkisiz kılar; çünkü karar
    # dosya yolundan değil, sabit izin kümesinden veriliyor.
    if filename not in ALLOWED_FILES:
        raise HTTPException(status_code=404, detail="Not found")

    file_path = os.path.join(FILES_DIR, filename)
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()
