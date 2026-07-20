"""
Modül 02 — Security Misconfiguration
Senaryo 4: Public Cloud Storage Misconfiguration (FIXED)

Remediation: Storage nesnesine erişim, geçerli bir API key şartına bağlandı. `X-API-Key`
header'ı eksik ya da yanlışsa istek 403 ile reddedilir; yalnızca doğru key ile nesne
servis edilir. Bu, gerçek dünyada bucket'ı "Block Public Access" ile kapatıp erişimi
kimliği doğrulanmış/yetkili principal'lara (IAM policy, SAS token, imzalı URL vb.) sınırlamanın
lokal karşılığıdır — anonim public erişim kaldırılır.

ÖNEMLİ: Bu senaryo gerçek bir cloud servisine istek ATMAZ; lokal mock storage üzerinde
simülasyondur (bkz. report.md).

Çalıştırma: uvicorn main:app --port 8041
"""
# PORT: 8041
import os

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import PlainTextResponse

app = FastAPI()

BUCKET_DIR = os.path.join(os.path.dirname(__file__), "bucket")

# Gerçekte bu değer environment/secret manager'dan gelir; lab'da sabit tutuldu.
# (Gömülü sabit key'in kendisi de bir kötü pratiktir; buradaki odak public erişimin
#  kapatılmasıdır — key yönetimi ayrı bir konudur.)
VALID_API_KEY = os.environ.get("STORAGE_API_KEY", "acme-storage-key-please-rotate")


def require_api_key(x_api_key: str | None = Header(default=None)):
    # Fix: Anonim erişim kaldırıldı. Nesneye ulaşmadan ÖNCE kimlik/yetki doğrulanıyor.
    # Key yoksa veya yanlışsa akış hiç dosya sistemine inmeden 403 ile kesilir —
    # yani "public read" varsayılanı yerine "explicit deny by default" davranışı.
    if x_api_key is None or x_api_key != VALID_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: valid X-API-Key required",
        )


@app.get("/")
def index():
    return {"app": "Acme Cloud Storage (mock)", "status": "running"}


@app.get("/storage/{filename}", response_class=PlainTextResponse)
def get_object(filename: str, _: None = Depends(require_api_key)):
    # Yetki kontrolü dependency olarak endpoint'in önüne konuldu; ancak buraya
    # gelindiğinde geçerli bir API key doğrulanmış olur.
    object_path = os.path.join(BUCKET_DIR, filename)
    with open(object_path, "r", encoding="utf-8") as f:
        return f.read()
