"""
Modül 02 — Security Misconfiguration
Senaryo 3: Verbose Error Messages (FIXED)

Remediation: Genel (last-resort) bir exception handler eklendi. Beklenmeyen bir hata
oluştuğunda istemciye YALNIZCA `{"detail": "Internal server error"}` (jenerik mesaj)
dönüyor; tam stack trace ve kütüphane sürümleri gibi detaylar YALNIZCA sunucu tarafı
log'a (console) yazılıyor. Böylece hata ayıklama bilgisi ekipte kalır, saldırgana sızmaz.

Çalıştırma: uvicorn main:app --port 8031
"""
# PORT: 8031
import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("acme.errors")

app = FastAPI()


@app.get("/api/process/{item_id}")
def process_item(item_id: str):
    # Tetikleyici aynı bırakıldı: sayısal olmayan input hâlâ ValueError fırlatır.
    # Fark, hatanın istemciye NASIL yansıdığındadır — aşağıdaki handler onu jenerikleştirir.
    numeric_id = int(item_id)
    return {"item_id": numeric_id, "status": "processed"}


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Fix: Detaylar yalnızca sunucu log'una. logger.exception(...) tam stack trace'i
    # console'a yazar (destek/geliştirme için); istemci ise ayrıntısız jenerik yanıt alır.
    logger.exception("Unhandled error while processing %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )
