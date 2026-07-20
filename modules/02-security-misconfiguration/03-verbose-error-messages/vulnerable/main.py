"""
Modül 02 — Security Misconfiguration
Senaryo 3: Verbose Error Messages (VULNERABLE)

Zafiyet: `GET /api/process/{item_id}` içinde yakalanmamış bir exception (sayısal
olmayan input için `int(item_id)` → ValueError) fırlatılıyor. Uygulama, production'da
açık kalmış bir "debug" davranışını taklit eden özel bir exception handler ile,
yanıt gövdesinde TAM stack trace'i VE kullanılan kütüphane sürümlerini istemciye
döndürüyor. Bu, saldırgana dosya yolları, iç kod yapısı ve bilinen CVE eşlemesi için
sürüm bilgisi veren klasik bir bilgi ifşasıdır (CWE-209).

Çalıştırma: uvicorn main:app --port 8030
"""
# PORT: 8030
import traceback
from importlib.metadata import PackageNotFoundError, version

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# Yanıtta ifşa edilen "kullanılan kütüphaneler" — gerçekte requirements.txt'teki paketler.
TRACKED_PACKAGES = ["fastapi", "starlette", "pydantic", "uvicorn"]


def _dependency_versions() -> dict:
    result = {}
    for pkg in TRACKED_PACKAGES:
        try:
            result[pkg] = version(pkg)
        except PackageNotFoundError:
            result[pkg] = "unknown"
    return result


@app.get("/api/process/{item_id}")
def process_item(item_id: str):
    # ZAFIYET (tetikleyici): item_id str olarak alınıyor ve doğrudan int()'e veriliyor.
    # "abc" gibi sayısal olmayan bir değerde ValueError fırlar ve YAKALANMAZ.
    numeric_id = int(item_id)
    return {"item_id": numeric_id, "status": "processed"}


@app.exception_handler(Exception)
async def verbose_exception_handler(request: Request, exc: Exception):
    # ZAFIYET (asıl kusur): Beklenmeyen hata olduğunda istemciye tam iç detay dönüyor.
    # - traceback.format_exc(): tam stack trace → dosya yolları, satır numaraları, iç fonksiyon adları
    # - _dependency_versions(): kütüphane sürümleri → saldırgan için bilinen CVE eşlemesi
    # Bu bilgiler yalnızca sunucu tarafı log'a ait olmalıyken response body'sinde sızıyor.
    return JSONResponse(
        status_code=500,
        content={
            "error": str(exc),
            "exception_type": type(exc).__name__,
            "traceback": traceback.format_exc(),
            "dependencies": _dependency_versions(),
        },
    )
