# CWE-404 / CWE-772 — FIX.
# Kaynak, bir context manager (with) içinde ayrılır ve __exit__ garantisiyle HER ZAMAN
# serbest bırakılır — işlem başarılı da olsa, istisna da fırlasa. Cleanup'ı "hatırlamak"
# yerine dile/yapıya devretmek, bu sınıf hataları YAPISAL olarak önler.
"""
Modül 10 — Mishandling of Exceptional Conditions
Senaryo 1: Kaynak Tükenmesi / DoS (FIXED)

Tasarım: `managed_resource()` bir context manager'dır; `with` bloğundan çıkılırken
(normal dönüş, `return`, ya da istisna — fark etmez) kaynak serbest bırakılır. Aynı 5
hatalı istekten sonra `GET /resource-status` `locked_count: 0` gösterir ve sistem meşru
istekleri işlemeye devam eder.

Alternatif olarak `try/finally` de aynı garantiyi verir; context manager, bu garantiyi
yeniden kullanılabilir tek bir yerde topladığı için tercih edilmiştir.

Çalıştırma: uvicorn main:app --port 8281
"""
# PORT: 8281
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

POOL_SIZE = 5
LOCKED_RESOURCES: list[str] = []


class UploadRequest(BaseModel):
    filename: str


@contextmanager
def managed_resource(filename: str):
    """FIX: kaynak ayrılır ve çıkışta HER DURUMDA serbest bırakılır (istisna dahil)."""
    if len(LOCKED_RESOURCES) >= POOL_SIZE:
        raise HTTPException(
            status_code=503,
            detail=f"Kaynaklar tükendi ({len(LOCKED_RESOURCES)}/{POOL_SIZE} kilitli) — servis kullanılamıyor.",
        )
    handle = f"fh-{len(LOCKED_RESOURCES) + 1}:{filename}"
    LOCKED_RESOURCES.append(handle)
    try:
        yield handle
    finally:
        # Bu blok, istisna fırlasa bile ÇALIŞIR → kaynak sızıntısı imkânsız.
        if handle in LOCKED_RESOURCES:
            LOCKED_RESOURCES.remove(handle)


def process_upload(filename: str) -> str:
    # Vulnerable ile AYNI hata noktası — fark yalnızca kaynak yönetiminde.
    if filename.lower().startswith("corrupt_"):
        raise ValueError(f"Bozuk dosya adı: {filename}")
    return f"{filename} işlendi"


@app.get("/status")
def status():
    return {"status": "up", "scenario": "resource-exhaustion-dos (fixed)"}


@app.post("/upload")
def upload(req: UploadRequest):
    with managed_resource(req.filename) as handle:  # noqa: F841
        try:
            result = process_upload(req.filename)
        except ValueError as e:
            # İstisna yükseltilse bile with bloğunun finally'si kaynağı bırakır.
            raise HTTPException(status_code=400, detail=f"Yükleme başarısız: {e}")

    return {"uploaded": True, "result": result, "locked_count": len(LOCKED_RESOURCES)}


@app.get("/resource-status")
def resource_status():
    return {
        "locked_count": len(LOCKED_RESOURCES),
        "pool_size": POOL_SIZE,
        "available": POOL_SIZE - len(LOCKED_RESOURCES),
        "locked_resources": LOCKED_RESOURCES,
    }
