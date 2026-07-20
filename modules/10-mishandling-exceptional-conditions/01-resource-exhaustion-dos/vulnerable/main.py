# CWE-404 (Improper Resource Shutdown or Release) + CWE-772 (Missing Release of Resource
# after Effective Lifetime): istisna oluştuğunda ayrılan kaynak serbest bırakılmaz. Her
# hatalı istek bir kaynağı kalıcı olarak "kilitli" bırakır → havuz tükenir → DoS.
"""
Modül 10 — Mishandling of Exceptional Conditions
Senaryo 1: Kaynak Tükenmesi / DoS (VULNERABLE)

Zafiyet: `POST /upload` her istekte havuzdan bir "dosya handle'ı" ayırır. İşlem sırasında
bir istisna oluşursa (dosya adı 'x' içeriyorsa hata fırlatılır), istisna yakalanır AMA
kaynak serbest BIRAKILMAZ — `finally`/cleanup bloğu yoktur.

Sonuç: Her hatalı istek havuzdan bir slot sızdırır. Havuz küçük (5) olduğundan, 5 hatalı
istekten sonra sistem meşru istekleri de reddetmeye başlar ("kaynaklar tükendi") — yani
saldırgan yalnızca hatalı istek göndererek servisi kullanılamaz hale getirir (DoS).

Çalıştırma: uvicorn main:app --port 8280
"""
# PORT: 8280
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

POOL_SIZE = 5
# Kilitli (kullanımda) kaynakların listesi. Serbest bırakılmayan her kaynak burada kalır.
LOCKED_RESOURCES: list[str] = []


class UploadRequest(BaseModel):
    filename: str


def acquire_resource(filename: str) -> str:
    """Havuzdan bir kaynak ayırır. Havuz doluysa hata."""
    if len(LOCKED_RESOURCES) >= POOL_SIZE:
        raise HTTPException(
            status_code=503,
            detail=f"Kaynaklar tükendi ({len(LOCKED_RESOURCES)}/{POOL_SIZE} kilitli) — servis kullanılamıyor.",
        )
    handle = f"fh-{len(LOCKED_RESOURCES) + 1}:{filename}"
    LOCKED_RESOURCES.append(handle)
    return handle


def release_resource(handle: str) -> None:
    if handle in LOCKED_RESOURCES:
        LOCKED_RESOURCES.remove(handle)


def process_upload(filename: str) -> str:
    # Bilinçli hata noktası: dosya adı "corrupt_" ile başlıyorsa işlem başarısız olur.
    # (Açık bir işaretleyici — rastgele meşru dosya adlarının yanlışlıkla tetiklenmemesi için.)
    if filename.lower().startswith("corrupt_"):
        raise ValueError(f"Bozuk dosya adı: {filename}")
    return f"{filename} işlendi"


@app.get("/status")
def status():
    return {"status": "up", "scenario": "resource-exhaustion-dos"}


@app.post("/upload")
def upload(req: UploadRequest):
    handle = acquire_resource(req.filename)  # kaynak ayrıldı

    try:
        result = process_upload(req.filename)
    except ValueError as e:
        # ZAFIYET: istisna yakalanıyor ama kaynak SERBEST BIRAKILMIYOR.
        # finally bloğu / context manager yok → handle sonsuza dek kilitli kalır.
        raise HTTPException(status_code=400, detail=f"Yükleme başarısız: {e}")

    release_resource(handle)  # yalnızca BAŞARILI yolda serbest bırakılıyor
    return {"uploaded": True, "result": result, "locked_count": len(LOCKED_RESOURCES)}


@app.get("/resource-status")
def resource_status():
    return {
        "locked_count": len(LOCKED_RESOURCES),
        "pool_size": POOL_SIZE,
        "available": POOL_SIZE - len(LOCKED_RESOURCES),
        "locked_resources": LOCKED_RESOURCES,
    }
