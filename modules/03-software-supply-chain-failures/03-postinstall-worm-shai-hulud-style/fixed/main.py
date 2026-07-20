# DEFANGED SIMULATION — no real malicious behavior, for educational demonstration only
"""
Modül 03 — Software Supply Chain Failures
Senaryo 3: Post-install Worm / Shai-Hulud tarzı (FIXED)

Remediation: Güvenilir, imzası doğrulanmış ve sürümü pinlenmiş `awesome_utils` temiz
sürümüne geçildi. Bu sürümde uygulama başlangıcında (lifespan) çalışan gizli post-install
mantığı yoktur — startup'ta hiçbir sır toplanmaz, hiçbir dosya yazılmaz, hiçbir yayılma
simülasyonu tetiklenmez. Paket yalnızca açıkça çağrıldığında ilan ettiği işi yapar.

Çalıştırma: uvicorn main:app --port 8071
"""
# PORT: 8071
from contextlib import asynccontextmanager

import awesome_utils
from fastapi import FastAPI


@asynccontextmanager
async def lifespan(app: FastAPI):
    # FIX: Başlangıçta zararlı/gizli hiçbir şey çalışmıyor. Temiz paket sessizce yüklenir.
    yield


app = FastAPI(lifespan=lifespan)


@app.get("/status")
def status():
    return {
        "status": "up",
        "component": "awesome_utils",
        "component_version": awesome_utils.__version__,
        "postinstall_simulation": None,  # startup'ta gizli davranış yok
    }
