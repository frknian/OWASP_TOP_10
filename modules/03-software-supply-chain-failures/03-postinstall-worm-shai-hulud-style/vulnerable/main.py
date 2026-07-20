# DEFANGED SIMULATION — no real malicious behavior, for educational demonstration only
"""
Modül 03 — Software Supply Chain Failures
Senaryo 3: Post-install Worm / Shai-Hulud tarzı (VULNERABLE)

Zafiyet: Uygulama, ele geçirilmiş `awesome_utils` paketine bağımlıdır. Bu paketin
"post-install" zararlı mantığı, uygulama başlangıcında (FastAPI `lifespan`) otomatik
çalışır — kullanıcı hiçbir endpoint'e istek atmadan önce bile. Yani zafiyet, uygulama
ayağa kalkar kalkmaz tetiklenir; bu, kurulum/başlangıç adımında çalışan supply chain
worm'unun doğasını yansıtır.

`GET /status` endpoint'i, uygulamanın ayakta olduğunu doğrulamak ve post-install
simülasyonunun çıktısını görüntülemek için vardır.

Çalıştırma: uvicorn main:app --port 8070
"""
# PORT: 8070
from contextlib import asynccontextmanager

import awesome_utils
from fastapi import FastAPI

# Post-install simülasyonunun çıktısını /status üzerinden görebilmek için saklıyoruz.
_STARTUP_REPORT = {"postinstall_output": None}


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ZAFIYET: Bağımlılığın post-install/worm kodu, uygulama başlar başlamaz çalışıyor.
    # Uygulama bunu istememesine rağmen, güvenilen paket bunu kendisi tetikliyor.
    _STARTUP_REPORT["postinstall_output"] = awesome_utils.run_postinstall()
    yield


app = FastAPI(lifespan=lifespan)


@app.get("/status")
def status():
    return {
        "status": "up",
        "component": "awesome_utils",
        "component_version": awesome_utils.__version__,
        "postinstall_simulation": _STARTUP_REPORT["postinstall_output"],
    }
