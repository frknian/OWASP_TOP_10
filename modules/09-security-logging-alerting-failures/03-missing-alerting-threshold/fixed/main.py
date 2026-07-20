# CWE-778 (Insufficient Logging → burada "insufficient ALERTING") — FIX.
# Loglama aynı kalır; EK olarak bir eşik mantığı gelir: aynı username'e karşı 60 sn içinde
# 5+ başarısız deneme olursa bir "alert" objesi üretilip /alerts listesine eklenir. Toplanan
# veri artık harekete dönüşür — "loglamak yetmez, birinin/bir şeyin tepki vermesi gerekir".
"""
Modül 09 — Security Logging and Alerting Failures
Senaryo 3: Alerting Eksikliği (FIXED)

Tasarım: Başarısız login denemeleri (vulnerable ile aynı şekilde) loglanır, AMA ayrıca
kullanıcı bazlı bir kayan pencere sayacı tutulur. 60 saniyelik pencerede aynı username'e
karşı ALERT_THRESHOLD (5) veya daha fazla başarısız deneme olursa, bir alert objesi
üretilir ve GET /alerts'te görünür:
    {"type": "brute_force_suspected", "username": "...", "attempt_count": N, "timestamp": "..."}

Bu, OWASP A09'un 2021→2025 isim değişikliğinin (Monitoring → Alerting) özüdür: veri
toplamak (loglama) tek başına yetmez; bir eşik aşıldığında birinin/bir şeyin haberdar
olması (alerting) gerekir.

Çalıştırma: uvicorn main:app --port 8271
"""
# PORT: 8271
import time
from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

ALERT_THRESHOLD = 5      # pencere içinde bu kadar başarısız deneme → alert
ALERT_WINDOW_SECONDS = 60

APP_LOG: list[str] = []
ALERTS: list[dict] = []
# username -> başarısız deneme zaman damgaları (kayan pencere)
FAILED_ATTEMPTS: dict[str, list[float]] = {}


def _log(line: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    APP_LOG.append(f"{ts} {line}")


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/status")
def status():
    return {"status": "up", "scenario": "missing-alerting-threshold (fixed)"}


@app.post("/login")
def login(req: LoginRequest):
    # Loglama (vulnerable ile aynı)...
    _log(f"WARN Failed login for username={req.username}")

    # ...ARTI eşik mantığı: kayan pencerede başarısız denemeleri say.
    now = time.time()
    window_start = now - ALERT_WINDOW_SECONDS
    attempts = [t for t in FAILED_ATTEMPTS.get(req.username, []) if t > window_start]
    attempts.append(now)
    FAILED_ATTEMPTS[req.username] = attempts

    alert_created = False
    if len(attempts) >= ALERT_THRESHOLD:
        # Eşik aşıldı → alert üret. (Aynı pencerede tekrar tekrar üretmemek için, bu
        # username için zaten aktif bir alert yoksa ekle.)
        already = any(a["username"] == req.username and a["type"] == "brute_force_suspected" for a in ALERTS)
        if not already:
            alert = {
                "type": "brute_force_suspected",
                "username": req.username,
                "attempt_count": len(attempts),
                "window_seconds": ALERT_WINDOW_SECONDS,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            ALERTS.append(alert)
            _log(f"ALERT brute_force_suspected username={req.username} attempts={len(attempts)}")
            alert_created = True

    return {
        "authenticated": False,
        "message": "Başarısız giriş loglandı.",
        "alert_created": alert_created,
        "failed_in_window": len(attempts),
    }


@app.get("/logs")
def get_logs():
    return {"log_lines": APP_LOG, "count": len(APP_LOG)}


@app.get("/alerts")
def get_alerts():
    # FIX: eşik aşıldığında üretilen gerçek alert objeleri burada görünür.
    return {"alerts": ALERTS, "count": len(ALERTS)}


@app.post("/reset")
def reset():
    # Lab kolaylığı: sayaçları ve alert'leri sıfırlar. Gerçek sistemde bulunmaz.
    APP_LOG.clear()
    ALERTS.clear()
    FAILED_ATTEMPTS.clear()
    return {"reset": True}
