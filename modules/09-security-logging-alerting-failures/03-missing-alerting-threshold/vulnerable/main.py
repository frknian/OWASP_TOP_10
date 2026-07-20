# CWE-778 (Insufficient Logging — burada "insufficient ALERTING" olarak yorumlanır):
# başarısız login denemeleri loglanır ama hiçbir eşik/tetikleyici mantığı yoktur. Saldırı
# kayda geçer ama kimse/hiçbir şey tepki vermez. "Great logging with no alerting is of
# minimal value." (OWASP A09).
"""
Modül 09 — Security Logging and Alerting Failures
Senaryo 3: Alerting Eksikliği — Loglanıyor Ama Alarm Yok (VULNERABLE)

Zafiyet: `POST /login` başarısız denemeleri loglar (log listesi büyür), AMA hiçbir eşik
mantığı yoktur. Aynı kullanıcıya karşı 50 başarısız deneme olsa bile `GET /alerts` HER
ZAMAN boş liste döner. Veri toplanıyor ama harekete dönüşmüyor.

Loglama HER İKİ sürümde de çalışır (bu senaryonun konusu loglama değil); fark ALERTING'te.

Çalıştırma: uvicorn main:app --port 8270
"""
# PORT: 8270
from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

APP_LOG: list[str] = []
# Not: bir "alerts" deposu YOK — çünkü hiçbir alert üretilmiyor.


def _log(line: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    APP_LOG.append(f"{ts} {line}")


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/status")
def status():
    return {"status": "up", "scenario": "missing-alerting-threshold"}


@app.post("/login")
def login(req: LoginRequest):
    # Başarısız deneme loglanıyor (loglama VAR)...
    _log(f"WARN Failed login for username={req.username}")
    # ...ama hiçbir eşik kontrolü / alert üretimi YOK (alerting eksik).
    return {"authenticated": False, "message": "Başarısız giriş loglandı — ama alarm üretilmedi."}


@app.get("/logs")
def get_logs():
    return {"log_lines": APP_LOG, "count": len(APP_LOG)}


@app.get("/alerts")
def get_alerts():
    # ZAFIYET: eşik mantığı olmadığından bu liste HER ZAMAN boştur — kaç deneme olursa olsun.
    return {"alerts": [], "count": 0, "note": "Hiçbir alerting eşiği tanımlı değil — saldırı kayda geçse de alarm yok."}
