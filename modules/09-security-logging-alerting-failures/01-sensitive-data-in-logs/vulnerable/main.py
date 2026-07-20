# CWE-532 (Insertion of Sensitive Information into Log File): uygulama, kimlik doğrulama
# isteğinin tam gövdesini (parola dahil) düz metin olarak log'a yazar. Log dosyaları genelde
# daha az korunur ve daha çok kişi/servis tarafından erişilir → hassas veri sızıntısı.
"""
Modül 09 — Security Logging and Alerting Failures
Senaryo 1: Loglara Hassas Veri Sızması (VULNERABLE)

Zafiyet: `POST /login` her denemede gelen tüm request body'yi (username VE password düz
metin) log satırına yazar. `GET /logs` (debug endpoint'i) bu log'u döndürdüğünde
parolalar açıkça görünür.

Neden tehlikeli: Log dosyaları çoğu zaman uygulamanın kendisinden daha zayıf korunur —
farklı ekipler (ops, destek, veri analizi) erişebilir, yedeklenir, ve üçüncü taraf log
toplama/analiz servislerine (Datadog, Splunk, ELK, CloudWatch) gönderilir. Parola log'a
bir kez yazıldığında, artık bu geniş yüzeyin tamamına sızmış demektir.

Çalıştırma: uvicorn main:app --port 8250
"""
# PORT: 8250
from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

# In-memory uygulama log'u (gerçek sistemde dosya/stdout/log servisi olurdu).
APP_LOG: list[str] = []


def _log(line: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    APP_LOG.append(f"{ts} {line}")


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/status")
def status():
    return {"status": "up", "scenario": "sensitive-data-in-logs"}


@app.post("/login")
def login(req: LoginRequest):
    # ZAFIYET: tam request body log'a düz metin yazılıyor — password dahil.
    _log(f"INFO Login attempt: username={req.username} password={req.password}")

    # (Kimlik doğrulama mantığı bu senaryonun konusu değil; her deneme "reddedildi" kabul.)
    return {"authenticated": False, "message": "Giriş denemesi loglandı (bkz. GET /logs)."}


@app.get("/logs")
def get_logs():
    # ZAFIYET: log, redaksiyon olmadan olduğu gibi döndürülüyor → parolalar görünür.
    return {"log_lines": APP_LOG, "count": len(APP_LOG)}
