# CWE-117 (Improper Output Neutralization for Logs): kullanıcı girdisi, satır sonu (\n)
# gibi kontrol karakterleri temizlenmeden log satırına eklenir. Saldırgan girdiye gerçek
# bir newline koyarak log'a SAHTE, meşru görünümlü ek satırlar enjekte edebilir (log forging).
"""
Modül 09 — Security Logging and Alerting Failures
Senaryo 2: Log Injection / Forging (VULNERABLE)

Zafiyet: `POST /report-issue` gelen `message` alanını hiçbir temizlik yapmadan log
satırına gömer: f"User {username} reported: {message}". `message` içine gerçek bir `\n`
karakteri konursa, log'da yeni bir satır oluşur ve saldırgan ardına SAHTE bir sistem
kaydı ekleyebilir.

Bu GERÇEKTEN çalışır (defanged değil): enjekte edilen `\n` log listesinde ayrı, meşru
görünümlü bir satır üretir — GET /logs ile satır sayısının arttığı ve sahte satırın
gerçek bir sistem mesajı gibi durduğu görülür.

Çalıştırma: uvicorn main:app --port 8260
"""
# PORT: 8260
from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

APP_LOG: list[str] = []


def _log(line: str) -> None:
    # Her fiziksel satır, log listesine ayrı bir kayıt olarak eklenir (gerçek log
    # dosyası davranışını taklit eder: \n yeni satır = yeni kayıt).
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for physical_line in line.split("\n"):
        APP_LOG.append(f"{ts} {physical_line}")


class IssueRequest(BaseModel):
    username: str
    message: str


@app.get("/status")
def status():
    return {"status": "up", "scenario": "log-injection-forging"}


@app.post("/report-issue")
def report_issue(req: IssueRequest):
    # ZAFIYET: message hiç temizlenmeden log'a gömülüyor. İçindeki gerçek \n karakterleri
    # log'da yeni satırlar açar → saldırgan sahte log kaydı enjekte edebilir.
    _log(f"INFO User {req.username} reported: {req.message}")

    return {"received": True, "message": "Sorun bildirimi loglandı (bkz. GET /logs)."}


@app.get("/logs")
def get_logs():
    return {"log_lines": APP_LOG, "count": len(APP_LOG)}
