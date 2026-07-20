# CWE-117 (Improper Output Neutralization for Logs) — FIX.
# Kullanıcı girdisi log'a yazılmadan önce satır sonu / satır başı karakterleri escape edilir
# (\n → \\n, \r → \\r). Böylece enjekte edilen newline gerçek bir satır sonu ÜRETMEZ; girdi
# her zaman tek bir log satırı içinde kaçış karakteri olarak görünür.
"""
Modül 09 — Security Logging and Alerting Failures
Senaryo 2: Log Injection / Forging (FIXED)

Tasarım: Log'a yazılacak her serbest-metin girdi, `sanitize_for_log()` ile temizlenir:
kontrol karakterleri (özellikle \n ve \r) görünür kaçış dizilerine dönüştürülür. Saldırgan
`message` içine gerçek bir newline koysa da, log'da yeni satır açılmaz — enjekte edilen
içerik `\n[ADMIN] ...` şeklinde, tek satırlık ve açıkça "kullanıcı verisi" olarak kalır.

Çalıştırma: uvicorn main:app --port 8261
"""
# PORT: 8261
from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

APP_LOG: list[str] = []


def sanitize_for_log(value: str) -> str:
    # FIX: satır sonu/başı ve diğer kontrol karakterlerini escape et → log forging imkânsız.
    return (
        value.replace("\\", "\\\\")  # önce ters bölü (kaçışların kaçışı)
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def _log(line: str) -> None:
    # Girdi zaten sanitize edildiği için burada \n YOKTUR → tek kayıt eklenir.
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    APP_LOG.append(f"{ts} {line}")


class IssueRequest(BaseModel):
    username: str
    message: str


@app.get("/status")
def status():
    return {"status": "up", "scenario": "log-injection-forging (fixed)"}


@app.post("/report-issue")
def report_issue(req: IssueRequest):
    # FIX: username ve message log'a yazılmadan önce escape edilir.
    safe_user = sanitize_for_log(req.username)
    safe_msg = sanitize_for_log(req.message)
    _log(f"INFO User {safe_user} reported: {safe_msg}")

    return {"received": True, "message": "Sorun bildirimi güvenli şekilde loglandı (kontrol karakterleri escape edildi)."}


@app.get("/logs")
def get_logs():
    return {"log_lines": APP_LOG, "count": len(APP_LOG)}
