# CWE-532 (Insertion of Sensitive Information into Log File) — FIX.
# Hassas alanlar (password, token, secret, credit_card...) log'a yazılmadan önce genel bir
# redaksiyon fonksiyonundan geçirilir ve [REDACTED] ile maskelenir. Log'un işlevi korunur
# (kim, ne zaman denedi) ama gizli değerler asla log'a ulaşmaz.
"""
Modül 09 — Security Logging and Alerting Failures
Senaryo 1: Loglara Hassas Veri Sızması (FIXED)

Tasarım: Log'a yazılacak veri, önce alan adına göre çalışan genel bir redaksiyon
fonksiyonundan geçer. Hassas alan adları (allowlist yerine denylist — çünkü "neyin gizli
olduğu" bellidir) [REDACTED] ile değiştirilir. Böylece:
    * Log hâlâ faydalıdır: kim (username), ne zaman, hangi endpoint denendi görülür.
    * Gizli değerler (password) log'a HİÇ yazılmaz → dosya/servis/ekip yüzeyinin hiçbirine
      sızmaz.

Çalıştırma: uvicorn main:app --port 8251
"""
# PORT: 8251
import re
from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

APP_LOG: list[str] = []

# Log'a yazılırken maskelenecek hassas alan adları.
SENSITIVE_FIELDS = {"password", "passwd", "pwd", "token", "secret", "api_key", "credit_card", "cvv", "ssn"}


def redact(data: dict) -> dict:
    """Hassas alanları [REDACTED] ile maskeler (log'a yazmadan önce çağrılır)."""
    return {k: ("[REDACTED]" if k.lower() in SENSITIVE_FIELDS else v) for k, v in data.items()}


def redact_text(text: str) -> str:
    """Serbest metinde 'alan=değer' kalıplarını da maskeler (defansif ikinci katman)."""
    pattern = r"\b(" + "|".join(re.escape(f) for f in SENSITIVE_FIELDS) + r")=(\S+)"
    return re.sub(pattern, r"\1=[REDACTED]", text, flags=re.IGNORECASE)


def _log(line: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    APP_LOG.append(f"{ts} {line}")


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/status")
def status():
    return {"status": "up", "scenario": "sensitive-data-in-logs (fixed)"}


@app.post("/login")
def login(req: LoginRequest):
    # FIX: request body redaksiyondan geçirilerek loglanır — password [REDACTED] olur.
    safe = redact(req.model_dump())
    _log(f"INFO Login attempt: username={safe['username']} password={safe['password']}")

    return {"authenticated": False, "message": "Giriş denemesi güvenli şekilde loglandı (parola redakte edildi)."}


@app.get("/logs")
def get_logs():
    # Ekstra güvenlik: dışarı verirken de redaksiyon (log'a hatalı bir yol sızmış olsa bile).
    lines = [redact_text(line) for line in APP_LOG]
    return {"log_lines": lines, "count": len(lines)}
