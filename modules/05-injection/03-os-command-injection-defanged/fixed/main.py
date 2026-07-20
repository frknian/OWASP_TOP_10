# DEFANGED SIMULATION — no real shell execution, for educational demonstration only
# FIX (CWE-78): girdi strict allowlist regex ile doğrulanır; komut string'i kurulmaz.
"""
Modül 05 — Injection
Senaryo 3: OS Command Injection (FIXED, DEFANGED)

Remediation: `domain` girdisi, kabuğa ulaşmadan ÖNCE katı bir allowlist regex'iyle
(^[a-zA-Z0-9.-]+$) doğrulanır. Uymayan girdi (metakarakter, boşluk vb.) 400 ile reddedilir
ve komut string'i hiç oluşturulmaz. Böylece `example.com; cat /etc/passwd` gibi bir payload
daha ilk adımda düşer.

Not: DEFANGED — doğrulanan girdi için bile gerçek komut çalıştırılmaz. Gerçek dünyada ek
olarak subprocess argüman listesi (shell=False) kullanılmalıdır; validation ilk savunma hattıdır.

Çalıştırma: uvicorn main:app --port 8141
"""
# PORT: 8141
import re

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

# Allowlist: yalnızca harf, rakam, nokta ve tire. Kabuk metakarakteri (; | & $ boşluk...) yok.
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.-]+$")


class DiagnoseRequest(BaseModel):
    domain: str


@app.get("/status")
def status():
    return {"status": "up", "scenario": "os-command-injection-fixed"}


@app.post("/diagnose")
def diagnose(req: DiagnoseRequest):
    # FIX: Strict allowlist doğrulaması. Uymayan girdi hiç işlenmeden 400 döner.
    if not _DOMAIN_RE.match(req.domain):
        raise HTTPException(status_code=400, detail="Geçersiz domain: yalnızca [a-zA-Z0-9.-] izinli")
    # Doğrulanmış girdi için bile (defanged) komut kurulmuyor; validation ilk savunma hattı.
    return {
        "safe": f"[GÜVENLİ] Doğrulanmış domain: {req.domain}, komut hiç oluşturulmadı.",
        "note": "Metakarakter içeren girdiler 400 ile reddedilir; kabuğa hiçbir şey ulaşmaz.",
    }
