# DEFANGED SIMULATION — no real malicious behavior, for educational demonstration only
"""
Modül 03 — Software Supply Chain Failures
Senaryo 1: Vulnerable Component / Log4Shell tarzı (FIXED)

Remediation: Uygulama kodu neredeyse aynı — `POST /log` yine kullanıcının mesajını
logger'a geçirir. Fark, ARTIK GÜVENLİ SÜRÜME (2.0.0-fixed) yükseltilmiş `vulnerable_logger`
kullanılmasıdır; bu sürüm `${...}` ifadelerini yorumlamaz. Yani düzeltme uygulama
mantığında değil, ZAFİYETLİ BİLEŞENİN GÜVENLİ SÜRÜME PİNLENMESİNDE (supply chain
remediation) gerçekleşir.

Çalıştırma: uvicorn main:app --port 8051
"""
# PORT: 8051
from fastapi import FastAPI
from pydantic import BaseModel

import vulnerable_logger

app = FastAPI()


class LogEntry(BaseModel):
    message: str


@app.get("/status")
def status():
    return {"status": "up", "logger": "vulnerable_logger", "logger_version": vulnerable_logger.__version__}


@app.post("/log")
def write_log(entry: LogEntry):
    # Aynı çağrı; ama logger'ın güvenli sürümü girdiyi düz string olarak işler.
    logged_line = vulnerable_logger.log(entry.message)
    return {"logged": logged_line}
