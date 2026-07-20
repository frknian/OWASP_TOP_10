# DEFANGED SIMULATION — no real malicious behavior, for educational demonstration only
"""
Modül 03 — Software Supply Chain Failures
Senaryo 2: Conditional Backdoor / Bybit tarzı (FIXED)

Remediation: Uygulama kodu değişmedi — düzeltme, backdoor'un tespit edilip kaldırıldığı
TEMİZ/İMZASI DOĞRULANMIŞ `wallet_helper` sürümüne geçmektir (dependency review +
imza & provenance doğrulama + sürüm pinleme). Aynı tetikleyici alıcı artık hiçbir
gizli davranışa yol açmaz.

Çalıştırma: uvicorn main:app --port 8061
"""
# PORT: 8061
from fastapi import FastAPI
from pydantic import BaseModel

import wallet_helper

app = FastAPI()


class Transfer(BaseModel):
    recipient: str
    amount: float


@app.get("/status")
def status():
    return {"status": "up", "signer": "wallet_helper", "signer_version": wallet_helper.__version__}


@app.post("/transfer")
def transfer(tx: Transfer):
    result = wallet_helper.process_transaction(tx.model_dump())
    return result
