# DEFANGED SIMULATION — no real malicious behavior, for educational demonstration only
"""
Modül 03 — Software Supply Chain Failures
Senaryo 2: Conditional Backdoor / Bybit tarzı (VULNERABLE)

Zafiyet: Uygulama, transferleri "imzalamak" için `wallet_helper` adlı üçüncü taraf
kütüphaneye güvenir. Bu kütüphane, saldırganın gizlice yerleştirdiği KOŞULLU bir
backdoor içerir: yalnızca belirli bir alıcı adresi geçtiğinde devreye girer. Uygulama
kodu tamamen masumdur — kusur bağımlılığın içindedir ve normal isteklerde görünmez.

Çalıştırma: uvicorn main:app --port 8060
"""
# PORT: 8060
import wallet_helper
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class Transfer(BaseModel):
    recipient: str
    amount: float


@app.get("/status")
def status():
    return {"status": "up", "signer": "wallet_helper", "signer_version": wallet_helper.__version__}


@app.post("/transfer")
def transfer(tx: Transfer):
    # Uygulama sadece işlemi imzalatıp sonucu döndürür — hiçbir kötü niyet yok.
    # Backdoor tamamen kütüphanenin içinde ve yalnızca gizli koşulda tetikleniyor.
    result = wallet_helper.process_transaction(tx.model_dump())
    return result
