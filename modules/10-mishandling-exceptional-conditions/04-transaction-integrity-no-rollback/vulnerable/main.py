# CWE-460 (Improper Cleanup on Thrown Exception): çok adımlı bir işlemin ortasında istisna
# oluştuğunda, önceki adımların yaptığı değişiklikler GERİ ALINMAZ. Sistem tutarsız duruma
# düşer — ACID'in "Atomicity" (ya hep ya hiç) ilkesi ihlal edilir.
"""
Modül 10 — Mishandling of Exceptional Conditions
Senaryo 4: İşlem Bütünlüğü — Rollback Eksikliği (VULNERABLE)

Bağlam: `POST /transfer` iki hesap arasında para transferi yapar. İşlem üç adımlıdır:
    1. Gönderenin bakiyesi düşürülür.
    2. Alıcı hesap doğrulanır  ← BİLİNÇLİ HATA NOKTASI (geçersiz hesapta istisna)
    3. Alıcının bakiyesi artırılır.

Zafiyet: Adım 1 başarıyla uygulandıktan sonra adım 2'de istisna oluşursa, adım 1 GERİ
ALINMAZ. Gönderenin parası düşer ama alıcıya hiç ulaşmaz — para sistemden "kaybolur" ve
toplam bakiye azalır (tutarsız durum).

Çalıştırma: uvicorn main:app --port 8310
"""
# PORT: 8310
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

INITIAL_BALANCES = {"alice": 1000.0, "bob": 500.0}
ACCOUNTS: dict[str, float] = dict(INITIAL_BALANCES)


class TransferRequest(BaseModel):
    from_account: str
    to_account: str
    amount: float


@app.get("/status")
def status():
    return {"status": "up", "scenario": "transaction-integrity-no-rollback"}


@app.get("/balance/{account}")
def balance(account: str):
    if account not in ACCOUNTS:
        raise HTTPException(status_code=404, detail="Hesap bulunamadı")
    return {"account": account, "balance": ACCOUNTS[account]}


@app.get("/total")
def total():
    """Sistemdeki toplam para — tutarlılık kontrolü için."""
    return {
        "total_balance": sum(ACCOUNTS.values()),
        "expected_total": sum(INITIAL_BALANCES.values()),
        "consistent": sum(ACCOUNTS.values()) == sum(INITIAL_BALANCES.values()),
        "balances": ACCOUNTS,
    }


@app.post("/transfer")
def transfer(req: TransferRequest):
    if req.from_account not in ACCOUNTS:
        raise HTTPException(status_code=404, detail="Gönderen hesap bulunamadı")
    if ACCOUNTS[req.from_account] < req.amount:
        raise HTTPException(status_code=400, detail="Yetersiz bakiye")

    # --- ADIM 1: gönderenin bakiyesini düşür (uygulandı) ---
    ACCOUNTS[req.from_account] -= req.amount

    # --- ADIM 2: alıcıyı doğrula (BİLİNÇLİ HATA NOKTASI) ---
    if req.to_account not in ACCOUNTS:
        # ZAFIYET: burada istisna fırlıyor ama ADIM 1 GERİ ALINMIYOR.
        # try/except/rollback yok → para gönderenden düştü, alıcıya ulaşmadı, kayboldu.
        raise HTTPException(status_code=404, detail=f"Alıcı hesap bulunamadı: {req.to_account}")

    # --- ADIM 3: alıcının bakiyesini artır ---
    ACCOUNTS[req.to_account] += req.amount

    return {"transferred": True, "from": req.from_account, "to": req.to_account, "amount": req.amount}


@app.post("/reset")
def reset():
    # Lab kolaylığı: bakiyeleri başlangıç değerlerine döndürür.
    ACCOUNTS.clear()
    ACCOUNTS.update(INITIAL_BALANCES)
    return {"reset": True, "balances": ACCOUNTS}
