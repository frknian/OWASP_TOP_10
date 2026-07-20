# CWE-460 (Improper Cleanup on Thrown Exception) — FIX.
# Çok adımlı işlem atomik hale getirilir: herhangi bir adımda istisna oluşursa, o ana kadar
# yapılan TÜM değişiklikler geri alınır (rollback). ACID'in "Atomicity" ilkesi: işlem ya
# tamamen uygulanır ya da hiç uygulanmaz — arada bir durum yoktur.
"""
Modül 10 — Mishandling of Exceptional Conditions
Senaryo 4: İşlem Bütünlüğü — Rollback Eksikliği (FIXED)

Tasarım: İşlem, değişikliklerin bir "snapshot"ı alınarak try/except içinde yürütülür.
Herhangi bir adımda istisna fırlarsa `except` bloğu snapshot'ı geri yükler (rollback) ve
istisnayı yeniden yükseltir. Böylece:
    * Başarılı yol: tüm adımlar uygulanır (commit).
    * Hatalı yol: hiçbir adım kalıcı olmaz (rollback) → toplam bakiye korunur.

Gerçek bir veritabanında bunun karşılığı `BEGIN ... COMMIT/ROLLBACK` bloğudur; burada
in-memory state üzerinde aynı semantik elle uygulanmıştır.

Çalıştırma: uvicorn main:app --port 8311
"""
# PORT: 8311
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
    return {"status": "up", "scenario": "transaction-integrity-no-rollback (fixed)"}


@app.get("/balance/{account}")
def balance(account: str):
    if account not in ACCOUNTS:
        raise HTTPException(status_code=404, detail="Hesap bulunamadı")
    return {"account": account, "balance": ACCOUNTS[account]}


@app.get("/total")
def total():
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

    # FIX: işlem öncesi snapshot (BEGIN TRANSACTION karşılığı)
    snapshot = dict(ACCOUNTS)

    try:
        # --- ADIM 1: gönderenin bakiyesini düşür ---
        ACCOUNTS[req.from_account] -= req.amount

        # --- ADIM 2: alıcıyı doğrula (vulnerable ile AYNI hata noktası) ---
        if req.to_account not in ACCOUNTS:
            raise HTTPException(status_code=404, detail=f"Alıcı hesap bulunamadı: {req.to_account}")

        # --- ADIM 3: alıcının bakiyesini artır ---
        ACCOUNTS[req.to_account] += req.amount

    except Exception:
        # FIX: ROLLBACK — herhangi bir adımda hata olursa tüm değişiklikler geri alınır.
        ACCOUNTS.clear()
        ACCOUNTS.update(snapshot)
        raise  # istisna yeniden yükseltilir (istemci doğru hata kodunu alır)

    # Buraya yalnızca tüm adımlar başarılıysa ulaşılır (COMMIT karşılığı).
    return {"transferred": True, "from": req.from_account, "to": req.to_account, "amount": req.amount}


@app.post("/reset")
def reset():
    ACCOUNTS.clear()
    ACCOUNTS.update(INITIAL_BALANCES)
    return {"reset": True, "balances": ACCOUNTS}
