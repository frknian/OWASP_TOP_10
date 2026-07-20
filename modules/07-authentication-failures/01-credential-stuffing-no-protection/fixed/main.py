# CWE-307 (Improper Restriction of Excessive Authentication Attempts) — FIX.
# Hashing zaten doğruydu (argon2id); eklenen şey deneme sayısını/hızını sınırlayan bir
# TASARIM kontrolüdür: kullanıcı bazlı başarısız deneme sayacı + geçici kilitleme.
"""
Modül 07 — Authentication Failures
Senaryo 1: Credential Stuffing / Brute-Force Koruması Yok (FIXED)

Eklenen kontrol: her kullanıcı adı için başarısız deneme sayısı in-memory tutulur.
5 başarısız denemeden sonra hesap 30 saniye geçici olarak kilitlenir (429 + Retry-After).
Kilitliyken doğru parola gönderilse bile giriş reddedilir — bu bilinçli bir tasarım
kararıdır: kilitleme penceresi doğru parolayı da geçersiz kılar, çünkü saldırgan doğru
parolayı 6. denemede bulmuş olabilir ve bu, kilitleme mekanizmasının varlığını
saldırgana hemen ifşa etmemelidir.

Başarılı girişte sayaç sıfırlanır (meşru kullanıcı arada bir yanlış yazarsa cezalanmaz).

Çalıştırma: uvicorn main:app --port 8191
"""
# PORT: 8191
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()
password_hasher = PasswordHasher()

MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 30

USERS = {
    "alice": {"password_hash": password_hasher.hash("Tr@ck3r-Alice-99!")},
    "bob": {"password_hash": password_hasher.hash("B0b-Secure#Pass22")},
    "carol": {"password_hash": password_hasher.hash("Password1")},
}

# username -> {"failed_count": int, "locked_until": float | None}
ATTEMPTS: dict[str, dict] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/status")
def status():
    return {"status": "up", "scenario": "credential-stuffing-no-protection (fixed)"}


@app.post("/login")
def login(req: LoginRequest):
    entry = ATTEMPTS.setdefault(req.username, {"failed_count": 0, "locked_until": None})

    # Kilitliyken hiçbir parola kontrolü yapılmaz — doğru olsa bile reddedilir.
    if entry["locked_until"] and time.time() < entry["locked_until"]:
        retry_after = int(entry["locked_until"] - time.time()) + 1
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Çok fazla başarısız deneme",
                "locked_for_seconds": retry_after,
            },
            headers={"Retry-After": str(retry_after)},
        )

    user = USERS.get(req.username)
    password_ok = False
    if user:
        try:
            password_hasher.verify(user["password_hash"], req.password)
            password_ok = True
        except VerifyMismatchError:
            password_ok = False

    if not password_ok:
        entry["failed_count"] += 1
        if entry["failed_count"] >= MAX_ATTEMPTS:
            entry["locked_until"] = time.time() + LOCKOUT_SECONDS
            entry["failed_count"] = 0  # kilitleme penceresi sonunda sayaç sıfırlanır
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "Çok fazla başarısız deneme — hesap geçici kilitlendi",
                    "locked_for_seconds": LOCKOUT_SECONDS,
                },
                headers={"Retry-After": str(LOCKOUT_SECONDS)},
            )
        raise HTTPException(
            status_code=401,
            detail={
                "error": "Geçersiz kullanıcı adı veya parola",
                "failed_attempts": entry["failed_count"],
                "max_attempts": MAX_ATTEMPTS,
            },
        )

    # Başarılı giriş: sayaç sıfırlanır (meşru kullanıcı arızi yanlış yazımdan cezalanmaz).
    entry["failed_count"] = 0
    entry["locked_until"] = None
    return {
        "authenticated": True,
        "username": req.username,
        "message": "Giriş başarılı.",
    }


@app.post("/reset")
def reset():
    # Lab kolaylığı: deneme sayaçlarını sıfırlar. Gerçek sistemde bulunmaz.
    ATTEMPTS.clear()
    return {"reset": True}
