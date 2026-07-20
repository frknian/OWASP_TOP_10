# CWE-307 (Improper Restriction of Excessive Authentication Attempts): login
# endpoint'i deneme sayısını, hızını veya kaynağını hiç sınırlamaz. Hashing'in kendisi
# (argon2id) doğrudur — kusur hashing'de değil, brute-force korumasının YOKLUĞUNDADIR.
"""
Modül 07 — Authentication Failures
Senaryo 1: Credential Stuffing / Brute-Force Koruması Yok (VULNERABLE)

Zafiyet: `POST /login` username+password alır, argon2id ile doğru şekilde karşılaştırır
(hashing kusuru YOK). Ama hiçbir deneme limiti, gecikme veya kilitleme mekanizması
olmadığından, saldırgan tek bir kullanıcıya karşı saniyeler içinde onlarca/yüzlerce
parola deneyebilir (credential stuffing / password spraying).

Seed kullanıcılardan biri (carol) yaygın/zayıf bir parola kullanır — bu, gerçek dünyada
kullanıcıların büyük bir kısmının "Top 20 password" listelerinden birini seçtiği
gerçeğini yansıtır. Hashing doğru olsa da, sınırsız deneme hakkı bu zayıflığı
kaçınılmaz kılar.

Çalıştırma: uvicorn main:app --port 8190
"""
# PORT: 8190

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()
password_hasher = PasswordHasher()

# Seed kullanıcılar — hashing doğru (argon2id), kusur burada değil.
# carol bilinçli olarak yaygın/zayıf bir parola kullanıyor (gerçek kullanıcı davranışı).
USERS = {
    "alice": {"password_hash": password_hasher.hash("Tr@ck3r-Alice-99!")},
    "bob": {"password_hash": password_hasher.hash("B0b-Secure#Pass22")},
    "carol": {"password_hash": password_hasher.hash("Password1")},  # yaygın/zayıf parola
}


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/status")
def status():
    return {"status": "up", "scenario": "credential-stuffing-no-protection"}


@app.post("/login")
def login(req: LoginRequest):
    # ZAFIYET: deneme sayacı, gecikme veya kilitleme YOK. Hashing doğru olsa da
    # (argon2id), saldırgan aynı kullanıcıya karşı sınırsız sayıda parola deneyebilir.
    user = USERS.get(req.username)
    if not user:
        raise HTTPException(status_code=401, detail="Geçersiz kullanıcı adı veya parola")

    try:
        password_hasher.verify(user["password_hash"], req.password)
    except VerifyMismatchError:
        raise HTTPException(status_code=401, detail="Geçersiz kullanıcı adı veya parola")

    return {
        "authenticated": True,
        "username": req.username,
        "message": "Giriş başarılı.",
    }
