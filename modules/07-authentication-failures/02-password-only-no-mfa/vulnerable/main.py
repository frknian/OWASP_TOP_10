# CWE-308 (Use of Single-factor Authentication): kimlik doğrulama tamamen tek bir
# faktöre (parola) dayanır. Parola sızarsa/tahmin edilirse/phishing ile çalınırsa,
# saldırgan hiçbir ek engelle karşılaşmadan hesaba tam erişim kazanır.
"""
Modül 07 — Authentication Failures
Senaryo 2: Tek Faktör Olarak Parola / MFA Yokluğu (VULNERABLE)

Zafiyet: `POST /login` doğru parola girilince DOĞRUDAN tam erişim (session) verir.
Parola tek başına yeterlidir — başka hiçbir doğrulama katmanı yoktur.

Bu, parolanın (data breach, phishing, credential stuffing, keylogger, shoulder
surfing...) herhangi bir yolla ele geçirilmesinin doğrudan hesap devralmaya
dönüştüğü anlamına gelir. NIST 800-63B artık parola karmaşıklığı/rotasyon
zorunluluğunu değil, MFA'yı asıl savunma katmanı olarak önerir (bkz. report.md).

Çalıştırma: uvicorn main:app --port 8200
"""
# PORT: 8200
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()
password_hasher = PasswordHasher()

USERS = {
    "alice": {"password_hash": password_hasher.hash("Tr@ck3r-Alice-99!")},
    "bob": {"password_hash": password_hasher.hash("B0b-Secure#Pass22")},
}

# token -> username (tam yetkili session)
SESSIONS: dict[str, str] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/status")
def status():
    return {"status": "up", "scenario": "password-only-no-mfa"}


@app.post("/login")
def login(req: LoginRequest):
    user = USERS.get(req.username)
    if not user:
        raise HTTPException(status_code=401, detail="Geçersiz kullanıcı adı veya parola")

    try:
        password_hasher.verify(user["password_hash"], req.password)
    except VerifyMismatchError:
        raise HTTPException(status_code=401, detail="Geçersiz kullanıcı adı veya parola")

    # ZAFIYET: doğru parola = DOĞRUDAN tam erişim. İkinci bir doğrulama katmanı yok.
    token = secrets.token_urlsafe(24)
    SESSIONS[token] = req.username
    return {
        "authenticated": True,
        "mfa_required": False,
        "session_token": token,
        "message": "Giriş başarılı — tam erişim verildi (tek faktör: parola).",
    }


@app.get("/profile")
def profile(session_token: str):
    username = SESSIONS.get(session_token)
    if not username:
        raise HTTPException(status_code=401, detail="Geçersiz veya süresi dolmuş session")
    return {"username": username, "message": "Bu, parola tek başına ile erişilen korumalı profildir."}
