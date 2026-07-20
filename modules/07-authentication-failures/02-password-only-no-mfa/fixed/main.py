# CWE-308 (Use of Single-factor Authentication) — FIX.
# Bu bir kod yaması değil, TASARIM değişikliğidir: kimlik doğrulama akışı tek adımdan
# iki adıma çıkarılır. Doğru parola artık "erişim izni" değil, "ikinci faktöre geçiş
# izni" anlamına gelir.
"""
Modül 07 — Authentication Failures
Senaryo 2: Tek Faktör Olarak Parola / MFA Yokluğu (FIXED)

Yeni akış:
    1. POST /login {username, password} → parola doğruysa TAM SESSION verilmez;
       yalnızca geçici bir "pending_token" (5 dk TTL) + 6 haneli OTP üretilir.
    2. OTP gerçek SMS/e-posta ile gönderilmez — bu labda sunucu konsoluna yazılır
       ("MFA SİMÜLASYONU" notuyla). Gerçek sistemde bu adım bir SMS/TOTP/push
       sağlayıcısı olurdu (bkz. report.md).
    3. POST /login/verify-mfa {pending_token, otp_code} → doğru OTP ile TAM session
       verilir. Yanlış OTP veya süresi dolmuş pending_token → 401/403.

Parola doğru olsa da OTP girilmeden hiçbir korumalı kaynağa erişim yoktur.

Çalıştırma: uvicorn main:app --port 8201
"""
# PORT: 8201
import random
import secrets
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()
password_hasher = PasswordHasher()

PENDING_TTL_SECONDS = 5 * 60

USERS = {
    "alice": {"password_hash": password_hasher.hash("Tr@ck3r-Alice-99!")},
    "bob": {"password_hash": password_hasher.hash("B0b-Secure#Pass22")},
}

# pending_token -> {"username", "otp_code", "expires_at"}
PENDING_MFA: dict[str, dict] = {}
# session_token -> username (TAM yetkili — sadece MFA sonrası verilir)
SESSIONS: dict[str, str] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class VerifyMfaRequest(BaseModel):
    pending_token: str
    otp_code: str


@app.get("/status")
def status():
    return {"status": "up", "scenario": "password-only-no-mfa (fixed)"}


@app.post("/login")
def login(req: LoginRequest):
    user = USERS.get(req.username)
    if not user:
        raise HTTPException(status_code=401, detail="Geçersiz kullanıcı adı veya parola")

    try:
        password_hasher.verify(user["password_hash"], req.password)
    except VerifyMismatchError:
        raise HTTPException(status_code=401, detail="Geçersiz kullanıcı adı veya parola")

    # FIX: Parola doğru → yalnızca ikinci faktöre geçiş izni. TAM session HENÜZ verilmez.
    pending_token = secrets.token_urlsafe(24)
    otp_code = f"{random.randint(0, 999999):06d}"  # nosec B311
    PENDING_MFA[pending_token] = {
        "username": req.username,
        "otp_code": otp_code,
        "expires_at": time.time() + PENDING_TTL_SECONDS,
    }

    # MFA SİMÜLASYONU: gerçek sistemde SMS/e-posta/push ile gönderilir. Bu labda
    # sunucu konsoluna yazılır — HTTP yanıtında OTP kodu DÖNMEZ.
    print(f"[MFA SİMÜLASYONU] {req.username} için OTP kodu: {otp_code} (5 dk geçerli)")

    return {
        "authenticated": False,
        "mfa_required": True,
        "pending_token": pending_token,
        "message": "Parola doğru. Devam etmek için OTP kodu gerekli (bkz. sunucu konsolu — simülasyon).",
        "next_step": "POST /login/verify-mfa {pending_token, otp_code}",
    }


@app.post("/login/verify-mfa")
def verify_mfa(req: VerifyMfaRequest):
    entry = PENDING_MFA.get(req.pending_token)
    if not entry:
        raise HTTPException(status_code=403, detail="Geçersiz veya bilinmeyen pending_token")
    if time.time() > entry["expires_at"]:
        del PENDING_MFA[req.pending_token]
        raise HTTPException(status_code=403, detail="OTP süresi doldu (5 dk) — tekrar giriş yapın")
    if req.otp_code != entry["otp_code"]:
        raise HTTPException(status_code=401, detail="Geçersiz OTP kodu")

    # OTP doğru → TAM session verilir. Tek kullanımlık: pending_token tüketilir.
    del PENDING_MFA[req.pending_token]
    session_token = secrets.token_urlsafe(24)
    SESSIONS[session_token] = entry["username"]
    return {
        "authenticated": True,
        "session_token": session_token,
        "message": "MFA doğrulandı — tam erişim verildi (iki faktör: parola + OTP).",
    }


@app.get("/profile")
def profile(session_token: str):
    username = SESSIONS.get(session_token)
    if not username:
        raise HTTPException(status_code=401, detail="Geçersiz veya süresi dolmuş session")
    return {"username": username, "message": "Bu, parola + MFA ile erişilen korumalı profildir."}


@app.get("/lab/otp-inbox")
def lab_otp_inbox(pending_token: str):
    """
    ⚠️ YALNIZCA LAB — GERÇEK SİSTEMDE ASLA BULUNMAZ.

    Kullanıcının SMS/e-posta gelen kutusunu simüle eder. Normalde OTP kodu
    out-of-band bir kanaldan kullanıcıya ulaşır ve bu labda sunucu konsoluna
    yazılır. Ancak control-panel alt süreçleri stdout=DEVNULL ile başlattığından,
    panelden çalıştırıldığında konsol çıktısı okunamaz ve demo çıkmaza girer.
    Bu endpoint yalnızca o boşluğu doldurur.

    ÖNEMLİ: Gösterilen güvenlik özelliğini BOZMAZ — /login yanıtı hâlâ OTP kodunu
    DÖNDÜRMEZ; yalnızca parolayı bilen bir saldırgan login yanıtından ikinci
    faktörü elde edemez. Gerçek sistemde bu endpoint'in yerini kullanıcının kendi
    telefonu/e-posta kutusu alır.
    """
    entry = PENDING_MFA.get(pending_token)
    if not entry:
        raise HTTPException(status_code=404, detail="Bekleyen MFA isteği bulunamadı")
    return {
        "lab_only": True,
        "note": "Gerçek ortamda bu kod SMS/e-posta ile gelirdi — bu uç nokta yalnızca lab simülasyonudur.",
        "otp_code": entry["otp_code"],
    }
