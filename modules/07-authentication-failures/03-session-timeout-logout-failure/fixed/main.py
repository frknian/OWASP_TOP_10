# CWE-613 (Insufficient Session Expiration) + CWE-287 — FIX.
# İki bağımsız tasarım kontrolü eklendi: (a) gerçek idle timeout (created_at + TTL,
# her istekte kontrol edilir), (b) /logout'un sunucu tarafında session'ı GERÇEKTEN
# silmesi. Lab'da hızlı test için TTL kasıtlı olarak 8 SANİYE (gerçek sistemde
# dakikalar/saatler olur — bkz. report.md).
"""
Modül 07 — Authentication Failures
Senaryo 3: Session Timeout / Logout Kırıklığı (FIXED)

    (a) Idle timeout: her session'a created_at damgası eklenir. /profile her istekte
        `now - created_at > SESSION_TTL_SECONDS` kontrolü yapar; aşılmışsa session
        sunucu tarafında silinir ve 401 döner. TTL = 8 sn (gerçekçi göstermek için
        kısaltıldı; üretimde dakikalar/saatler olur).
    (b) /logout artık GERÇEKTEN session'ı SESSIONS sözlüğünden siler. Sonrasında aynı
        token ile /profile → 401.

Çalıştırma: uvicorn main:app --port 8211
"""
# PORT: 8211
import secrets
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()
password_hasher = PasswordHasher()

SESSION_TTL_SECONDS = 8  # lab amaçlı kısaltıldı; üretimde dakikalar/saatler olur

USERS = {
    "alice": {"password_hash": password_hasher.hash("Tr@ck3r-Alice-99!")},
}

# token -> {"username", "created_at"}
SESSIONS: dict[str, dict] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenRequest(BaseModel):
    session_token: str


def _get_valid_session(token: str) -> str | None:
    """Session varsa VE süresi dolmamışsa username döner; süresi dolmuşsa siler."""
    entry = SESSIONS.get(token)
    if not entry:
        return None
    if time.time() - entry["created_at"] > SESSION_TTL_SECONDS:
        del SESSIONS[token]  # FIX: süresi dolan session sunucu tarafında silinir
        return None
    return entry["username"]


@app.get("/status")
def status():
    return {"status": "up", "scenario": "session-timeout-logout-failure (fixed)"}


@app.post("/login")
def login(req: LoginRequest):
    user = USERS.get(req.username)
    if not user:
        raise HTTPException(status_code=401, detail="Geçersiz kullanıcı adı veya parola")
    try:
        password_hasher.verify(user["password_hash"], req.password)
    except VerifyMismatchError:
        raise HTTPException(status_code=401, detail="Geçersiz kullanıcı adı veya parola")

    token = secrets.token_urlsafe(24)
    SESSIONS[token] = {"username": req.username, "created_at": time.time()}
    return {
        "authenticated": True,
        "session_token": token,
        "session_ttl_seconds": SESSION_TTL_SECONDS,
    }


@app.get("/profile")
def profile(session_token: str):
    # FIX: her istekte idle timeout kontrol edilir.
    username = _get_valid_session(session_token)
    if not username:
        raise HTTPException(status_code=401, detail="Geçersiz veya süresi dolmuş session (idle timeout)")
    return {"username": username, "message": f"Bu session {SESSION_TTL_SECONDS} sn sonra otomatik geçersiz olur."}


@app.post("/logout")
def logout(req: TokenRequest):
    # FIX: session GERÇEKTEN sunucu tarafında silinir. Aynı token bir daha geçerli olmaz.
    existed = SESSIONS.pop(req.session_token, None) is not None
    return {
        "logged_out": True,
        "session_existed": existed,
        "message": "Çıkış yapıldı — session sunucu tarafında silindi, aynı token artık geçersiz.",
    }
