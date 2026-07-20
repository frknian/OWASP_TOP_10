# CWE-613 (Insufficient Session Expiration) + CWE-287 (Improper Authentication):
# session'lar süresiz geçerlidir ve /logout endpoint'i sunucu tarafında session'ı
# GERÇEKTEN geçersiz kılmaz.
"""
Modül 07 — Authentication Failures
Senaryo 3: Session Timeout / Logout Kırıklığı (VULNERABLE)

İki bağımsız zafiyet:
    (a) Idle timeout YOK: session oluşturulduktan sonra süresiz geçerlidir. Kullanıcı
        saatlerce/günlerce hiçbir işlem yapmasa da aynı cookie ile /profile erişilebilir.
    (b) /logout endpoint'i VAR ama İŞLEMİYOR: yalnızca bir "ok" yanıtı döner; session'ı
        sunucu tarafında SİLMEZ. Bu, "kullanıcı sekmeyi kapatıp gitti" senaryosunu
        simüle eder — arayüzde çıkış yapılmış GİBİ görünür, ama eski cookie/token'la
        istek atan biri (paylaşımlı bilgisayar, çalınmış cookie, XSS ile sızdırılmış
        token) hâlâ tam erişim elde eder.

Çalıştırma: uvicorn main:app --port 8210
"""
# PORT: 8210
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()
password_hasher = PasswordHasher()

USERS = {
    "alice": {"password_hash": password_hasher.hash("Tr@ck3r-Alice-99!")},
}

# token -> username. Not: created_at/expiry alanı YOK — süresiz geçerli.
SESSIONS: dict[str, str] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenRequest(BaseModel):
    session_token: str


@app.get("/status")
def status():
    return {"status": "up", "scenario": "session-timeout-logout-failure"}


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
    SESSIONS[token] = req.username  # ZAFIYET: created_at/expiry yok — süresiz geçerli
    return {"authenticated": True, "session_token": token}


@app.get("/profile")
def profile(session_token: str):
    # ZAFIYET: idle timeout kontrolü yok — token var olduğu sürece (logout dahil
    # hiçbir şey silmediği için sonsuza kadar) geçerli.
    username = SESSIONS.get(session_token)
    if not username:
        raise HTTPException(status_code=401, detail="Geçersiz session")
    return {"username": username, "message": "Bu session hiç zaman aşımına uğramaz."}


@app.post("/logout")
def logout(req: TokenRequest):
    # ZAFIYET: endpoint VAR ama session'ı sunucu tarafında SİLMİYOR. Yalnızca
    # "başarılı" görünümü veriyor — istemci cookie'yi silse de eski token hâlâ geçerli.
    return {
        "logged_out": True,
        "message": "Çıkış yapıldı (görünüşte) — ancak session sunucuda hâlâ geçerli.",
    }
