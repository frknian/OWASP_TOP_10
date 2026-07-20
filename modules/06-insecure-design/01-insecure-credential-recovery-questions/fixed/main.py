# CWE-640 (Weak Password Recovery Mechanism) — FIX.
# Dikkat: Bu fix bir "kod yaması" değil, TASARIM DEĞİŞİKLİĞİdir. Güvenlik sorusu
# mekanizması iyileştirilmedi — tamamen KALDIRILDI ve yerine out-of-band, süreli,
# tek kullanımlık token akışı tasarlandı.
"""
Modül 06 — Insecure Design
Senaryo 1: Insecure Credential Recovery / Güvenlik Soruları (FIXED)

Tasarım değişikliği (tek satırlık düzeltme DEĞİL):
    1. "Güvenlik sorusu" diye bir kavram artık YOK. Ne soru saklanıyor, ne cevap
       doğrulanıyor. /security-question endpoint'i tasarımdan kaldırıldı (410 Gone).
    2. /recover-password YALNIZCA {"username"} alır. Fazladan alan gönderilirse
       (örn. security_answer) istek 422 ile reddedilir — eski akış artık kabul edilmiyor.
    3. Kimlik kanıtı, kullanıcının KONTROL ETTİĞİ bir kanala (kayıtlı e-posta) taşındı:
       süreli (15 dk) ve tek kullanımlık bir token üretilir.
    4. Token HTTP yanıtında DÖNMEZ — out-of-band gönderilir (bu simülasyonda sunucu
       konsoluna, yani "e-posta kutusuna" yazılır).
    5. Kullanıcı var olsa da olmasa da AYNI yanıt döner → hesap enumeration'ı önlenir.

Neden bu bir tasarım kararı: "Kimliği nasıl kanıtlarız?" sorusunun cevabı artık
"kullanıcının bildiği bir sır" değil, "kullanıcının SAHİP OLDUĞU bir kanal".

Çalıştırma: uvicorn main:app --port 8161
"""
# PORT: 8161
import secrets
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

app = FastAPI()

TOKEN_TTL_SECONDS = 15 * 60  # süreli: 15 dakika

# Güvenlik sorusu/cevabı ARTIK SAKLANMIYOR — veri modelinden tamamen çıkarıldı.
USERS = {
    "alice": {"email": "alice@example.com", "password": "alice-original-password"},  # nosec B105
    "bob": {"email": "bob@example.com", "password": "bob-original-password"},      # nosec B105
    "carol": {"email": "carol@example.com", "password": "carol-original-password"},  # nosec B105
}

# token -> {"username", "expires_at", "used"}
RESET_TOKENS: dict[str, dict] = {}


class RecoverRequest(BaseModel):
    # extra="forbid": eski akışın alanları (security_answer) artık PROTOKOL düzeyinde
    # reddedilir. Bu, "mekanizma kaldırıldı" kararını API sözleşmesine yazmaktır.
    model_config = ConfigDict(extra="forbid")
    username: str


class ResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reset_token: str
    new_password: str


@app.get("/status")
def status():
    return {"status": "up", "scenario": "insecure-credential-recovery-questions (fixed)"}


@app.get("/security-question")
def security_question_removed(username: str = ""):
    # Bu endpoint TASARIMDAN KALDIRILDI. 410 Gone ile kalıcı kaldırıldığı bildiriliyor.
    raise HTTPException(
        status_code=410,
        detail=(
            "Bu endpoint kaldırıldı. Güvenlik soruları bir kimlik kanıtı olmadığı için "
            "parola kurtarma tasarımından tamamen çıkarılmıştır."
        ),
    )


@app.post("/recover-password")
def recover_password(req: RecoverRequest):
    # TASARIM: Yanıt, kullanıcının var olup olmadığından BAĞIMSIZ olarak aynıdır.
    # Böylece bu endpoint bir "hesap var mı?" oracle'ına dönüşmez.
    generic_response = {
        "message": "Sıfırlama bağlantısı kayıtlı e-posta adresine gönderildi (simülasyon).",
        "delivery": "out-of-band (e-posta) — token HTTP yanıtında DÖNMEZ",
        "token_ttl_minutes": TOKEN_TTL_SECONDS // 60,
        "single_use": True,
    }

    user = USERS.get(req.username)
    if not user:
        # Kullanıcı yok: hiçbir token üretilmez ama yanıt AYNI kalır.
        return generic_response

    token = secrets.token_urlsafe(32)
    RESET_TOKENS[token] = {
        "username": req.username,
        "expires_at": time.time() + TOKEN_TTL_SECONDS,
        "used": False,
    }

    # OUT-OF-BAND TESLİMAT SİMÜLASYONU: gerçek sistemde e-posta gönderilir.
    # Bu labda "e-posta kutusu" = sunucu konsolu. Token bilinçli olarak yanıta konmaz.
    print(
        f"[E-POSTA SİMÜLASYONU] Alıcı: {user['email']} | "
        f"Sıfırlama bağlantısı: https://example.test/reset?token={token} "
        f"(15 dk geçerli, tek kullanımlık)"
    )

    return generic_response


@app.post("/reset-password")
def reset_password(req: ResetRequest):
    entry = RESET_TOKENS.get(req.reset_token)
    if not entry:
        raise HTTPException(status_code=403, detail="Geçersiz veya bilinmeyen token")
    if entry["used"]:
        # Tek kullanımlık: aynı token ikinci kez çalışmaz (replay engeli).
        raise HTTPException(status_code=403, detail="Bu token daha önce kullanıldı")
    if time.time() > entry["expires_at"]:
        raise HTTPException(status_code=403, detail="Token süresi doldu (15 dk)")

    USERS[entry["username"]]["password"] = req.new_password
    entry["used"] = True
    return {
        "reset": True,
        "username": entry["username"],
        "message": "Parola değiştirildi (token tüketildi, tekrar kullanılamaz).",
    }
