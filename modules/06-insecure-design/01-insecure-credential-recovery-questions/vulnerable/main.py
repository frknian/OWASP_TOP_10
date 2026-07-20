# CWE-640 (Weak Password Recovery Mechanism for Forgotten Password): parola kurtarma,
# kimlik KANITI yerine "gizli soru cevabı" gibi paylaşılabilir/tahmin edilebilir bir
# sırra dayandırılır. Bu bir kodlama hatası değil, TASARIM (Insecure Design) kusurudur.
"""
Modül 06 — Insecure Design
Senaryo 1: Insecure Credential Recovery / Güvenlik Soruları (VULNERABLE)

Zafiyet: Parola sıfırlama akışı, kullanıcının önceden kaydettiği "güvenlik sorusu"
cevabına dayanır (örn. "Annenizin kızlık soyadı nedir?"). Cevap doğruysa sunucu
doğrudan parola sıfırlama izni (reset token) verir.

Kusurun TASARIMSAL doğası: Güvenlik sorusunun cevabı bir kimlik kanıtı DEĞİLDİR —
    * Aile üyeleri, arkadaşlar ve eski partnerler cevabı zaten bilir.
    * Sosyal medya/OSINT ile bulunabilir.
    * Cevap kümesi küçüktür (yaygın soyadlar, doğum şehirleri) → tahmin edilebilir.
    * Kullanıcı cevabı değiştiremez (annenizin kızlık soyadı asla "rotate" edilemez).
Bu yüzden kusur, "daha güçlü cevap doğrulaması" ile DÜZELTİLEMEZ; mekanizmanın
kendisi terk edilmelidir (bkz. fixed/main.py).

Çalıştırma: uvicorn main:app --port 8160
"""
# PORT: 8160
import secrets

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

# Seed kullanıcılar. Cevaplar bilinçli olarak GERÇEKÇİ derecede tahmin edilebilir:
# Türkiye'nin en yaygın soyadları / büyük şehirleri. Saldırgan için arama uzayı çok küçük.
USERS = {
    "alice": {
        "email": "alice@example.com",
        "password": "alice-original-password",
        "question": "Annenizin kızlık soyadı nedir?",
        "answer": "yilmaz",  # Türkiye'nin en yaygın soyadı
    },
    "bob": {
        "email": "bob@example.com",
        "password": "bob-original-password",
        "question": "Doğduğunuz şehir neresi?",
        "answer": "istanbul",  # en kalabalık şehir
    },
    "carol": {
        "email": "carol@example.com",
        "password": "carol-original-password",
        "question": "İlk evcil hayvanınızın adı neydi?",
        "answer": "boncuk",  # Türkiye'de çok yaygın evcil hayvan adı
    },
}

# Verilen parola sıfırlama izinleri (token -> username)
RESET_TOKENS: dict[str, str] = {}


class RecoverRequest(BaseModel):
    username: str
    security_answer: str


class ResetRequest(BaseModel):
    username: str
    reset_token: str
    new_password: str


@app.get("/status")
def status():
    return {"status": "up", "scenario": "insecure-credential-recovery-questions"}


@app.get("/security-question")
def security_question(username: str):
    # ZAFIYET (tasarım): Soru, kimlik doğrulaması OLMADAN herkese açıklanıyor.
    # Saldırgan hedefin hangi soruyla korunduğunu öğrenip cevabı araştırabilir/tahmin
    # edebilir. Ayrıca kullanıcının var olup olmadığını da sızdırır (enumeration).
    user = USERS.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
    return {"username": username, "question": user["question"]}


@app.post("/recover-password")
def recover_password(req: RecoverRequest):
    # ZAFIYET (tasarım): Kimlik kanıtı olarak yalnızca "gizli soru cevabı" isteniyor.
    # Cevap doğruysa saldırgan hesabı devralabilecek reset token'ı DOĞRUDAN yanıtta alır.
    # Ek olarak: deneme sayısı sınırı yok → kalan tahmin belirsizliği de brute-force ile eriyor.
    user = USERS.get(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")

    if req.security_answer.strip().lower() != user["answer"]:
        # Not: rate limit / deneme sayacı YOK — saldırgan sınırsız deneyebilir.
        raise HTTPException(status_code=403, detail="Güvenlik sorusu cevabı hatalı")

    token = secrets.token_urlsafe(16)
    RESET_TOKENS[token] = req.username
    return {
        "allowed": True,
        "message": "Güvenlik sorusu doğrulandı — parolanızı sıfırlayabilirsiniz.",
        "reset_token": token,  # ZAFIYET: token, kanıtlanmamış kimliğe anında veriliyor
        "next_step": "POST /reset-password {username, reset_token, new_password}",
    }


@app.post("/reset-password")
def reset_password(req: ResetRequest):
    # Token geçerliyse parola değişir → hesap devralma tamamlanır.
    owner = RESET_TOKENS.get(req.reset_token)
    if owner != req.username:
        raise HTTPException(status_code=403, detail="Geçersiz reset token")

    USERS[req.username]["password"] = req.new_password
    del RESET_TOKENS[req.reset_token]
    return {
        "reset": True,
        "username": req.username,
        "message": "Parola değiştirildi — hesap artık yeni parolayla erişilebilir.",
        "current_password": req.new_password,  # lab görünürlüğü: devralma kanıtı
    }
