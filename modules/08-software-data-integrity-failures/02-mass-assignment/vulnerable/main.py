# CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object
# Attributes / Mass Assignment): gelen istek gövdesi, hangi alanların
# güncellenebileceği KISITLANMADAN doğrudan kullanıcı objesine yazılır. Saldırgan,
# istemcinin normalde göremediği ayrıcalık alanlarını (role) gövdeye ekleyerek set eder.
"""
Modül 08 — Software or Data Integrity Failures
Senaryo 2: Mass Assignment (VULNERABLE)

Zafiyet: `PATCH /profile/update`, gelen JSON'daki TÜM alanları (role dahil) kabul eden
bir Pydantic modeliyle çözer ve her alanı doğrudan DB kaydına yazar. Kullanıcı yalnızca
email/bio güncellemesi beklenirken, `{"bio": "...", "role": "admin"}` göndererek kendi
rolünü yükseltir (privilege escalation).

Kök neden bir "trust boundary" ihlalidir: istemciden gelen veri, hangi alanların
değiştirilebileceğine dair sunucu tarafı bir allowlist olmadan objeye bind edilir.

Çalıştırma: uvicorn main:app --port 8230
"""
# PORT: 8230
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Basit in-memory "users tablosu".
USERS: dict[int, dict] = {}
CURRENT_USER_ID = 1  # bu demoda tek oturum: id=1 kullanıcısı "giriş yapmış" varsayılır


def seed():
    USERS.clear()
    USERS[1] = {
        "id": 1,
        "username": "alice",
        "email": "alice@example.com",
        "bio": "Merhaba, ben Alice.",
        "role": "user",  # varsayılan
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    seed()
    yield


app = FastAPI(lifespan=lifespan)


class ProfileUpdate(BaseModel):
    # ZAFIYET: model TÜM alanları kabul eder — role dahil. İstemci hangi alanı
    # gönderirse o güncellenir. (Alanlar opsiyonel; yalnızca gönderilenler yazılır.)
    username: str | None = None
    email: str | None = None
    bio: str | None = None
    role: str | None = None  # ← ayrıcalık alanı; istemciye ASLA açılmamalıydı


@app.get("/status")
def status():
    return {"status": "up", "scenario": "mass-assignment"}


@app.get("/profile")
def get_profile():
    return USERS[CURRENT_USER_ID]


@app.patch("/profile/update")
def update_profile(update: ProfileUpdate):
    user = USERS.get(CURRENT_USER_ID)
    if not user:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")

    # ZAFIYET: gelen gövde doğrudan objeye bind ediliyor. exclude_unset ile yalnızca
    # gönderilen alanlar yazılır — ama role de "gönderilebilir" alanlardan biri olduğu
    # için saldırgan onu set edebilir. Sunucu tarafı bir allowlist YOK.
    changes = update.model_dump(exclude_unset=True)
    user.update(changes)

    return {
        "updated": True,
        "applied_fields": list(changes.keys()),
        "profile": user,
        "note": "Gelen tüm alanlar (role dahil) doğrudan yazıldı — mass assignment.",
    }
