# CWE-915 (Mass Assignment) — FIX.
# Güncellenebilir alanlar sunucu tarafında AÇIK bir allowlist ile sınırlanır: ayrı bir
# DTO yalnızca email + bio içerir ve extra="forbid" ile beklenmeyen alan (role) reddedilir.
# role alanı istemci girdisine hiçbir yolla bağlanmaz.
"""
Modül 08 — Software or Data Integrity Failures
Senaryo 2: Mass Assignment (FIXED)

Tasarım: "hangi alanlar istemci tarafından güncellenebilir?" sorusu sunucu tarafında,
açık bir allowlist ile yanıtlanır. ProfileUpdateRequest DTO'su SADECE email ve bio
alanlarını tanır. role gibi ayrıcalık alanları bu sözleşmenin dışındadır; gönderilmeye
çalışılırsa (extra="forbid") istek 422 ile reddedilir ve hiçbir değişiklik yazılmaz.

Kritik nokta: Vulnerable ile aynı DB modeli kullanılır (role hâlâ var), değişen şey
istemci girdisiyle DB modeli arasındaki SÖZLEŞMEdir — trust boundary'nin doğru çizilmesi.

Çalıştırma: uvicorn main:app --port 8231
"""
# PORT: 8231
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

USERS: dict[int, dict] = {}
CURRENT_USER_ID = 1


def seed():
    USERS.clear()
    USERS[1] = {
        "id": 1,
        "username": "alice",
        "email": "alice@example.com",
        "bio": "Merhaba, ben Alice.",
        "role": "user",
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    seed()
    yield


app = FastAPI(lifespan=lifespan)


class ProfileUpdateRequest(BaseModel):
    # FIX: ALLOWLIST DTO — yalnızca istemcinin değiştirmesine izin verilen alanlar.
    # extra="forbid" → sözleşme dışı bir alan (role, username, id...) gelirse 422.
    model_config = ConfigDict(extra="forbid")
    email: str | None = None
    bio: str | None = None


@app.get("/status")
def status():
    return {"status": "up", "scenario": "mass-assignment (fixed)"}


@app.get("/profile")
def get_profile():
    return USERS[CURRENT_USER_ID]


@app.patch("/profile/update")
def update_profile(update: ProfileUpdateRequest):
    user = USERS.get(CURRENT_USER_ID)
    if not user:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")

    # FIX: yalnızca DTO'daki (allowlist) alanlardan gönderilenler yazılır. role burada
    # yok — istemci girdisine hiçbir şekilde bağlanamaz.
    changes = update.model_dump(exclude_unset=True)
    user.update(changes)

    return {
        "updated": True,
        "applied_fields": list(changes.keys()),
        "profile": user,
        "note": "Yalnızca allowlist alanları (email, bio) yazıldı; role istemciye kapalı.",
    }
