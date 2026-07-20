# CWE-502 (Deserialization of Untrusted Data) — FIX.
# Pickle TAMAMEN terk edildi. İki bağımsız kontrol birlikte uygulanır:
#   (1) JSON + katı şema doğrulaması → "format doğru mu?" sorusunu çözer.
#   (2) HMAC imza doğrulaması (server-side secret) → "veri sunucudan mı geldi / değişti mi?"
#       sorusunu çözer.
"""
Modül 08 — Software or Data Integrity Failures
Senaryo 1: Insecure Deserialization (FIXED)

Neden iki kontrol birden:
    * Şema doğrulaması TEK BAŞINA yetmez: geçerli formatta ama saldırganın elle
      değiştirdiği bir state (örn. theme'i değiştirmiş) yine kabul edilirdi. Şema
      "format doğru mu?" der, "bu veri gerçekten sunucudan mı geldi?" demez.
    * HMAC TEK BAŞINA yetmez: imza sadece bütünlüğü kanıtlar; imzalı ama bozuk/beklenmeyen
      bir yapı yine de işlenebilirdi. HMAC "değişti mi?" der, "yapı doğru mu?" demez.
    * İkisi birlikte: veri hem SUNUCUDAN gelmiş (HMAC) hem BEKLENEN yapıda (şema) olmalı.

Pickle hiç kullanılmaz → CWE-502'nin kök nedeni (keyfi obje deserialize etme) ortadan kalkar.

Çalıştırma: uvicorn main:app --port 8221
"""
# PORT: 8221
import base64
import hashlib
import hmac
import json

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ValidationError, field_validator

app = FastAPI()

# Server-side secret — imzalama/doğrulama için. Gerçek sistemde env/secret manager'dan gelir.
_HMAC_SECRET = b"module08-s1-server-side-signing-secret"

DEFAULT_STATE = {"theme": "dark", "language": "tr", "sidebar": "expanded"}
ALLOWED_THEMES = {"dark", "light"}
ALLOWED_LANGUAGES = {"tr", "en"}
ALLOWED_SIDEBAR = {"expanded", "collapsed"}


class StateSchema(BaseModel):
    # KATI ŞEMA: yalnızca beklenen alanlar + tipler + değer allowlist'i.
    model_config = {"extra": "forbid"}  # beklenmeyen alan → 422/hata
    theme: str
    language: str
    sidebar: str

    @field_validator("theme")
    @classmethod
    def _theme(cls, v):
        if v not in ALLOWED_THEMES:
            raise ValueError("theme yalnızca dark|light olabilir")
        return v

    @field_validator("language")
    @classmethod
    def _lang(cls, v):
        if v not in ALLOWED_LANGUAGES:
            raise ValueError("language yalnızca tr|en olabilir")
        return v

    @field_validator("sidebar")
    @classmethod
    def _sidebar(cls, v):
        if v not in ALLOWED_SIDEBAR:
            raise ValueError("sidebar yalnızca expanded|collapsed olabilir")
        return v


class RestoreRequest(BaseModel):
    state: str  # JSON string
    signature: str = ""  # HMAC-SHA256 imzası (hex)


def _sign(payload: str) -> str:
    return hmac.new(_HMAC_SECRET, payload.encode(), hashlib.sha256).hexdigest()


@app.get("/status")
def status():
    return {"status": "up", "scenario": "insecure-deserialization-defanged (fixed)"}


@app.get("/get-state")
def get_state():
    # FIX: state JSON olarak serialize edilir VE HMAC ile imzalanır.
    payload = json.dumps(DEFAULT_STATE, sort_keys=True, separators=(",", ":"))
    return {
        "state": payload,
        "signature": _sign(payload),
        "note": "state + signature'ı POST /restore-state ile geri gönderin.",
    }


@app.post("/restore-state")
def restore_state(req: RestoreRequest):
    # KONTROL 1 — HMAC: veri sunucudan mı geldi / değişti mi?
    # constant-time karşılaştırma (timing attack'e karşı).
    expected = _sign(req.state)
    if not req.signature or not hmac.compare_digest(req.signature, expected):
        raise HTTPException(
            status_code=400,
            detail="[GÜVENLİ] İmza doğrulanamadı veya format geçersiz (veri sunucudan gelmemiş veya değiştirilmiş).",
        )

    # KONTROL 2 — Şema: format/yapı doğru mu? (pickle yok, yalnızca JSON + allowlist)
    try:
        parsed = json.loads(req.state)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="[GÜVENLİ] İmza doğrulanamadı veya format geçersiz.")

    try:
        validated = StateSchema(**parsed)
    except (ValidationError, TypeError):
        raise HTTPException(status_code=400, detail="[GÜVENLİ] İmza doğrulanamadı veya format geçersiz.")

    return {
        "restored": True,
        "state": validated.model_dump(),
        "message": "Durum geri yüklendi (HMAC imzası doğrulandı + şema geçerli).",
    }
