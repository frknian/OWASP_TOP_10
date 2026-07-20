# CWE-636 (Not Failing Securely) — FIX.
# Yetki servisi istisna fırlattığında karar GÜVENLİ tarafa düşer: erişim REDDEDİLİR
# (fail secure / fail closed). Kesinti anında kimse (admin dahil) içeri giremez —
# hizmet kaybı, yetkisiz erişimden her zaman tercih edilir.
"""
Modül 10 — Mishandling of Exceptional Conditions
Senaryo 2: Fail-Open Kimlik Doğrulama (FIXED)

Tasarım ilkesi — "fail secure by default": Bir güvenlik kontrolü, kararını veremiyorsa
(bağımlı servis çöktü, zaman aşımı, beklenmeyen hata) VARSAYILAN CEVAP "HAYIR" olmalıdır.
Erişim kontrolünün "bilmiyorum" durumu, "izin ver" değil "reddet" ile eşlenir.

Kesinti anında `GET /admin/dashboard` → 503 (servis geçici olarak kullanılamıyor).
Kullanıcı deneyimi bozulur ama yetkisiz erişim gerçekleşmez.

Çalıştırma: uvicorn main:app --port 8291
"""
# PORT: 8291
from fastapi import FastAPI, HTTPException

app = FastAPI()

AUTH_SERVICE_DOWN = {"value": False}


class PolicyEngineError(Exception):
    """Yetki servisine ulaşılamadığında fırlatılır (dış servis hatası simülasyonu)."""


def policy_engine_check(user: str | None) -> bool:
    # Vulnerable ile AYNI davranış — fark yalnızca istisnanın nasıl ELE ALINDIĞINDA.
    if AUTH_SERVICE_DOWN["value"]:
        raise PolicyEngineError("Yetki servisine ulaşılamıyor (bağlantı zaman aşımı)")
    return user == "admin"


@app.get("/status")
def status():
    return {"status": "up", "scenario": "fail-open-authentication (fixed)", "auth_service_down": AUTH_SERVICE_DOWN["value"]}


@app.post("/simulate-outage")
def simulate_outage():
    AUTH_SERVICE_DOWN["value"] = True
    return {"auth_service_down": True, "message": "Yetki servisi kesintisi simüle edildi."}


@app.post("/restore-service")
def restore_service():
    AUTH_SERVICE_DOWN["value"] = False
    return {"auth_service_down": False, "message": "Yetki servisi geri geldi."}


@app.get("/admin/dashboard")
def admin_dashboard(user: str | None = None):
    try:
        allowed = policy_engine_check(user)
    except PolicyEngineError:
        # FIX (FAIL SECURE / CLOSED): karar verilemiyorsa erişim REDDEDİLİR.
        # İstisna detayı istemciye sızdırılmaz (bkz. Modül 02/S3, Modül 10/S3).
        raise HTTPException(
            status_code=503,
            detail="Yetkilendirme servisi geçici olarak kullanılamıyor — erişim reddedildi (fail-secure).",
        )

    if not allowed:
        raise HTTPException(status_code=403, detail="Admin yetkisi yok")

    return {"access": "granted", "data": "GİZLİ: admin paneli verileri (tüm kullanıcılar, sistem ayarları)"}
