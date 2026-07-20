# CWE-636 (Not Failing Securely / 'Failing Open'): yetki servisi bir istisna fırlattığında
# kod, güvenli tarafa (reddet) değil AÇIK tarafa (izin ver) düşer. Sonuç: yetkilendirme
# altyapısı çöktüğünde erişim kontrolü tamamen devre dışı kalır.
"""
Modül 10 — Mishandling of Exceptional Conditions
Senaryo 2: Fail-Open Kimlik Doğrulama (VULNERABLE)

Bağlam: `GET /admin/dashboard`, arka planda bir "policy engine" (yetki servisi) çağırarak
erişim kararı alır. Gerçek dünyada bu, harici bir IAM/LDAP/OPA servisi olurdu.

Zafiyet: Policy engine bir istisna fırlattığında (servis çöktü), `except` bloğu kararı
"izin ver" olarak verir — FAIL OPEN. Yani yetki servisi erişilemez olduğunda, kimlik
doğrulaması olmayan HERKES admin paneline girebilir.

Test: `POST /simulate-outage` ile servis kesintisi tetiklenir; ardından hiç oturum
açmadan `GET /admin/dashboard` çağrıldığında 200 döner.

Çalıştırma: uvicorn main:app --port 8290
"""
# PORT: 8290
from fastapi import FastAPI

app = FastAPI()

# "Yetki servisi" kesinti durumu (test için tetiklenebilir).
AUTH_SERVICE_DOWN = {"value": False}


class PolicyEngineError(Exception):
    """Yetki servisine ulaşılamadığında fırlatılır (dış servis hatası simülasyonu)."""


def policy_engine_check(user: str | None) -> bool:
    """Yetki servisi: kullanıcının admin olup olmadığını döner. Kesintide istisna fırlatır."""
    if AUTH_SERVICE_DOWN["value"]:
        raise PolicyEngineError("Yetki servisine ulaşılamıyor (bağlantı zaman aşımı)")
    return user == "admin"


@app.get("/status")
def status():
    return {"status": "up", "scenario": "fail-open-authentication", "auth_service_down": AUTH_SERVICE_DOWN["value"]}


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
    except PolicyEngineError as e:
        # ZAFIYET (FAIL OPEN): yetki servisi çöktüğünde erişim REDDEDİLMİYOR, İZİN VERİLİYOR.
        # "Kullanıcıyı mağdur etmeyelim" refleksiyle yazılmış bu satır, kesinti anında
        # erişim kontrolünü tamamen devre dışı bırakır.
        return {
            "access": "granted",
            "degraded_mode": True,
            "reason": f"Yetki servisi hatası — erişime izin verildi (fail-open): {e}",
            "data": "GİZLİ: admin paneli verileri (tüm kullanıcılar, sistem ayarları)",
        }

    if not allowed:
        return {"access": "denied", "reason": "Admin yetkisi yok"}

    return {"access": "granted", "data": "GİZLİ: admin paneli verileri (tüm kullanıcılar, sistem ayarları)"}
