"""
Modül 02 — Security Misconfiguration
Senaryo 1: Forgotten Sample App / Default Credentials (FIXED)

Remediation: Zafiyet "parolayı güçlendirmek" ile değil, gereksiz/kurulumdan kalma
`/sample-admin` endpoint'ini production'dan TAMAMEN KALDIRARAK kapatıldı. Kök neden
zayıf parola değil, saldırı yüzeyinde hiç bulunmaması gereken bir kurulum panelinin
varlığıydı — dolayısıyla doğru düzeltme, o yüzeyi ortadan kaldırmaktır.

Sonuç: `/sample-admin` (GET ve POST) artık kayıtlı değil; FastAPI bilinmeyen route
için otomatik olarak 404 döner. Varsayılan kimlik bilgisiyle giriş denemesi için
saldırılacak bir hedef kalmaz.

Çalıştırma: uvicorn main:app --port 8011
"""
# PORT: 8011
from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def index():
    # Yalnızca asıl uygulama ayakta kalıyor; kurulum paneli üretim yapısından çıkarıldı.
    return {"app": "Acme Widgets API", "status": "running"}


# NOT: /sample-admin route'u (form + login) burada kasıtlı olarak yoktur.
# Kaldırılan endpoint = ortadan kalkan saldırı yüzeyi. Varsayılan kimlik bilgisi
# kontrolü, gömülü admin/admin parolası ve system-info sızıntısı artık mevcut değil.
