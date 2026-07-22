# [A02:2025] Security Misconfiguration → Forgotten Sample App / Default Credentials

**Modül:** 02-security-misconfiguration
**Senaryo:** Kurulumdan kalma bir "örnek yönetim / setup paneli"nin (`/sample-admin`) production'a taşınıp unutulması; panelin sabit kodlanmış `admin`/`admin` varsayılan kimlik bilgisiyle korunması ve doğru kimlik girildiğinde sunucuya dair system-info (sürüm/OS) sızdırması
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed) — Burp Suite görsel kanıtları için bkz. [evidence/](evidence/)

## Bu Kategori Nedir?
Bu kategori kod hatası değil, unutulmuş/varsayılan bırakılmış ayarlardan doğar — kurulum panelleri, açık dizin listeleme, aşırı detaylı hata mesajları, yanlış izin verilmiş depolama. Temel korunma: production ortamını sertleştirme (hardening) checklist'i, gereksiz özellik/endpoint'lerin kaldırılması, güvenli varsayılanlar.

## CVSS 3.1
- **Skor:** 5.3 (Medium)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

**Gerekçe:**
- **AV:N** — `/sample-admin` HTTP üzerinden ağ genelinde erişilebilir.
- **AC:L** — Herhangi bir özel koşul yok; saldırgan iyi bilinen `admin`/`admin` varsayılanını denemekle yetiniyor.
- **PR:N** — Hiçbir önceden ayrıcalık gerekmiyor; varsayılan kimlik bilgisi fiilen "kimlik doğrulama yok" ile eşdeğerdir.
- **UI:N** — Başka bir kullanıcının etkileşimi gerekmiyor.
- **S:U** — Etki aynı uygulama sınırında kalıyor.
- **C:L** — Sızan veri sunucu fingerprint bilgisi (Python/FastAPI sürümü, OS, hostname); kullanıcı verisi değil ama bilinen CVE eşlemesi için keşif değeri taşıyan bir gizlilik ihlali.
- **I:N / A:N** — Bu panel yalnızca bilgi döndürüyor; bütünlük/erişilebilirlik etkisi bu repro'da yok.

> **Not:** Skor, panelin *bu senaryoda fiilen yaptığı işe* (yalnızca system-info dönmesi) göre verilmiştir. Gerçek dünyadaki unutulmuş kurulum panelleri çoğu zaman konfigürasyon değiştirme / kullanıcı ekleme gibi yetenekler de içerir; öyle bir panelde aynı zafiyet `I:H`/`A:H` ile Critical seviyeye çıkardı.

## Risk Seviyesi
- [ ] Low
- [x] Medium
- [ ] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V14.3.2:** *"Verify that web or application server and application framework debug modes are disabled in production to eliminate debug features, developer consoles, and unintended security disclosures."* (Kurulum/geliştirme amaçlı özelliklerin production'dan çıkarılması.)
- **CWE-1392:** Use of Default Credentials
- **CWE-489:** Active Debug Code / Leftover Development/Setup Feature

## Açıklama
`vulnerable/main.py` içindeki `/sample-admin` endpoint'i (GET form + POST login), uygulamanın ilk kurulumunda gelen bir "setup paneli"dir. Kimlik doğrulaması, kaynak koda gömülü `admin`/`admin` varsayılanı ile yapılır:

```python
@app.post("/sample-admin")
def sample_admin_login(request, username=Form(...), password=Form(...)):
    if username == "admin" and password == "admin":
        return JSONResponse({"system_info": { ... }})
```

Kök neden, parolanın "zayıf" olması değildir — panelin production ortamında **hiç bulunmaması** gerekirdi. Bu, klasik bir **Security Misconfiguration** örneğidir: kurulum/geliştirme amaçlı bir bileşenin canlı sisteme sızması ve varsayılan yapılandırmasıyla (default credentials) bırakılması. Panel, doğru kimlik girildiğinde saldırgana sunucu parmak izi (Python/FastAPI sürümü, OS, hostname) vererek hedefli saldırının keşif adımını besler.

## Repro Adımları

**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8010` üzerinde çalışıyor.
```
uvicorn main:app --port 8010
```

1. **Panelin varlığını keşfet (form erişilebilir):**
   ```
   curl -i http://127.0.0.1:8010/sample-admin
   ```
   **Beklenen:** `200 OK`, HTML setup formu (ve "Default credentials: admin / admin" ipucu).

2. **Varsayılan kimlik bilgisiyle giriş yap:**
   ```
   curl -i -X POST http://127.0.0.1:8010/sample-admin \
     -F "username=admin" -F "password=admin"
   ```
   **Beklenen:** `200 OK` + system-info sızıntısı:
   ```json
   {"message": "Welcome to the Acme setup panel",
    "system_info": {"python_version": "3.x.y", "fastapi_version": "0.x.y",
                    "os": "Darwin 25.x", "hostname": "..."}}
   ```
   Saldırgan hiçbir hesaba sahip olmadan, iyi bilinen varsayılanı deneyerek panele girdi ve sunucu fingerprint bilgisini elde etti.

## Etki
- **Gizlilik (bilgi ifşası):** Python/FastAPI sürümleri ve OS bilgisi, saldırganın bilinen CVE'lerle eşleştirme yaparak exploit seçmesine olanak tanır (fingerprinting → hedefli saldırı).
- **Yetkisiz erişim:** Varsayılan kimlik bilgisi fiilen kimlik doğrulamasız erişimdir; panelin yetenekleri arttıkça (config değişikliği vb.) etki hızla büyür.

## Remediation Önerisi
`fixed/main.py` içinde uygulanan çözüm: **`/sample-admin` endpoint'i tamamen kaldırıldı** (GET ve POST route'ları koddan çıkarıldı).

- Remediation "parolayı değiştir" değildir — kök neden, saldırı yüzeyinde bulunmaması gereken bir kurulum panelidir; doğru düzeltme o yüzeyi ortadan kaldırmaktır.
- Genel ilke: kurulum/geliştirme/örnek (sample) bileşenleri build/deploy sürecinde production imajından hariç tutulmalı; varsayılan hesaplar ürünle birlikte sevk edilmemelidir.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, ayrı portta (`8011`) çalışıyor.

1. `curl -i http://127.0.0.1:8011/sample-admin` → **Beklenen:** `404 Not Found` (route kayıtlı değil).
2. `curl -i -X POST http://127.0.0.1:8011/sample-admin -F "username=admin" -F "password=admin"` → **Beklenen:** `404 Not Found` (denenecek hedef yok).
3. `curl -i http://127.0.0.1:8011/` → **Beklenen:** `200 OK` — asıl uygulama etkilenmeden çalışmaya devam ediyor.

Vulnerable sürümde system-info sızdıran panel, fixed sürümde artık mevcut değildir; varsayılan kimlik bilgisiyle saldırılacak bir yüzey kalmamıştır.

### Curl Doğrulama Sonuçları (gerçekleşen)

Vulnerable (`8010`) ve fixed (`8011`) sürümler aynı anda ayağa kaldırılıp aynı istek her ikisine gönderildi:

| İstek | Vulnerable (8010) | Fixed (8011) |
|-------|-------------------|--------------|
| `POST /sample-admin` (`username=admin&password=admin`) | **`200 OK`** — panel açıldı ve system-info sızdı | **`404 Not Found`** — route kayıtlı değil |

Vulnerable yanıt gövdesi (gerçek çıktı):
```json
{"message": "Welcome to the Acme setup panel",
 "system_info": {"python_version": "3.14.6", "fastapi_version": "0.139.0",
                 "os": "Darwin 25.5.0", "hostname": "lab-host.local"}}
```
Fixed yanıt gövdesi: `{"detail": "Not Found"}` (FastAPI'nin bilinmeyen route için verdiği varsayılan 404).

**Sonuç:** ✅ Varsayılan kimlik bilgisiyle system-info sızdıran panel, remediation sonrası tamamen erişilemez (endpoint kaldırıldı).
