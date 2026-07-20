# OWASP Top 10 Lab
### OWASP Top 10:2025 — Vulnerable & Fixed Implementations with Interactive Lab

Bilinçli olarak zafiyetli mini web uygulamaları üzerinde web güvenliği zafiyetlerini
gösteren, her zafiyet için **Vulnerable / Fixed** sürüm çifti, CVSS/CWE/ASVS eşlemesi ve
profesyonel formatta pentest raporu üreten bir öğrenme ve portföy projesi.

> 📖 **Projeye yeni başlıyorsan önce [INTRODUCTION.md](INTRODUCTION.md)'yi okumanı öneririz** —
> OWASP Top 10'un ne olduğu, 2025 listesindeki 10 kategori, temel korunma prensipleri ve
> bu projede nasıl öğrendiğimiz orada anlatılıyor.

## Önizleme

![OWASP Top 10 Lab — Tanıtım Sayfası](assets/landing-preview.png)

> ⚠️ **Etik kullanım:** Tüm modüller yalnızca yerel lab ortamında (`127.0.0.1`) çalışır.
> Hiçbir gerçek/üçüncü taraf sisteme istek atılmaz. Amaç savunma ve saldırı yetkinliğini
> eğitim/portföy bağlamında belgelemektir.

## Kapsam
**OWASP Top 10:2025'in her maddesini kod + test + rapor + interaktif demo ile kapsayan,
net bir bitiş çizgisi olan tamamlanmış bir portföy projesi.** Kapsam 10 modülle sınırlıdır;
açık uçlu bir platform değildir.

Her zafiyet kategorisi; çalıştırılabilir zafiyetli kod, düzeltilmiş karşılığı ve
standartlara (CVSS 3.1, CWE, OWASP ASVS) dayalı bir bulgu raporuyla birlikte ele alınır —
böylece hem zafiyetin *nasıl* sömürüldüğü hem de *neden* düzeltildiği kanıtlanabilir
şekilde belgelenir.

## Modül Listesi (OWASP Top 10:2025)
Proje **OWASP Top 10:2021 → 2025** sırasına geçmiştir. Güncel modül sırası:

| # | Modül | Not | Durum |
|---|-------|-----|-------|
| 01 | Broken Access Control | SSRF dahil; BOLA/BFLA açıkça kapsanıyor | ✅ Tamamlandı |
| 02 | Security Misconfiguration | | ✅ Tamamlandı |
| 03 | Software Supply Chain Failures | Eski "Vulnerable and Outdated Components"ın genişletilmiş hali; senaryolar DEFANGED simülasyon | ✅ Tamamlandı (4/4 senaryo) |
| 04 | Cryptographic Failures | | ✅ Tamamlandı (3/3 senaryo) |
| 05 | Injection | | ✅ Tamamlandı (4/4 senaryo) |
| 06 | Insecure Design | Kusur kod hatası değil tasarım kusuru — fix, akışın/iş kuralının yeniden tasarlanması | ✅ Tamamlandı (3/3 senaryo) |
| 07 | Authentication Failures | | ✅ Tamamlandı (3/3 senaryo) |
| 08 | Software or Data Integrity Failures | | ✅ Tamamlandı (3/3 senaryo) |
| 09 | Security Logging and Alerting Failures | | ✅ Tamamlandı (3/3 senaryo) |
| 10 | Mishandling of Exceptional Conditions | Yeni kategori; eski SSRF modülünün yerine geçti — SSRF artık A01'e konsolide oldu | ✅ Tamamlandı (4/4 senaryo) |

> 🏁 **10/10 modül tamamlandı — bu proje kapanmıştır.**

## Şu Anki Durum
**10/10 modül tamamlandı — OWASP Top 10:2025 Lab backend'i TAMAMLANMIŞTIR.** Toplam **10 modül, 34 senaryo** — her biri çalıştırılabilir Vulnerable/Fixed sürüm çifti, CVSS 3.1 skoru, CWE eşlemesi, OWASP ASVS kontrol maddesi ve curl (bazı senaryolarda tarayıcı) ile doğrulanmış tam bir pentest raporuyla birlikte (kod + test + rapor).

Modül dökümü: Modül 01 — Broken Access Control (3/3), Modül 02 — Security Misconfiguration (4/4), Modül 03 — Software Supply Chain Failures (4/4), Modül 04 — Cryptographic Failures (3/3), Modül 05 — Injection (4/4), Modül 06 — Insecure Design (3/3), Modül 07 — Authentication Failures (3/3), Modül 08 — Software or Data Integrity Failures (3/3), Modül 09 — Security Logging and Alerting Failures (3/3), Modül 10 — Mishandling of Exceptional Conditions (4/4).

**Modül 01 — Broken Access Control**

| Senaryo | Zafiyet | Durum |
|---------|---------|-------|
| 1 | IDOR / Horizontal Privilege Escalation | ✅ Tamamlandı |
| 2 | Missing Function Level Access Control | ✅ Tamamlandı |
| 3 | Client-Side Enforcement Bypass (CWE-602) | ✅ Tamamlandı |

**Modül 02 — Security Misconfiguration**

| Senaryo | Zafiyet | Durum |
|---------|---------|-------|
| 1 | Forgotten Sample App / Default Credentials (CWE-1392/489) | ✅ Tamamlandı |
| 2 | Directory Listing → Source Exposure (CWE-548/540/798) | ✅ Tamamlandı |
| 3 | Verbose Error Messages (CWE-209) | ✅ Tamamlandı |
| 4 | Public Cloud Storage Misconfiguration (CWE-732/284/1188) | ✅ Tamamlandı |

**Modül 03 — Software Supply Chain Failures** *(4 senaryo — DEFANGED simülasyon; gerçek zararlı kod/RCE/exfiltration yoktur)*

| Senaryo | Zafiyet | Port (vuln/fixed) | Durum |
|---------|---------|-------------------|-------|
| 1 | Vulnerable Component / Log4Shell tarzı (CWE-1395/477) | 8050 / 8051 | ✅ Tamamlandı (curl ile doğrulandı) |
| 2 | Conditional Backdoor / Bybit tarzı (CWE-1395/506) | 8060 / 8061 | ✅ Tamamlandı (curl ile doğrulandı) |
| 3 | Post-install Worm / Shai-Hulud tarzı (CWE-1395/506) | 8070 / 8071 | ✅ Tamamlandı (curl ile doğrulandı) |
| 4 | Component RCE / Struts tarzı (CWE-1395/477) | 8080 / 8081 | ✅ Tamamlandı (curl ile doğrulandı) |

**Modül 04 — Cryptographic Failures** *(3 senaryo; S2/S3 fixed sürümleri fail-secure — `ENCRYPTION_KEY` env yoksa başlamayı reddeder)*

| Senaryo | Zafiyet | Port (vuln/fixed) | Durum |
|---------|---------|-------------------|-------|
| 1 | Weak/Unsalted Hashing + Rainbow Table (CWE-327/759/916) | 8090 / 8091 | ✅ Tamamlandı (curl ile doğrulandı) |
| 2 | Hardcoded Encryption Key (CWE-321/798) | 8100 / 8101 | ✅ Tamamlandı (curl ile doğrulandı) |
| 3 | Plaintext Sensitive Data at Rest (CWE-311/312) | 8110 / 8111 | ✅ Tamamlandı (curl ile doğrulandı) |

**Modül 05 — Injection** *(4 senaryo; S3 command injection DEFANGED — gerçek komut çalıştırılmaz)*

| Senaryo | Zafiyet | Port (vuln/fixed) | Durum |
|---------|---------|-------------------|-------|
| 1 | SQL Injection / String Concatenation (CWE-89) | 8120 / 8121 | ✅ Tamamlandı (curl ile doğrulandı) |
| 2 | ORM Injection / Blind Trust in Frameworks (CWE-89) | 8130 / 8131 | ✅ Tamamlandı (curl ile doğrulandı) |
| 3 | OS Command Injection (CWE-78, DEFANGED) | 8140 / 8141 | ✅ Tamamlandı (curl ile doğrulandı) |
| 4 | Reflected XSS (CWE-79) | 8150 / 8151 | ✅ Tamamlandı (curl ile doğrulandı) |

**Modül 06 — Insecure Design** *(3 senaryo; senaryolar gerçekten çalışır — defanged değil. Vulnerable/fixed farkı tek satırlık kod düzeltmesi değil, akışın/iş kuralının yeniden tasarlanmasıdır)*

| Senaryo | Zafiyet | Port (vuln/fixed) | Durum |
|---------|---------|-------------------|-------|
| 1 | Insecure Credential Recovery / Güvenlik Soruları (CWE-640) | 8160 / 8161 | ✅ Tamamlandı (curl ile doğrulandı) |
| 2 | Business Logic Bypass / Grup Rezervasyonu (CWE-841/770) | 8170 / 8171 | ✅ Tamamlandı (curl ile doğrulandı) |
| 3 | Missing Rate Limiting / Bot Protection (CWE-770/799) | 8180 / 8181 | ✅ Tamamlandı (curl ile doğrulandı) |

**Modül 07 — Authentication Failures** *(3 senaryo; hashing zaten doğru — argon2id; kusur brute-force koruması, MFA ve session yaşam döngüsü yönetiminde)*

| Senaryo | Zafiyet | Port (vuln/fixed) | Durum |
|---------|---------|-------------------|-------|
| 1 | Credential Stuffing / Brute-Force Koruması Yok (CWE-307) | 8190 / 8191 | ✅ Tamamlandı (curl ile doğrulandı) |
| 2 | Tek Faktör Olarak Parola / MFA Yokluğu (CWE-308) | 8200 / 8201 | ✅ Tamamlandı (curl ile doğrulandı) |
| 3 | Session Timeout / Logout Kırıklığı (CWE-613/287) | 8210 / 8211 | ✅ Tamamlandı (curl ile doğrulandı) |

**Modül 08 — Software or Data Integrity Failures** *(3 senaryo; S1 DEFANGED — gerçek pickle.loads çağrılmaz. S3 defanged DEĞİL — gerçek W3C SRI davranışı tarayıcıda kanıtlanır)*

| Senaryo | Zafiyet | Port (vuln/fixed) | Durum |
|---------|---------|-------------------|-------|
| 1 | Insecure Deserialization (CWE-502, DEFANGED) | 8220 / 8221 | ✅ Tamamlandı (curl ile doğrulandı) |
| 2 | Mass Assignment (CWE-915) | 8230 / 8231 | ✅ Tamamlandı (curl ile doğrulandı) |
| 3 | Missing Subresource Integrity / SRI (CWE-829) | 8240 / 8241 | ✅ Tamamlandı (curl + tarayıcı ile doğrulandı) |

**Modül 09 — Security Logging and Alerting Failures** *(3 senaryo; S3'te loglama her iki sürümde de çalışır — fark yalnızca alerting katmanındadır)*

| Senaryo | Zafiyet | Port (vuln/fixed) | Durum |
|---------|---------|-------------------|-------|
| 1 | Loglara Hassas Veri Sızması (CWE-532) | 8250 / 8251 | ✅ Tamamlandı (curl ile doğrulandı) |
| 2 | Log Injection / Forging (CWE-117) | 8260 / 8261 | ✅ Tamamlandı (curl ile doğrulandı) |
| 3 | Alerting Eksikliği / Eşik Yok (CWE-778) | 8270 / 8271 | ✅ Tamamlandı (curl ile doğrulandı) |

**Modül 10 — Mishandling of Exceptional Conditions** *(4 senaryo — projenin SON modülü; her biri istisna/hata durumlarının güvensiz ele alınmasını kapsar)*

| Senaryo | Zafiyet | Port (vuln/fixed) | Durum |
|---------|---------|-------------------|-------|
| 1 | Kaynak Tükenmesi / DoS (CWE-404/772) | 8280 / 8281 | ✅ Tamamlandı (curl ile doğrulandı) |
| 2 | Fail-Open Kimlik Doğrulama (CWE-636) | 8290 / 8291 | ✅ Tamamlandı (curl ile doğrulandı) |
| 3 | Veritabanı Hatası Üzerinden Bilgi Sızıntısı (CWE-209) | 8300 / 8301 | ✅ Tamamlandı (curl ile doğrulandı) |
| 4 | İşlem Bütünlüğü — Rollback Eksikliği (CWE-460) | 8310 / 8311 | ✅ Tamamlandı (curl ile doğrulandı) |

## Teknoloji Stack
- **Backend:** FastAPI (Python)
- **Frontend:** Minimal (Jinja2 / hafif SPA) — amaç frontend showcase değil, API + frontend
  etkileşiminde ortaya çıkan zafiyetleri (XSS vb.) gösterebilmek
- **Ortam:** Docker kullanılmıyor — her modül kendi Python `venv` + `requirements.txt` ile
  izole çalışır; Vulnerable/Fixed sürümler farklı portlarda ayağa kaldırılır

## Proje Yapısı
```
modules/
  01-broken-access-control/
    01-idor-horizontal-privilege-escalation/
      vulnerable/   # zafiyetli sürüm (kendi venv + requirements.txt)
      fixed/        # düzeltilmiş sürüm (kendi venv + requirements.txt)
      report.md     # CVSS / ASVS / repro / etki / remediation
    02-missing-function-level-access-control/
    03-client-side-enforcement-bypass/
control-panel/         # senaryoları başlatıp durduran ayrı iç araç (launcher)
```

## Control Panel (Launcher)
`control-panel/`, `modules/` altındaki senaryoları tek bir web arayüzünden **başlatıp
durdurmak** için ayrı bir FastAPI uygulamasıdır. Senaryo kodlarına hiç dokunmaz; her
`main.py`'nin en üstündeki `# PORT: XXXX` işaretini okuyarak hangi uygulamanın hangi
portta çalışacağını öğrenir ve her birini kendi `venv`'iyle ayrı bir subprocess olarak
ayağa kaldırır.

**Çalıştırma:**
```
cd control-panel
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
./venv/bin/uvicorn main:app --port 9000
# tarayıcı: http://127.0.0.1:9000
```
> **Not:** Python 3.14 kullanıyorsanız Jinja2 3.1.5+ gerekir (eski Jinja2 sürümleri
> Python 3.14 ile uyumsuz — `requirements.txt` bu minimum sürümü sabitler).

> 🏠 **Ana sayfa:** `http://127.0.0.1:9000/` artık yeni tasarımlı landing sayfasıyla
> açılır (`/` → `/app/` yönlendirmesi; OWASP Top 10:2025 tanıtımı + modül gezgini).
> Teknik launcher (manuel başlat/durdur tablosu) `/launcher` adresinde çalışmaya devam eder.

**Ne işe yarar:**
- `modules/` altını tarar (34 senaryo, 68 port — 10 modülün tamamı) ve her senaryo için
  Vulnerable/Fixed sürümleri ayrı ayrı listeler.
- Her sürüm için **Başlat / Durdur** butonu ve o portun dinlenip dinlenmediğini gösteren
  **yeşil/kırmızı durum noktası** (birkaç saniyede bir otomatik güncellenir).
- **Tümünü Durdur** butonu ile oturum sonu temizliği (bilinen tüm portlardaki süreçleri
  öldürür). Panel yeniden başlatılmış olsa bile orphan süreçleri `lsof` ile bulup durdurur.
- Modül 04 fixed S2/S3 fail-secure olduğundan panel, başlattığı her alt sürece geçerli
  bir `ENCRYPTION_KEY` enjekte eder — bu senaryolar da panelden çalıştırılabilir.
- Önkoşul: ilgili modülde `setup_venvs.sh` çalıştırılmış olmalı (venv yoksa panel net
  bir hata döndürür).

**Interactive Lab kapsamı:**
Panel yalnızca bir launcher değil; her senaryo için tek tıkla saldırıyı çalıştıran,
Vulnerable/Fixed yanıtlarını yan yana gösteren ve "Nasıl Çalışır?" açıklamasıyla kodu
karşılaştıran interaktif demolar içerir.

> 🏁 **10/10 modül — Interactive Lab TAMAMLANDI.** Launcher (Başlat/Durdur + canlı durum)
> **34 senaryonun tamamını** (68 port) otomatik tarar ve **34 senaryonun her biri için
> özel (bespoke) interaktif demo bileşeni** mevcuttur: sidebar'da 10 modül grubu,
> 34 senaryo. Her demo tek tıkla saldırıyı çalıştırır, Vulnerable/Fixed yanıtlarını yan
> yana gösterir ve "🔍 Nasıl Çalışır?" panelinde adım adım anlatım + gerçek `main.py`
> kod alıntılarını sunar.

## Rapor Formatı
Her bulgu için: Başlık, CVSS 3.1 skoru ve vektörü, Risk Seviyesi (Low/Med/High/Critical),
ilgili OWASP ASVS kontrol maddesi, Açıklama, Repro adımları, Etki, Remediation önerisi.

# OWASP_TOP_10
