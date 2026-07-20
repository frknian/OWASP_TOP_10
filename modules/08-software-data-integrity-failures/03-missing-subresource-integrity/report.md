# [A08:2025] Software or Data Integrity Failures → Missing Subresource Integrity (SRI)

**Modül:** 08-software-data-integrity-failures
**Senaryo:** HTML sayfası, harici bir kaynaktan (CDN) bir JavaScript kütüphanesi yükler ama `<script>` tag'inde `integrity`/`crossorigin` özniteliği yoktur. CDN ele geçirilir/script değiştirilirse, tarayıcı değiştirilmiş kodu sayfanın tam yetkisiyle çalıştırır.
**Portlar:** vulnerable `8240`, fixed `8241`
**Durum:** Tamamlandı (curl + tarayıcı ile doğrulandı: vulnerable + fixed). **Not:** Bu senaryonun asıl doğrulaması tarayıcıda yapılır (SRI, gerçek tarayıcı davranışıdır — defanged değildir).

## Bu Kategori Nedir?
Yazılımın veya verinin KAYNAĞINA/BÜTÜNLÜĞÜNE güvenilip doğrulanmamasıyla ilgilidir — güvensiz deserialization, mass assignment, imzasız kaynaklardan yüklenen script'ler. A03'ten farkı: A03 dış bağımlılık zincirini, A08 kendi uygulama/veri sınırların içindeki bütünlüğü kapsar. Temel korunma: dijital imza/HMAC doğrulama, allowlist DTO'lar, Subresource Integrity (SRI).

## CVSS 3.1
- **Skor:** 8.6 (High)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`

**Gerekçe:**
- **AV:N / AC:L / PR:N** — Saldırı, üçüncü taraf kaynağın (CDN) ele geçirilmesiyle uzaktan gerçekleşir; siteyi ziyaret eden herkesi etkiler.
- **UI:R** — Kurbanın etkilenen sayfayı ziyaret etmesi gerekir.
- **S:C (Scope: Changed)** — Zafiyet üçüncü taraf CDN'dedir ama etki, script'i dahil eden uygulamanın güvenlik alanında gerçekleşir (kapsam değişir). Değiştirilmiş script, sayfanın origin'inde çalışır: çerez/oturum çalma, DOM manipülasyonu, kullanıcı adına işlem.
- **C:H / I:H** — Sayfa origin'inde keyfi JS → oturum verilerinin okunması ve sayfa bütünlüğünün bozulması.

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [x] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V14.2.3:** *"Verify that if client-side assets, such as JavaScript libraries, CSS or web fonts, are hosted externally on a Content Delivery Network (CDN) or external provider, Subresource Integrity (SRI) is used to validate the integrity of the asset."*
- **V1.14.x / V14.4.x:** İçerik güvenliği (CSP) ve güvenli bağımlılık dahil etme.
- **CWE-829:** Inclusion of Functionality from Untrusted Control Sphere
- Destekleyici: **CWE-353** (Missing Support for Integrity Check)

## Açıklama
```html
<!-- vulnerable: integrity/crossorigin YOK -->
<script src="http://127.0.0.1:8240/cdn/lib.js"></script>
```
**Subresource Integrity (SRI)**, W3C standardıdır: `<script>`/`<link>` tag'ine, kaynağın beklenen içeriğinin kriptografik özeti (`integrity="sha384-..."`) gömülür. Tarayıcı kaynağı indirdikten sonra özetini hesaplar ve gömülü değerle karşılaştırır; eşleşmezse kaynağı **çalıştırmaz/uygulamaz**.

SRI olmadığında, tarayıcının indirdiği script'in beklenen kod olup olmadığını anlama yolu yoktur. Bir saldırgan CDN'i ele geçirir (veya DNS/BGP hijack, MITM ile içeriği değiştirirse), o CDN'den beslenen **tüm siteler** değiştirilmiş kodu, her birinin kendi origin'inde ve tam yetkisiyle çalıştırır. Bu, gerçek dünyada tekrar tekrar görülen bir tedarik zinciri saldırısı biçimidir (ör. British Airways/Magecart, Polyfill.io 2024, çeşitli npm/CDN kompromizleri).

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8240`. **Asıl gösterim tarayıcıda yapılır.**

1. **HTML kaynağında SRI eksikliğini göster:**
   ```
   curl -s http://127.0.0.1:8240/ | grep script
   ```
   **Beklenen:** `<script src="http://127.0.0.1:8240/cdn/lib.js"></script>` — `integrity`/`crossorigin` **yok**.

2. **Meşru vs ele geçirilmiş içeriğin farklı olduğunu göster:**
   ```
   curl -s "http://127.0.0.1:8240/cdn/lib.js"               # meşru: "lib.js yüklendi"
   curl -s "http://127.0.0.1:8240/cdn/lib.js?tampered=true" # ele geçirilmiş: "CDN ELE GEÇİRİLDİ"
   ```

3. **Tarayıcıda "ele geçirilmiş CDN" senaryosu:**
   - `http://127.0.0.1:8240/?tampered=true` adresini tarayıcıda aç.
   - **Beklenen:** Sayfadaki durum kutusu **kırmızı** *"⚠️ CDN ELE GEÇİRİLDİ — değiştirilmiş script çalıştı!"* olur; konsolda aynı uyarı görünür. SRI olmadığından değiştirilmiş script **çalışır**.

**Test sonucu (curl + tarayıcı ile doğrulandı):**

*Statik kontrol (curl):*
- VULN `GET /` → `<script src="http://127.0.0.1:8240/cdn/lib.js"></script>` — `integrity`/`crossorigin` **yok**. ✅
- FIXED `GET /` → `<script src="...8241/cdn/lib.js" integrity="sha384-+haW3XCw7F2zZBYEwJnBdKHaaq1iKY68Hw5s511nPq2BqoY0JRQ2/Hetd4jQsvOp" crossorigin="anonymous"></script>`. ✅
- Hash tutarlılığı: FIXED `GET /status`'taki `sri_hash` ile HTML'deki `integrity` değeri **birebir eşleşti**. ✅
- `GET /cdn/lib.js` (meşru) vs `?tampered=true` (ele geçirilmiş) → iki farklı içerik döndü. ✅

*Tarayıcı testi (gerçek W3C SRI davranışı — defanged DEĞİL):*

| Sayfa | Durum kutusu | Script çalıştı mı? |
|---|---|---|
| **FIXED meşru** (`8241/`) | "lib.js yüklendi ✓ (meşru)" | ✅ Evet — hash tuttu |
| **FIXED tampered** (`8241/?tampered=true`) | "script bekleniyor…" (değişmedi) | ⛔ **Hayır — tarayıcı native SRI ile engelledi** |
| **VULN tampered** (`8240/?tampered=true`) | "⚠️ CDN ELE GEÇİRİLDİ — değiştirilmiş script çalıştı!" | 🔓 Evet — SRI olmadığından çalıştı |

Kritik kanıt: FIXED tampered sayfasında hash uyuşmadığı için tarayıcı script'i **hiç çalıştırmadı** (durum "script bekleniyor…" olarak kaldı); aynı tampered içerik VULN'de sorunsuz çalıştı. Bu, SRI'nin tedarik zinciri saldırısını tarayıcı seviyesinde engellediğinin canlı kanıtıdır.

## Etki
- **Origin düzeyinde tam JS yürütme:** Değiştirilmiş script, sayfanın origin'inde çalışır → oturum çerezi/token okuma, form verisi sızdırma (Magecart tarzı ödeme bilgisi çalma), kullanıcı adına işlem, sayfa içeriğini değiştirme.
- **Tek noktadan çok kurban:** Ele geçirilen bir CDN, ondan beslenen tüm siteleri aynı anda etkiler — tedarik zinciri saldırılarının kaldıraç etkisi.

## Remediation Önerisi
```html
<!-- fixed: SHA-384 integrity + crossorigin -->
<script src="http://127.0.0.1:8241/cdn/lib.js"
        integrity="sha384-<meşru lib.js'nin base64 SHA-384 özeti>"
        crossorigin="anonymous"></script>
```
```python
# hash hesabı (fixed/main.py, import anında):
digest = hashlib.sha384(LIB_JS_BENIGN.encode()).digest()
LIB_JS_SRI = "sha384-" + base64.b64encode(digest).decode()
# eşdeğeri: openssl dgst -sha384 -binary lib.js | openssl base64 -A
```
- **SRI hash'i:** `<script>` tag'ine meşru sürümün SHA-384 özeti `integrity` olarak gömülür. Tarayıcı, indirdiği script'in özetini bununla karşılaştırır; **uyuşmazsa çalıştırmaz** (konsola bir SRI hatası yazar). Bu **defanged değildir** — gerçek tarayıcı davranışıdır.
- **`crossorigin="anonymous"`:** Cross-origin kaynaklarda SRI'nin çalışması için CORS gereklidir; kimlik bilgisi göndermeden (anonim) istek yapılır.
- **Hash sabitliği:** `integrity` değeri her zaman **meşru** sürümün hash'idir. `?tampered=true` ile farklı içerik geldiğinde özet tutmaz ve tarayıcı script'i reddeder.
- **CSP ile katmanlama:** SRI'ye ek olarak `Content-Security-Policy` (özellikle `require-sri-for script` benzeri direktifler ve `script-src` allowlist'i) ile hangi kaynakların yüklenebileceği de kısıtlanır.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8241`. **Asıl doğrulama tarayıcıda yapılır (native SRI).**

1. **HTML kaynağında integrity'nin varlığını göster:**
   ```
   curl -s http://127.0.0.1:8241/ | grep script
   ```
   **Beklenen:** `<script src="..." integrity="sha384-..." crossorigin="anonymous"></script>`.

2. **Meşru sayfa (tarayıcıda):** `http://127.0.0.1:8241/` → durum kutusu **yeşil** *"lib.js yüklendi ✓ (meşru)"* — hash tuttu, script çalıştı.

3. **Ele geçirilmiş sayfa (tarayıcıda):** `http://127.0.0.1:8241/?tampered=true` → durum kutusu **"meşru" OLMAZ**; script çalışmaz. Tarayıcı konsolunda şu tarz bir hata görünür:
   > *"Failed to find a valid digest in the 'integrity' attribute for resource ... The resource has been blocked."*
   Bu, SRI'nin değiştirilmiş kodu native olarak engellediğinin kanıtıdır.

4. **Sunucu tarafı hash'i kontrol et:**
   ```
   curl -s http://127.0.0.1:8241/status
   ```
   **Beklenen:** `{"...","sri_hash":"sha384-..."}` — HTML'e gömülen değerle aynı.

---

## Gerçek Dünyada Tespit / Önleme
- **SRI zorunluluğu:** CDN/dış kaynaktan yüklenen tüm statik varlıklar (`<script>`, `<link rel=stylesheet>`) `integrity` + `crossorigin` ile korunur. Build araçları (Webpack `SubresourceIntegrityPlugin`, Vite eklentileri) hash'leri otomatik üretir.
- **Content-Security-Policy (CSP):** `script-src` allowlist'i + gerektiğinde nonce/hash tabanlı politika; hangi origin'lerden script yükleneceği tarayıcı düzeyinde kısıtlanır.
- **Bağımlılık sabitleme (pinning):** CDN yerine/yanında, sürümü ve hash'i sabitlenmiş, kendi altyapında barındırılan (self-hosted) varlıklar; "latest" gibi kayan sürümlerden kaçınılır.
- **Tedarik zinciri izleme:** Üçüncü taraf script değişikliklerini izleyen araçlar (ör. web-page-integrity monitoring), Magecart/skimmer tespiti; kritik sayfalarda (ödeme) client-side envanteri sürekli denetlenir.
- **OWASP ASVS V14.2.3:** "Dış barındırılan client-side varlıklar için SRI kullanılıyor mu?" denetim listesine eklenir; PR şablonlarında yeni `<script src>` ekleyen değişiklikler için SRI kontrolü zorunlu tutulur.
- **Gerçek olaylar:** British Airways (2018, Magecart), Polyfill.io (2024, ~100k+ site), event-stream/npm kompromizleri — hepsi güvenilir görünen bir üçüncü taraf kaynağın ele geçirilmesiyle gerçekleşti; SRI + CSP bu vektörün etkisini önemli ölçüde azaltır.
