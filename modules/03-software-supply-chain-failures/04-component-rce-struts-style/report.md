# [A03:2025] Software Supply Chain Failures → Component RCE (Struts tarzı)

**Modül:** 03-software-supply-chain-failures
**Senaryo:** Uygulama, gelen veriyi işlemek için zafiyetli `data_parser` bileşenine güvenir. `POST /parse`, kullanıcı girdisini doğrudan bu ayrıştırıcıya verir; ayrıştırıcı, girdideki `%{...}` ifadelerini kod olarak "değerlendirir" (Apache Struts, CVE-2017-5638 / S2-045 — OGNL injection deseni).
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

> ⚠️ **DEFANGED SIMULATION:** `%{...}` bulunduğunda hiçbir gerçek komut/kod çalıştırılmaz. Ayrıştırıcı, gerçek eylem yerine `"[SİMÜLASYON] Bu noktada arbitrary code execution olurdu: ..."` metni döndürür. Amaç, güvenilen bir ayrıştırıcı bileşenin **girdiyi kod olarak yorumlaması** kusurunu güvenle göstermektir.

## Bu Kategori Nedir?
Uygulamanın kendi kodu güvenli olsa bile, kullandığı bağımlılıklar (kütüphaneler, paketler, build araçları) güvenli olmayabilir. Log4Shell, SolarWinds, npm worm'ları gerçek örneklerdir. Temel korunma: SBOM (Software Bill of Materials), bağımlılık taraması (SCA), imza/provenance doğrulama, sürüm pinleme.

## CVSS 3.1
- **Skor:** 9.8 (Critical) — *simüle edilen gerçek zafiyetin skoru; bu ortamda etki defanged'dır.*
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Gerekçe (gerçek karşılık):**
- **AV:N** — `POST /parse` HTTP üzerinden erişilebilir.
- **AC:L** — Tek gereken, girdiye `%{...}` ifadesi yerleştirmek.
- **PR:N / UI:N** — Anonim, etkileşimsiz.
- **S:U** — Etki uygulama sınırında modellendi (gerçekte S:C'ye çıkabilir).
- **C:H / I:H / A:H** — Gerçek karşılığında uzaktan kod çalıştırma → tam gizlilik/bütünlük/erişilebilirlik kaybı (Struts S2-045 tam olarak buydu).

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [ ] High
- [x] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V14.2.1:** *"Verify that all components are up to date, preferably using a dependency checker during build or compile time."*
- Destekleyici: **V5.5.1 / V5.5.3** — serileştirilmiş veri/ifade değerlendirmesinin güvensiz kullanımına karşı koruma.
- **CWE-1395:** Dependency on Vulnerable Third-Party Component *(ana CWE)*
- Destekleyici: **CWE-477** (Use of Obsolete Function) — bileşenin ifade değerlendirme özelliği, terk edilmesi gereken güvensiz bir davranıştır.

## Açıklama
Uygulama kodu masumdur: `parse`, girdiyi yalnızca `data_parser.parse(...)`'a verir. Kusur, **girdiyi ifade olarak değerlendiren** bağımlılıktadır:

```python
# data_parser/__init__.py
_EXPRESSION_PATTERN = re.compile(r"%\{([^}]*)\}")  # OGNL benzeri %{...}

def parse(payload):
    match = _EXPRESSION_PATTERN.search(payload)
    if match:
        # DEFANGED — gerçekte gömülü ifade sunucuda çalıştırılır (RCE)
        return {"parsed": False, "rce": "[SİMÜLASYON] Bu noktada arbitrary code execution olurdu: ..."}
    return {"parsed": True, "value": payload}
```

Struts CVE-2017-5638'de saldırgan, `Content-Type` başlığına gömdüğü OGNL ifadesini çalıştırarak sunucuda komut yürütüyordu. Mekanizma aynıdır: **güvenilen bir ayrıştırıcı/deserializer, saldırgan kontrollü veriyi kod olarak yorumlar.**

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8080`.
```
uvicorn main:app --port 8080
```

1. **Zararsız veri — normal ayrıştırma:**
   ```
   curl -s -X POST http://127.0.0.1:8080/parse \
     -H "Content-Type: application/json" \
     -d '{"payload": "name=alice"}'
   ```
   **Beklenen:** `{"parsed": true, "value": "name=alice"}` — girdi düz veri olarak işlenir.

2. **OGNL/ifade payload'ı — zafiyet tetiklenir:**
   ```
   curl -s -X POST http://127.0.0.1:8080/parse \
     -H "Content-Type: application/json" \
     -d '{"payload": "name=%{7*7}"}'
   ```
   **Beklenen:** `parsed: false` ve `rce` alanında:
   ```
   [SİMÜLASYON] Bu noktada arbitrary code execution olurdu: ayrıştırıcı, gömülü ifade
   '%{7*7}' değerini kod olarak değerlendirip sunucuda çalıştırırdı ...
   ```
   `%{7*7}` klasik OGNL/ifade-injection sondasıdır; simülasyon metninin görünmesi, bileşenin girdiyi **kod olarak değerlendirdiğini** kanıtlar.

**Test sonucu (curl ile doğrulandı):**
- **Vulnerable (8080):** `{"payload":"order total %{7*7}"}` → `parsed:false` ve `rce` alanında ifadenin kod olarak değerlendirilip çalıştırılacağı simülasyon metni. ✅
- **Fixed (8081):** Aynı payload → `{"parsed":true,"value":"order total %{7*7}"}` — ifade **yorumlanmadı**, düz veri olarak işlendi. ✅

## Etki
- **Uzaktan kod çalıştırma (gerçek karşılık):** Saldırgan gömülü ifadeyle sunucuda komut çalıştırır — tam sistem ele geçirme.
- **Bileşen kaynaklı, geniş yüzey:** Ayrıştırıcıya veri ulaştıran her yol (form, header, gövde) potansiyel giriş noktasıdır.

## Remediation Önerisi
> **Ortak gözlem (A03:2025):** Bu senaryoda vulnerable ve fixed sürümlerin uygulama kodu (main.py) neredeyse birebir aynıdır — kusur uygulama mantığında değil, güvenilen bağımlılıkta yaşar. Bu, A03:2025'in temel önermesini somutlaştırır: remediation kod değişikliği değil, bileşenin güvenli/imzalı bir sürüme pinlenmesidir (bkz. sürüm farkları: 2.0.0-fixed, 5.2.1-verified vb.).

`fixed/main.py` uygulama kodunu değiştirmez; düzeltme, ifade değerlendirmesini kaldıran **güvenli `data_parser` sürümüne** geçmektir:

```python
# fixed data_parser v6.4.0-verified
def parse(payload):
    # İfade ayrıştırma/değerlendirme YOK; girdi literal veri olarak döner.
    return {"parsed": True, "value": payload}
```

- **Sürüm pinleme:** Bileşen, ifade değerlendirmesi kaldırılmış güvenli sürüme sabitlenir (Struts'ta yamalı sürüme yükseltme karşılığı).
- **Trusted source + SCA:** Bileşen doğrulanmış depodan kurulur ve `pip-audit`/SCA ile bilinen CVE'lere karşı sürekli taranır.
- **Güvenli ayrıştırma prensibi:** Ayrıştırıcı/deserializer asla girdiyi kod/ifade olarak değerlendirmemeli; yalnızca beklenen veri şemasını okumalıdır.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8081`.
1. Aynı OGNL payload'ını gönder:
   ```
   curl -s -X POST http://127.0.0.1:8081/parse -H "Content-Type: application/json" \
     -d '{"payload": "name=%{7*7}"}'
   ```
   **Beklenen:** `{"parsed": true, "value": "name=%{7*7}"}` — `%{...}` **yorumlanmadan** düz veri olarak döndü; `rce`/`[SİMÜLASYON]` alanı **yok**.
2. `GET /status` → `parser_version` = `6.4.0-verified` (vulnerable'da `2.5.10`).

Vulnerable sürümde RCE'yi tetikleyen aynı girdi, fixed sürümde zararsız bir string olarak işleniyor.

---

## Gerçek Dünyada Tespit / Önleme
Bu senaryo, **bilinen zafiyetli bir bileşenin (ör. eski Struts) güvensiz ifade/deserialization davranışı** durumudur. Savunma katmanları:

- **SCA / `pip-audit` / OWASP Dependency-Check:** Bağımlılıklar bilinen CVE veritabanlarıyla (OSV, NVD) eşlenir; Struts'ın zafiyetli sürümü gibi bileşenler build/CI'da yakalanır ve pipeline kırılır (ASVS V14.2.1). Struts krizinde etkilenenlerin çoğu, savunmasız sürümü envanterlerinde göremeyen ekiplerdi.
- **SBOM + Dependency-Track:** Hangi uygulamada hangi ayrıştırıcı/deserializer bileşeninin hangi sürümde olduğu envanterlenir; yeni bir Struts benzeri CVE çıktığında etkilenen tüm servisler anında listelenir.
- **Sürüm pinleme + güvenli sürüme yükseltme:** Bileşen yamalı/güvenli sürüme yükseltilir ve sürüm pinlenir; "ifade değerlendirme" gibi tehlikeli özellikler kapatılır.
- **İmza & provenance + trusted source:** Bileşen yalnızca doğrulanmış, bakımlı depodan kurulur.
- **Güvenli deserialization prensibi:** Untrusted veri asla ifade/kod olarak değerlendirilmez; katı şema doğrulaması (allow-list) ve güvenli ayrıştırıcılar kullanılır. Bu, bileşen düzeltilse bile derinlemesine savunma sağlar.
- **A03:2025 remediation bağlantısı:** "SCA ile zafiyetli bileşeni tespit et → güvenli sürüme yükselt → sürümü pinle → trusted source'tan kur → SBOM ile sürekli izle." Bileşen kaynaklı RCE'de en etkili tek kontrol, **bilinen zafiyetli sürümü hiç dağıtıma sokmamaktır.**
