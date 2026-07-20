# [A03:2025] Software Supply Chain Failures → Post-install Worm (Shai-Hulud tarzı)

**Modül:** 03-software-supply-chain-failures
**Senaryo:** Uygulama, ele geçirilmiş `awesome_utils` paketine bağımlıdır. Bu paketin "post-install" zararlı mantığı, uygulama başlangıcında (FastAPI `lifespan`) otomatik çalışır — kullanıcı hiçbir endpoint'e istek atmadan önce bile. Ortam değişkenlerindeki sırları toplar, dışarı sızdırır ve diğer paketlere yayılır ("Shai-Hulud", Eylül 2025 — self-replicating npm worm deseni).
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

> ⚠️ **DEFANGED SIMULATION:** Gerçek ortam değişkeni/token OKUNMAZ (sabit sahte örnekler kullanılır), HİÇBİR dış adrese istek atılmaz, kod kendini KOPYALAMAZ/yaymaz. "Sızdırma" yalnızca **lokal** `exfiltrated_data_demo.txt` dosyasına yazılır ve yayılma yalnızca bir simülasyon metniyle anlatılır. Amaç, post-install worm'un neden bu kadar tehlikeli olduğunu güvenle göstermektir.

## Bu Kategori Nedir?
Uygulamanın kendi kodu güvenli olsa bile, kullandığı bağımlılıklar (kütüphaneler, paketler, build araçları) güvenli olmayabilir. Log4Shell, SolarWinds, npm worm'ları gerçek örneklerdir. Temel korunma: SBOM (Software Bill of Materials), bağımlılık taraması (SCA), imza/provenance doğrulama, sürüm pinleme.

## CVSS 3.1
- **Skor:** 9.8 (Critical) — *simüle edilen gerçek zafiyetin skoru; bu ortamda etki defanged'dır.*
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

**Gerekçe (gerçek karşılık):**
- **AV:N / AC:L** — Zararlı kod, paketi kurup çalıştırmakla otomatik tetiklenir; ağ üzerinden dağıtılan bir bileşendir.
- **PR:N / UI:N** — Kurulum/başlangıçta çalıştığı için ayrıcalık/etkileşim gerekmez.
- **S:C (Scope Changed)** — Worm; toplanan CI/CD ve paket-yayım token'larıyla **başka projelere/paketlere** yayılır — etki, zafiyetli bileşenin güvenlik sınırının ötesine geçer.
- **C:H / I:H / A:H** — Sır sızması (C), zehirli yeniden yayım (I), bağımlılığa güvenen sistemlerin bozulması (A).

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [ ] High
- [x] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V14.2.4:** *"Verify that third party components come from pre-defined, trusted and continually maintained repositories."*
- Destekleyici: **V14.2.6** — build/deploy sürecinde çalıştırılan üçüncü taraf script'lerinin güvenli/kontrollü olması.
- **CWE-1395:** Dependency on Vulnerable Third-Party Component *(ana CWE)*
- Destekleyici konsept: **CWE-506** (Embedded Malicious Code) — pakete gömülü, kurulumda çalışan zararlı yük.

## Açıklama
Uygulama, `awesome_utils`'ı yalnızca import edip başlatır. Ancak ele geçirilmiş paket, uygulama başlar başlamaz (lifespan) kendi post-install/worm mantığını tetikler:

```python
# awesome_utils/__init__.py — run_postinstall() (DEFANGED)
# 1) env'deki sırları topla (burada SAHTE örnekler)
# 2) uzak C2'ye POST et  -> [SİMÜLASYON], hiçbir ağ isteği yok
# 3) diğer paketlere kendini enjekte edip yeniden yayımla -> [SİMÜLASYON], yayılma yok
_DEMO_EXFIL_FILE.write_text(report)   # tek somut çıktı: LOKAL demo dosyası
```

```python
# main.py — lifespan
async def lifespan(app):
    _STARTUP_REPORT["postinstall_output"] = awesome_utils.run_postinstall()  # startup'ta otomatik
    yield
```

**Neden özellikle tehlikeli:** Zararlı davranış bir endpoint çağrısına bağlı değildir; **paketi kurup uygulamayı çalıştırmak yeterlidir.** Toplanan npm/PyPI/CI token'larıyla worm kendini diğer paketlere kopyalayıp yeniden yayımladığı için etki üstel biçimde yayılır (Shai-Hulud'da yüzlerce paket bu şekilde zehirlendi).

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8070`.
```
uvicorn main:app --port 8070
```

1. **Uygulamayı başlat** — daha ilk saniyede, hiçbir istek atmadan, uvicorn console'unda post-install simülasyon çıktısı görünür (`=== [SİMÜLASYON] awesome_utils post-install worm çalıştı ===`).
2. **Lokal demo dosyasının oluştuğunu doğrula:**
   ```
   cat vulnerable/exfiltrated_data_demo.txt
   ```
   **Beklenen:** toplanan (sahte) sırların ve C2 gönderimi + yayılma adımlarının simülasyon dökümü. **Hiçbir dış adrese gidilmedi**, dosya repo içinde kaldı.
3. **`GET /status` ile de görüntüle:**
   ```
   curl -s http://127.0.0.1:8070/status
   ```
   **Beklenen:** `component_version: "5.2.0"` ve `postinstall_simulation` alanında startup'ta çalışan simülasyon metni.

**Test sonucu (curl ile doğrulandı):**
- **Vulnerable (8070):** Uygulama başlar başlamaz (startup side-effect) `exfiltrated_data_demo.txt` **oluştu** — hiçbir endpoint'e istek atılmadan. `GET /status` → `component_version: "5.2.0"`, `postinstall_simulation` alanında sahte sır toplama + C2 gönderimi + yayılma özeti döndü. ✅
- **Fixed (8071):** Startup'ta demo dosyası **oluşmadı**. `GET /status` → `component_version: "5.2.1-verified"`, `postinstall_simulation: null` — temiz, hiçbir side-effect yok. ✅

## Etki
- **Gizli anahtar/token sızması (gerçek karşılık):** AWS, GitHub, npm/PyPI token'ları saldırgana gider.
- **Kendini yayan tedarik zinciri kompromisi:** Çalınan yayım token'larıyla worm başka paketlere bulaşır — **Scope Changed (S:C)**; tek kurbanla sınırlı kalmaz.
- **Kurulum/başlangıçta tetiklenme:** Uygulama mantığına dokunmaya gerek yoktur; kurmak/çalıştırmak yeterlidir.

## Remediation Önerisi
> **Ortak gözlem (A03:2025):** Bu senaryoda vulnerable ve fixed sürümlerin uygulama kodu (main.py) neredeyse birebir aynıdır — kusur uygulama mantığında değil, güvenilen bağımlılıkta yaşar. Bu, A03:2025'in temel önermesini somutlaştırır: remediation kod değişikliği değil, bileşenin güvenli/imzalı bir sürüme pinlenmesidir (bkz. sürüm farkları: 2.0.0-fixed, 5.2.1-verified vb.).

`fixed/main.py` + temiz `awesome_utils` (5.2.1-verified): startup'ta çalışan gizli davranış tamamen yok.

```python
# fixed main.py — lifespan
async def lifespan(app):
    # Başlangıçta zararlı/gizli hiçbir şey çalışmıyor.
    yield

# fixed awesome_utils — otomatik/import-side-effect davranış yok; yalnızca açık çağrı
def healthcheck(): return "awesome_utils ok"
```

- **Trusted/imzalı kaynak:** Bileşen yalnızca doğrulanmış, bakımlı depodan; imza & provenance doğrulanarak kurulur.
- **Post-install script'lerini devre dışı bırakma:** npm'de `--ignore-scripts`, kurulumda otomatik çalışan yükleri engeller; temiz pakette startup side-effect yoktur.
- **Sürüm + hash pinleme:** Sessiz yeniden yayımla zehirlenmiş bir sürümün kuruluma girmesi engellenir.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8071`.
1. Uygulamayı başlat → console'da **hiçbir** post-install/exfil çıktısı yok; `exfiltrated_data_demo.txt` **oluşmaz**.
2. `curl -s http://127.0.0.1:8071/status` → `component_version: "5.2.1-verified"`, `postinstall_simulation: null`.

Vulnerable sürümde başlangıçta otomatik tetiklenen sır toplama/yayılma simülasyonu, fixed sürümde tamamen ortadan kalkıyor — startup temiz.

---

## Gerçek Dünyada Tespit / Önleme
Bu senaryo, **kurulum/başlangıç adımında çalışan, kendini yayan zararlı bir bağımlılık** durumudur. Savunma katmanları:

- **Post-install/lifecycle script kontrolü:** npm kurulumlarında `--ignore-scripts` (ve CI'da varsayılan olarak script çalıştırmama), paketlerin kurulum anında keyfi kod çalıştırmasını engeller. Şüpheli `postinstall` içeren paketler işaretlenir.
- **SBOM + Dependency-Track:** Envanterdeki bileşenlerin sürüm/hash'i izlenir; Shai-Hulud gibi bir kampanyada zehirlenmiş sürümler yayımlandığında etkilenen tüm projeler otomatik alarm verir.
- **SCA / `pip-audit` / OSV taraması:** Bilinen kötü sürümler (IoC olarak yayımlanan zehirli paket sürümleri) CI'da yakalanır; pipeline kırılır.
- **İmza & provenance (SLSA / Sigstore):** Yalnızca beklenen yayıncı imzası ve doğrulanabilir build provenance'ı olan artefaktlar kurulur; ele geçirilmiş yeniden yayımlar reddedilir.
- **Sırların izole edilmesi & rotasyonu:** CI/CD token'ları en az ayrıcalıkla, kısa ömürlü ve build ortamına izole verilir; bir worm ele geçirse bile etki alanı sınırlı olur ve token rotasyonuyla hızla iptal edilir.
- **Sandbox'lı kurulum:** Bağımlılık kurulumu ve build, ağ erişimi kısıtlı/izole ortamda yapılır; bir post-install script'i C2'ye ulaşamaz.
- **A03:2025 remediation bağlantısı:** "Kurulum script'lerini kısıtla → trusted/imzalı kaynak → sürüm+hash pinle → sırları izole et → SBOM ile sürekli izle." Buradaki kritik fark: tehdit, uygulama çalışırken değil **kurulurken/başlarken** tetiklenir.
