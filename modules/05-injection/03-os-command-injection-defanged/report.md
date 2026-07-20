# [A05:2025] Injection → OS Command Injection (DEFANGED)

**Modül:** 05-injection
**Senaryo:** `POST /diagnose`, gelen `domain` değerini bir kabuk komutuna (`nslookup {domain}`) string olarak gömer. Girdi kabuk tarafından yorumlanacağından, `;` `|` `&&` gibi metakarakterlerle saldırgan ek komut çalıştırabilir (örn. `example.com; cat /etc/passwd`).
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

> ⚠️ **DEFANGED SIMULATION:** Komut GERÇEKTE çalıştırılmaz (`os.system`/`subprocess` yok). Vulnerable sürüm yalnızca oluşan tam komut string'ini `"[SİMÜLASYON] Bu komut çalıştırılırdı: ..."` olarak döndürür. Amaç, enjeksiyonun kabuğa nasıl bir komut ürettiğini güvenle göstermektir.

## Bu Kategori Nedir?
Kullanıcı girdisinin, veri yerine KOD olarak yorumlanmasıyla oluşur — SQL, komut, XSS hepsi bu ailenin üyesidir (2025'te XSS bu kategoriye dahil edildi). Temel korunma: parametreli sorgular, allowlist input validation, çıktı bağlamına uygun encoding, ORM'lerin DOĞRU kullanımı.

## CVSS 3.1
- **Skor:** 9.8 (Critical) — *simüle edilen gerçek zafiyetin skoru; bu ortamda etki defanged'dır.*
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Gerekçe (gerçek karşılık):** OS command injection uzaktan, anonim, tek istekle sunucuda keyfi komut çalıştırmaya (RCE) yol açar → tam gizlilik/bütünlük/erişilebilirlik kaybı.

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [ ] High
- [x] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V5.2.5:** *"Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding."*
- Destekleyici: **V5.1.3/V5.1.4** — girdi allowlist doğrulaması ve tip/aralık kontrolü.
- **CWE-78:** Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)

## Açıklama
```python
# vulnerable/main.py
command = f"nslookup {req.domain}"   # domain = kullanıcı girdisi
# (DEFANGED) gerçekte subprocess(command, shell=True) çalıştırılırdı
```
`domain = "example.com; cat /etc/passwd"` → oluşan komut:
```
nslookup example.com; cat /etc/passwd
```
Kabuk `;` ile iki komutu ardışık çalıştırır: ikinci komut saldırgan kontrolündedir. Kök neden, kullanıcı girdisinin *veri* olması gerekirken *kabuk komutunun parçası* olarak ele alınmasıdır.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8140`.
1. **Zararsız domain:**
   ```
   curl -s -X POST http://127.0.0.1:8140/diagnose \
     -H "Content-Type: application/json" -d '{"domain": "example.com"}'
   ```
   **Beklenen:** `built_command` = `nslookup example.com`.
2. **Injection payload'ı:**
   ```
   curl -s -X POST http://127.0.0.1:8140/diagnose \
     -H "Content-Type: application/json" -d '{"domain": "example.com; cat /etc/passwd"}'
   ```
   **Beklenen:** simülasyon mesajında oluşan komut `nslookup example.com; cat /etc/passwd` görünür — gerçek ortamda ikinci komut da çalışırdı.

**Test sonucu (curl ile doğrulandı):**
- **Vulnerable (8140):** `domain="example.com; cat /etc/passwd"` → `[SİMÜLASYON] Bu komut çalıştırılırdı: nslookup example.com; cat /etc/passwd` (+ `built_command` aynısı). Enjekte edilen ikinci komut oluşan string'de görünüyor. ✅
- **Fixed (8141) — enjeksiyon:** Aynı payload → **HTTP 400** `{"detail":"Geçersiz domain: yalnızca [a-zA-Z0-9.-] izinli"}` — metakarakterli girdi allowlist'e takıldı, komut hiç oluşturulmadı. ✅
- **Fixed (8141) — geçerli domain:** `domain="example.com"` → `[GÜVENLİ] Doğrulanmış domain: example.com, komut hiç oluşturulmadı.` ✅

## Etki
- **Uzaktan kod çalıştırma (gerçek karşılık):** Sunucuda keyfi komut → veri sızıntısı, sistem ele geçirme, yatay hareket.
- **Zincirleme:** Elde edilen erişimle diğer iç sistemlere geçiş (S:U modellendi; gerçekte S:C'ye çıkabilir).

## Remediation Önerisi
```python
# fixed/main.py
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.-]+$")   # allowlist
if not _DOMAIN_RE.match(req.domain):
    raise HTTPException(status_code=400, detail="Geçersiz domain")
```
- **Allowlist doğrulama:** Yalnızca beklenen karakter kümesine (`[a-zA-Z0-9.-]`) izin ver; kabuk metakarakterleri (`; | & $ ` boşluk…) baştan reddedilir (400).
- **Kabuğu tamamen atla:** Gerçek dünyada `subprocess.run([...], shell=False)` ile argümanları liste olarak geç — string birleştirme yapma. Mümkünse kabuk yerine kütüphane API'si kullan.
- **En az ayrıcalık:** Süreç düşük yetkiyle çalışsın; komut yürütme gerçekten gerekiyorsa katı sınırlar koy.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8141`.
1. Injection payload'ı:
   ```
   curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8141/diagnose \
     -H "Content-Type: application/json" -d '{"domain": "example.com; cat /etc/passwd"}'
   ```
   **Beklenen:** `400` — metakarakter içeren girdi allowlist'e takıldı, komut hiç oluşturulmadı.
2. Geçerli domain:
   ```
   curl -s -X POST http://127.0.0.1:8141/diagnose \
     -H "Content-Type: application/json" -d '{"domain": "example.com"}'
   ```
   **Beklenen:** `[GÜVENLİ] Doğrulanmış domain: example.com, komut hiç oluşturulmadı.`

---

## Gerçek Dünyada Tespit / Önleme
- **Kabuk kullanımından kaçınma:** `shell=True` ve string komutlar yasaklanır; argüman-listesi + `shell=False` standarttır.
- **Girdi allowlist:** Beklenen formata (domain, IP, dosya adı) katı regex/tip doğrulaması; denylist yerine allowlist.
- **SAST:** Bandit (`B602/B605` — shell=True, os.system), Semgrep command-injection kuralları CI'da.
- **En az ayrıcalık + sandbox:** Komut yürüten servisler kısıtlı kullanıcı/konteyner içinde; çıkışlar loglanır ve izlenir.
