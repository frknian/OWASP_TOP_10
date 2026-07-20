# [A02:2025] Security Misconfiguration → Directory Listing → Source Exposure

**Modül:** 02-security-misconfiguration
**Senaryo:** `files/` klasörünü listeleyen bir directory-listing endpoint'i (`GET /files/`) ve klasördeki her dosyayı ham servis eden `GET /files/{filename}`; klasörde unutulmuş `old_admin_utils.py` kaynak dosyası, canlı DB parolasını (hardcoded credential) ve bir IDOR tasarım kusurunu ifşa eden yorumu içeriyor
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed) — Burp Suite görsel kanıtları için bkz. [evidence/](evidence/)

## Bu Kategori Nedir?
Bu kategori kod hatası değil, unutulmuş/varsayılan bırakılmış ayarlardan doğar — kurulum panelleri, açık dizin listeleme, aşırı detaylı hata mesajları, yanlış izin verilmiş depolama. Temel korunma: production ortamını sertleştirme (hardening) checklist'i, gereksiz özellik/endpoint'lerin kaldırılması, güvenli varsayılanlar.

## CVSS 3.1
- **Skor:** 7.5 (High)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

**Gerekçe:**
- **AV:N** — `/files/` ve altındaki dosyalar HTTP üzerinden erişilebilir.
- **AC:L** — Directory listing dosya isimlerini doğrudan verdiği için tahmin/karmaşık koşul gerekmiyor.
- **PR:N** — Anonim erişim; hiçbir hesap/ayrıcalık gerekmiyor.
- **UI:N** — Kullanıcı etkileşimi gerekmiyor.
- **S:U** — Etki aynı uygulama sınırında.
- **C:H** — Sızan içerik yüksek değerli: canlı DB kimlik bilgisi (`root` / `S3cr3t-Pr0d-DB-P@ss!2024`) + kaynak kodu + bir başka endpoint'teki IDOR açığını doğrudan haber veren yorum. Bu, tam gizlilik ihlali ve ileri saldırılar için anahtar niteliğinde.
- **I:N / A:N** — Bu endpoint salt-okunur; doğrudan bütünlük/erişilebilirlik etkisi yok (ancak sızan DB parolası dolaylı olarak bunları da riske atar — bkz. Etki).

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [x] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V14.3.2:** *"...eliminate ... unintended security disclosures."* (Sunucu/framework yapılandırmasının istenmeyen ifşaları engellemesi.)
- Destekleyici: **V14.1.1** — Build/deploy sürecinin güvenli ve tekrarlanabilir olması (geliştirme artıklarının production'a taşınmaması).
- **CWE-548:** Exposure of Information Through Directory Listing
- **CWE-540:** Inclusion of Sensitive Information in Source Code
- **CWE-798:** Use of Hard-coded Credentials

## Açıklama
`vulnerable/main.py` iki ayrı misconfiguration'ı birleştiriyor:

1. **`GET /files/`** — `os.listdir(FILES_DIR)` ile klasörün tüm içeriğini HTML liste olarak dışarıya döküyor. Saldırgan dosya adı tahmin etmeye bile gerek kalmadan `old_admin_utils.py` gibi olması gerekmeyen dosyaları görüyor.
2. **`GET /files/{filename}`** — Klasördeki her dosyayı, tür/whitelist ayrımı yapmadan ham (`PlainTextResponse`) servis ediyor; `.py` kaynak dosyası dahi yorumlanmadan düz metin olarak dönüyor.

Sonuç: `old_admin_utils.py` içeriği okunabiliyor ve iki kritik sır ifşa oluyor:
```python
DB_ADMIN_PASSWORD = "S3cr3t-Pr0d-DB-P@ss!2024"   # canlı DB parolası (CWE-798)
# TODO: account_id sahiplik kontrolü eklenmedi — herkes herkesin hesabını çekebiliyor (IDOR)  (CWE-540)
```

FastAPI'de directory listing varsayılan olarak yoktur; buradaki davranış, gerçek dünyada web sunucusunda `autoindex on` bırakılması veya `StaticFiles` yanlış yapılandırması ile birebir aynı sonucu doğuran, bilinçli olarak yazılmış bir eşdeğerdir.

## Repro Adımları

**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8020`.
```
uvicorn main:app --port 8020
```

1. **Klasörü listele:**
   ```
   curl -i http://127.0.0.1:8020/files/
   ```
   **Beklenen:** `200 OK`, `readme.txt` ve `old_admin_utils.py` linklerini içeren HTML index.

2. **Unutulmuş kaynak dosyasını oku:**
   ```
   curl -i http://127.0.0.1:8020/files/old_admin_utils.py
   ```
   **Beklenen:** `200 OK`, dosyanın ham içeriği — hardcoded `DB_ADMIN_PASSWORD` ve IDOR'u haber veren `# TODO:` yorumu düz metin olarak görünür.

3. **(Kontrast) Masum dosya:**
   ```
   curl -i http://127.0.0.1:8020/files/readme.txt
   ```
   **Beklenen:** `200 OK`, zararsız içerik — sorun dosyaların servisi değil, *ayrımsız* servisi ve listelenmesidir.

## Etki
- **Gizlilik:** Canlı DB kimlik bilgisi sızıyor; saldırgan (ağ erişimi varsa) doğrudan veritabanına bağlanabilir — bu, dolaylı olarak bütünlük ve erişilebilirliği de tehdit eder.
- **Saldırı zinciri:** Kaynak koddaki `# TODO: IDOR` yorumu, uygulamanın *başka* bir endpoint'indeki BOLA açığını saldırgana hazır bilgi olarak verir; keşif maliyetini sıfıra indirir.
- **Saldırı yüzeyi haritalama:** Directory listing, iç dosya adlarını ve proje yapısını ifşa ederek sonraki hedefli saldırıları kolaylaştırır.

## Remediation Önerisi
`fixed/main.py` içinde iki katmanlı düzeltme uygulandı:

1. **`GET /files/` directory-listing endpoint'i tamamen kaldırıldı** — klasör içeriği artık dışarıya listelenmiyor.
2. **Whitelist ile dosya servisi:** `GET /files/{filename}` yalnızca `ALLOWED_FILES = {"readme.txt"}` kümesindeki dosyaları servis ediyor; izinli olmayan hiçbir dosya (örn. `old_admin_utils.py`) dönmüyor.

```python
if filename not in ALLOWED_FILES:
    raise HTTPException(status_code=404, detail="Not found")
```

- Karar, dosya *yolundan* değil sabit izin *kümesinden* verildiği için path traversal (`../`) denemeleri de etkisizdir.
- `old_admin_utils.py` fixed sürümde de diskte bırakıldı: amaç, düzeltmenin "dosyayı sildik" değil "erişimi doğru kısıtladık" olduğunu göstermek. (Pratikte bu dosya webroot'tan da çıkarılmalı ve sızan DB parolası derhal rotasyona alınmalıdır — erişim kontrolü, sırrın hâlâ kodda olması gerçeğini ortadan kaldırmaz.)

### Fixed Version Verification
**Ortam:** `fixed/main.py`, ayrı portta (`8021`).

1. `curl -i http://127.0.0.1:8021/files/` → **Beklenen:** `404 Not Found` (listing endpoint'i yok).
2. `curl -i http://127.0.0.1:8021/files/old_admin_utils.py` → **Beklenen:** `404 Not Found` (whitelist'te değil — dosya diskte olsa bile erişilemez).
3. `curl -i http://127.0.0.1:8021/files/readme.txt` → **Beklenen:** `200 OK` (meşru, izinli dosya çalışmaya devam ediyor).

Vulnerable sürümde canlı DB parolasını ve IDOR yorumunu sızdıran istek, fixed sürümde `404` ile bloke ediliyor; masum dosya ise erişilebilir kalıyor.

### Curl Doğrulama Sonuçları (gerçekleşen)

Vulnerable (`8020`) ve fixed (`8021`) sürümler aynı anda ayağa kaldırılıp test edildi:

| İstek | Vulnerable (8020) | Fixed (8021) |
|-------|-------------------|--------------|
| `GET /files/` | **`200 OK`** — HTML directory index (`old_admin_utils.py`, `readme.txt` linkleri listelendi) | **`404 Not Found`** — listing endpoint'i kaldırıldı |
| `GET /files/old_admin_utils.py` | **`200 OK`** — ham kaynak sızdı: hardcoded `DB_ADMIN_PASSWORD` + IDOR `# TODO` yorumu | **`404 Not Found`** — whitelist dışı; dosya diskte olsa bile erişilemiyor |
| `GET /files/readme.txt` | (erişilebilir) | **`200 OK`** — whitelist'teki meşru dosya çalışmaya devam ediyor |

Vulnerable `GET /files/` gerçek çıktısı:
```html
<h2>Index of /files/</h2><ul><li><a href="/files/old_admin_utils.py">old_admin_utils.py</a></li><li><a href="/files/readme.txt">readme.txt</a></li></ul>
```
Vulnerable `GET /files/old_admin_utils.py` çıktısı, `DB_ADMIN_PASSWORD = "S3cr3t-Pr0d-DB-P@ss!2024"` satırını ve `# TODO: account_id sahiplik kontrolü eklenmedi ... (IDOR)` yorumunu düz metin olarak döndürdü.

**Sonuç:** ✅ Directory listing + serbest dosya servisi, fixed sürümde whitelist ile kapatıldı; `old_admin_utils.py` diskte durmasına rağmen (silinmedi) artık erişilemiyor — remediation'ın "erişimi kısıtla" (silme değil) yaklaşımı doğrulandı. Whitelist'teki `readme.txt` ise meşru şekilde erişilebilir kaldı.

## Ek Not (Scope Dışı) — SQL Injection

`old_admin_utils.py` içindeki `get_account` fonksiyonunda, sorgu Python string formatting ile kuruluyor:
```python
query = "SELECT * FROM users WHERE id = %s" % account_id   # SQL injection'a açık
```
Bu satır **bu senaryonun asıl odağı değildir** — dosya içeriğinin gerçekçiliğini artırmak (bir junior geliştiricinin unuttuğu tipik legacy kod) ve directory listing'in *ne kadar* değerli bilgi sızdırabildiğini göstermek için bilinçli olarak eklendi. String formatting ile kurulan bu sorgu ayrı bir **Injection** zafiyetidir (**A05:2025 — Injection**, `CWE-89`) ve ileride ilgili modülde (parametreli sorgu / prepared statement remediation'ıyla) ele alınacaktır. CLAUDE.md'deki proje kuralı gereği ("yeni bir zafiyet kategorisine geçmeden önce önceki kategori tamamlanmış ve raporlanmış olmalı") bu modülün kapsamı genişletilmemiş, bulgu yalnızca not olarak kayıt altına alınmıştır.
