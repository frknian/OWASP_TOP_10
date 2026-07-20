# [A04:2025] Cryptographic Failures → Plaintext Sensitive Data at Rest

**Modül:** 04-cryptographic-failures
**Senaryo:** Müşteri kaydındaki hassas kimlik alanı (sahte "TC Kimlik No" benzeri `national_id`) veritabanına düz metin olarak yazılır. Uygulama katmanında erişim kontrolü olsa bile veriyi at-rest koruyan hiçbir şey yoktur: DB dosyasına, yedeğe, disk imajına veya bir SQLi'ye erişen herkes kimlik numaralarını doğrudan okur. `GET /admin/db-dump` verinin düz metin olduğunu kanıtlar.
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

> ℹ️ **Modül içi anlatı bütünlüğü:** Bu senaryonun fixed sürümü, Senaryo 2'de öğrenilen **doğru anahtar yönetimini** (env var'dan yüklenen anahtar) uygular. Yani "veriyi at-rest şifrele" (S3) ile "anahtarı kaynağa gömme" (S2) dersleri birleşerek tam korumayı oluşturur.

## Bu Kategori Nedir?
Hassas verinin (parola, kişisel bilgi, finansal veri) yetersiz korunmasıyla ilgilidir — zayıf/tuzsuz hashing, hardcoded anahtarlar, şifrelenmemiş depolama. Temel korunma: güncel algoritmalar (argon2, AES-GCM), anahtar yönetimi (env/KMS, asla kaynak kodda), veriyi sınıflandırıp gereken her yerde şifreleme.

## CVSS 3.1
- **Skor:** 6.5 (Medium)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

**Gerekçe:**
- **AV:N / AC:L** — `GET /admin/db-dump` üzerinden ya da DB dosyasına erişimle düz metin okunur.
- **PR:L** — Dump ucu bir "admin" yolu olarak modellenir (ya da DB/yedek erişimi gerektirir); tamamen anonim değil.
- **C:H** — Kişisel kimlik verisi (PII) tümüyle ifşa olur.
- **I:N / A:N** — Doğrudan bütünlük/erişilebilirlik etkisi yok.

## Risk Seviyesi
- [ ] Low
- [x] Medium
- [ ] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V6.1.1:** *"Verify that regulated private data ... is stored encrypted while at rest."*
- Destekleyici: **V6.1.3** — hassas verinin sınıflandırılması ve koruma seviyesinin buna göre uygulanması.
- **CWE-311:** Missing Encryption of Sensitive Data
- **CWE-312:** Cleartext Storage of Sensitive Information

## Açıklama
Hassas alan hiçbir dönüşüm olmadan yazılır:
```python
# vulnerable/main.py
conn.execute("INSERT INTO customers (name, national_id) VALUES (?, ?)",
             (customer.name, customer.national_id))   # düz metin at-rest
```
Uygulama çalışırken erişim kontrolü olsa bile, veri **disk üzerinde** korumasızdır. Tehdit modeli uygulama mantığının ötesindedir: çalınan/yanlış yapılandırılan yedek, atılan disk, bulut snapshot'ı, veya veriyi doğrudan sızdıran bir SQLi, tüm `national_id` değerlerini düz metin olarak verir. `GET /admin/db-dump` bu durumu doğrudan gösterir (aynısı `sqlite3 customers_vuln.db "SELECT * FROM customers"` ile de görülür).

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8110`.
```
uvicorn main:app --port 8110
```

1. **Hassas kayıt oluştur:**
   ```
   curl -s -X POST http://127.0.0.1:8110/customers \
     -H "Content-Type: application/json" \
     -d '{"name": "Ayse Yilmaz", "national_id": "12345678901"}'
   ```
   **Beklenen:** `{"id": 1, "name": "Ayse Yilmaz", "national_id": "12345678901"}`.

2. **At-rest veriyi dök — düz metin kanıtı:**
   ```
   curl -s http://127.0.0.1:8110/admin/db-dump
   ```
   **Beklenen:** `rows` içinde `national_id` **düz metin** (`"12345678901"`). Aynı sonuç DB dosyası doğrudan okunarak da alınır:
   ```
   sqlite3 customers_vuln.db "SELECT * FROM customers;"
   ```

**Test sonucu (curl ile doğrulandı):** Kayıt: `{"name":"Ayse Yilmaz","national_id":"12345678901"}`.
- **Vulnerable (8110):** `GET /admin/db-dump` → `national_id` **düz metin** (`"12345678901"`) olarak DB'de duruyor. ✅
- **Fixed (8111):** `GET /admin/db-dump` → alan `national_id_enc` ve **ciphertext** (`"gAAAAABqWNkw..."`, Fernet) olarak saklanıyor; düz metin DB'de yok. ✅
- **Fixed (8111) yetkili çözme:** `GET /customers/1` → `"national_id":"12345678901"` — yalnızca meşru istekte, sunucu tarafında anahtarla çözülüp döndürüldü. ✅

## Etki
- **PII ifşası:** Kimlik numaraları düz metin sızar → kimlik hırsızlığı, dolandırıcılık, mevzuat ihlali (KVKK/GDPR).
- **Geniş tehdit yüzeyi:** Uygulamayı hiç ele geçirmeden, yalnızca bir yedeğe/DB dosyasına/snapshot'a erişim yeterlidir.

## Remediation Önerisi
```python
# fixed/main.py
enc = fernet.encrypt(customer.national_id.encode()).decode()   # at-rest şifreli
conn.execute("INSERT INTO customers (name, national_id_enc) VALUES (?, ?)", (customer.name, enc))
```
- **At-rest şifreleme:** Hassas alan DB'ye yazılmadan Fernet ile şifrelenir; DB'de yalnızca ciphertext durur (CWE-311/312 kapatıldı). Çözme yalnızca yetkili sunucu tarafında, meşru `GET /customers/{id}` isteğinde yapılır.
- **Doğru anahtar yönetimi (S2 dersi):** Anahtar kaynağa gömülmez; `ENCRYPTION_KEY` ortam değişkeninden/secret manager'dan gelir.
- **Katmanlı savunma:** Uygulama-seviyesi şifreleme, disk/DB şifrelemesi (TDE) ve erişim kontrolüyle birlikte kullanılmalı — biri diğerinin yerine geçmez.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8111`.

**Kurulum (venv sonrası) — ENCRYPTION_KEY zorunlu:** Fixed sürüm *fail-secure*'dur (S2 ile aynı prensip); anahtar ortam değişkeninden gelmelidir, yoksa startup'ta `RuntimeError` fırlatıp başlamayı reddeder:
```
export ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
./venv/bin/uvicorn main:app --port 8111
```

0. **Fail-secure kontrolü (anahtarsız başlatma):** `ENCRYPTION_KEY` set edilmeden başlatılırsa uygulama ayağa **kalkmaz**; log'da `RuntimeError: ENCRYPTION_KEY environment variable is required ... Refusing to start with an insecure temporary key.` görünür.

   **Fail-secure test sonucu (doğrulandı):** `ENCRYPTION_KEY` set edilmeden başlatma denemesinde uygulama `RuntimeError: ENCRYPTION_KEY environment variable is required and was not set. Refusing to start with an insecure temporary key.` fırlattı; uvicorn `Application startup failed. Exiting.` ile süreci sonlandırdı ve **port 8111 hiç dinlemeye açılmadı**. Modül 02'nin fail-secure prensibiyle tutarlı çalışma zamanı kanıtı. ✅
1. Aynı kaydı oluştur (`POST /customers`).
2. Dump'ı incele:
   ```
   curl -s http://127.0.0.1:8111/admin/db-dump
   ```
   **Beklenen:** `national_id_enc` alanı **ciphertext** (`gAAAAA...`) — düz metin `national_id` DB'de yok.
3. Meşru okuma çözer:
   ```
   curl -s http://127.0.0.1:8111/customers/1
   ```
   **Beklenen:** `national_id` düz metin döner (yalnızca yetkili sunucu tarafında, anahtarla çözülerek).

Vulnerable'da dump kimlik numarasını düz verirken, fixed'de aynı dump yalnızca şifreli veri gösterir.

---

## Gerçek Dünyada Tespit / Önleme
- **Veri sınıflandırma & envanteri:** PII/regüle veri etiketlenir; her sınıf için at-rest koruma zorunluluğu politika olarak tanımlanır (ASVS V6.1).
- **At-rest şifreleme katmanları:** Uygulama-seviyesi alan şifrelemesi + veritabanı TDE (Transparent Data Encryption) + disk/volume şifreleme; yedekler de şifreli tutulur.
- **DLP / veri tarama:** Depolarda ve yedeklerde düz metin PII arayan tarayıcılar (ör. kimlik no/kart no regex'leri) periyodik çalıştırılır.
- **Anahtar yönetimi:** Şifreleme anahtarları KMS/Vault'ta; rotasyon ve envelope encryption uygulanır (Senaryo 2 ile aynı prensip).
- **En az ayrıcalık + denetim:** `/admin/db-dump` gibi ham veri döken uçlar üretimde kaldırılır veya sıkı yetkilendirme + denetim log'una bağlanır.
