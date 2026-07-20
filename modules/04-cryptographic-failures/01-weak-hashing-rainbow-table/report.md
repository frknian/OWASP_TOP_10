# [A04:2025] Cryptographic Failures → Weak/Unsalted Password Hashing + Rainbow Table Crack

**Modül:** 04-cryptographic-failures
**Senaryo:** Parolalar tuzsuz ve zayıf/hızlı bir algoritma (MD5) ile hash'lenir. Tuz olmadığı için aynı parola aynı hash'i verir ve MD5 çok hızlı olduğundan önceden hesaplanmış bir sözlük/rainbow table ile hash'ler anında kırılır. Unutulmuş `GET /debug/dump-hashes` endpoint'i tüm hash'leri dışarı vererek saldırıyı önemsizleştirir.
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

> ℹ️ **İZOLE DEMO:** Bu senaryo Modül 01'in kullanıcı sisteminden bağımsızdır; kendi `weak_users.db` / `strong_users.db` dosyalarını kullanır. `crack_demo.py` gerçek bir rainbow table değil, onu küçük ölçekte taklit eden eğitim scriptidir ve yalnızca kendi lokal endpoint'ine istek atar.

## Bu Kategori Nedir?
Hassas verinin (parola, kişisel bilgi, finansal veri) yetersiz korunmasıyla ilgilidir — zayıf/tuzsuz hashing, hardcoded anahtarlar, şifrelenmemiş depolama. Temel korunma: güncel algoritmalar (argon2, AES-GCM), anahtar yönetimi (env/KMS, asla kaynak kodda), veriyi sınıflandırıp gereken her yerde şifreleme.

## CVSS 3.1
- **Skor:** 7.5 (High)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

**Gerekçe:**
- **AV:N** — `GET /debug/dump-hashes` HTTP üzerinden erişilebilir.
- **AC:L / PR:N / UI:N** — Anonim, tek istekle hash'ler alınır; kırma önemsiz maliyetli.
- **C:H** — Tüm kullanıcı parolaları (kimlik bilgisi) ele geçirilir; kimlik hırsızlığı / parola tekrar kullanımıyla yatay yayılma.
- **I:N / A:N** — Doğrudan bütünlük/erişilebilirlik kaybı modellenmiyor (parolaların ele geçmesi sonrası hesap ele geçirme dolaylıdır).

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [x] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V2.4.1:** *"Verify that passwords are stored in a form that is resistant to offline attacks... using an approved key derivation / password hashing function (Argon2, scrypt, bcrypt, PBKDF2)."*
- Destekleyici: **V2.4.5** — her parola için benzersiz **tuz** kullanımı.
- **CWE-327:** Use of a Broken or Risky Cryptographic Algorithm *(MD5)*
- **CWE-759:** Use of a One-Way Hash without a Salt
- **CWE-916:** Use of Password Hash With Insufficient Computational Effort

## Açıklama
`hash_password`, parolayı tuzsuz MD5 ile özetler:
```python
# vulnerable/main.py
def hash_password(plain_password):
    return hashlib.md5(plain_password.encode("utf-8")).hexdigest()  # tuzsuz + hızlı
```
İki bağımsız kusur birleşir:
1. **Tuz yok (CWE-759):** `alice` ve başka bir kullanıcı aynı parolaya sahipse hash'leri birebir aynıdır; saldırgan tek bir önceden hesaplanmış tablo ile hepsini birden çözer.
2. **Zayıf/hızlı algoritma (CWE-327/916):** MD5, saniyede milyarlarca deneme hızındadır; tasarım gereği "yavaş" olması gereken bir parola hash'i için tamamen uygunsuzdur.

`GET /debug/dump-hashes` ise hash'leri kimlik doğrulaması olmadan verir — saldırganın DB'yi ele geçirmesine bile gerek kalmaz.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8090`.
```
uvicorn main:app --port 8090
```

1. **Hash'leri dök (unutulmuş debug endpoint):**
   ```
   curl -s http://127.0.0.1:8090/debug/dump-hashes
   ```
   **Beklenen:** her kullanıcı için `username` + tuzsuz MD5 `password_hash`.

2. **Rainbow table demo ile kır:**
   ```
   python crack_demo.py http://127.0.0.1:8090
   ```
   **Beklenen:** script, gömülü yaygın-parola sözlüğünün MD5'lerini önceden hesaplayıp dökülen hash'lerle eşleştirir ve `123456`, `password`, `qwerty`, `letmein` parolalarını **kırar**. Tuz olmadığı için eşleştirme birebir çalışır.

**Test sonucu (curl ile doğrulandı):**
- **Vulnerable (8090):** `GET /debug/dump-hashes` → 4 kullanıcının tuzsuz MD5 hash'i sızdı (ör. `alice` → `e10adc3949ba59abbe56e057f20f883e`). `crack_demo.py http://127.0.0.1:8090` → `alice=123456`, `bob=password`, `carol=qwerty`, `dave=letmein` → **4/4 kırıldı**. ✅
- **Fixed (8091):** `GET /debug/dump-hashes` → **HTTP 404** (endpoint kaldırılmış). `crack_demo.py http://127.0.0.1:8091` → hash çekilemedi (404) → **0/4 kırıldı**. Hash'ler argon2id (tuzlu) olduğundan MD5 sözlüğüyle zaten eşleşmezdi. ✅

## Etki
- **Toplu kimlik bilgisi ifşası:** Sızan/çözülen parolalar, aynı parolayı başka servislerde kullanan kullanıcılar için hesap ele geçirmeye (credential stuffing) yol açar.
- **Düşük saldırı maliyeti:** Tuzsuz + hızlı hash, offline kırmayı saniyeler mesafesine indirir; debug endpoint'i online erişimi de önemsizleştirir.

## Remediation Önerisi
İki katmanlı düzeltme:
```python
# fixed/main.py
password_hasher = PasswordHasher()          # argon2id
def hash_password(p): return password_hasher.hash(p)   # rastgele tuz + adaptif maliyet
```
- **Algoritma:** MD5 → **argon2id** (alternatif: bcrypt/scrypt/PBKDF2). Kütüphane her hash'e benzersiz, rastgele tuz gömer (CWE-759) ve bellek-zorlu/yavaş çalışır (CWE-916), offline kaba kuvveti ekonomik olmaktan çıkarır.
- **Saldırı yüzeyi:** `/debug/dump-hashes` tamamen kaldırıldı (404) — hash sızdıran yol yok.
- **Doğrulama:** Sabit-zamanlı `verify()` ile parola karşılaştırması.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8091`.
1. Dump endpoint'ini dene:
   ```
   curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8091/debug/dump-hashes
   ```
   **Beklenen:** `404` — endpoint yok, hash'ler dışarı verilmiyor.
2. Aynı crack demo'yu fixed'e karşı çalıştır:
   ```
   python crack_demo.py http://127.0.0.1:8091
   ```
   **Beklenen:** script hash bile çekemez (404) → *"endpoint muhtemelen kaldırılmış"*. Hash'ler elde edilse bile argon2id (tuzlu) olduğundan MD5 sözlüğüyle **hiç eşleşmez** → 0/N kırılır.

Aynı zayıf parolalar (`123456` vb.) vulnerable'da anında kırılırken, fixed'de rainbow table işlevsiz kalır — **zayıf parola ≠ zayıf hash**; doğru hash'leme zayıf parolayı bile offline saldırıya karşı korur.

---

## Gerçek Dünyada Tespit / Önleme
- **Parola hash politikası:** OWASP Password Storage Cheat Sheet — argon2id (veya bcrypt/scrypt/PBKDF2) zorunlu; MD5/SHA-1/düz SHA-256 parola hash'i olarak yasak.
- **Kod tarama (SAST):** `hashlib.md5(...)`/`sha1` parola bağlamında kullanımını yakalayan kurallar (Bandit `B303/B324`, Semgrep crypto kuralları) CI'da çalıştırılır.
- **Migration deseni:** Mevcut zayıf hash'ler, kullanıcı bir sonraki girişte doğru parolayı verdiğinde argon2'ye yeniden hash'lenerek kademeli taşınır (rehash-on-login).
- **Debug/temp endpoint denetimi:** `/debug/*` gibi geçici uçlar üretimde route envanteri + otomatik tarama ile tespit edilip kaldırılır (Modül 02 — Security Misconfiguration ile bağlantılı).
