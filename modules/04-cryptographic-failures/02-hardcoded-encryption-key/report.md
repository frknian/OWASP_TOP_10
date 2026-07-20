# [A04:2025] Cryptographic Failures → Hardcoded Encryption Key

**Modül:** 04-cryptographic-failures
**Senaryo:** Uygulama "özel notları" Fernet ile doğru şekilde şifreler, ancak şifreleme anahtarı kaynak kodun içine gömülüdür. Kaynağa erişen herkes (repo, container image, decompile, ya da `GET /source-leak`) anahtarı elde edip tüm şifreli veriyi çözebilir. Kusur algoritmada değil, **anahtar yönetimindedir**.
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

## Bu Kategori Nedir?
Hassas verinin (parola, kişisel bilgi, finansal veri) yetersiz korunmasıyla ilgilidir — zayıf/tuzsuz hashing, hardcoded anahtarlar, şifrelenmemiş depolama. Temel korunma: güncel algoritmalar (argon2, AES-GCM), anahtar yönetimi (env/KMS, asla kaynak kodda), veriyi sınıflandırıp gereken her yerde şifreleme.

## CVSS 3.1
- **Skor:** 7.5 (High)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

**Gerekçe:**
- **AV:N / AC:L / PR:N / UI:N** — `GET /source-leak` anonim ve tek istekle anahtarı ifşa eder; anahtar elde edilince tüm ciphertext çözülür.
- **C:H** — Şifreli tüm hassas notlar ele geçirilir (şifreleme etkisiz kalır).
- **I:N / A:N** — Doğrudan bütünlük/erişilebilirlik etkisi modellenmiyor (anahtar ele geçince veri değiştirme mümkün olsa da odak gizlilik ihlali).

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [x] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V6.4.1:** *"Verify that a secrets management solution such as a key vault is used to securely create, store, control access to and destroy secrets."*
- Destekleyici: **V6.4.2** — anahtar materyali uygulama kaynak koduna gömülmez.
- **CWE-321:** Use of Hard-coded Cryptographic Key
- **CWE-798:** Use of Hard-coded Credentials

## Açıklama
Şifreleme doğru (Fernet = AES-CBC + HMAC), ama anahtar kaynağa gömülü:
```python
# vulnerable/main.py
_HARDCODED_SECRET = b"hardcoded-demo-key-32-bytes-lo!!"     # kaynakta açıkça duruyor
ENCRYPTION_KEY = base64.urlsafe_b64encode(_HARDCODED_SECRET)
fernet = Fernet(ENCRYPTION_KEY)
```
Simetrik şifrelemenin tüm güvenliği anahtarın gizliliğine bağlıdır (Kerckhoffs ilkesi: algoritma bilinse de anahtar gizli kalmalı). Anahtar kaynakta olduğunda; git geçmişi, container katmanı, yedek veya `GET /source-leak` gibi tek bir sızıntı yolu anahtarı ifşa eder ve şifreleme tamamen değersizleşir. Ayrıca anahtar rotasyonu ancak kod değişikliği + yeniden dağıtımla mümkündür.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8100`.
```
uvicorn main:app --port 8100
```

1. **Bir özel not şifreleyip kaydet:**
   ```
   curl -s -X POST http://127.0.0.1:8100/notes \
     -H "Content-Type: application/json" \
     -d '{"content": "IBAN: TR00 0000 0000 0000 - gizli"}'
   ```
   **Beklenen:** `{"id": 1, "stored_ciphertext": "gAAAAA..."}` — DB'de ciphertext.

2. **Kaynak sızıntısı ile anahtarı keşfet:**
   ```
   curl -s http://127.0.0.1:8100/source-leak | grep _HARDCODED_SECRET
   ```
   **Beklenen:** `_HARDCODED_SECRET = b"hardcoded-demo-key-32-bytes-lo!!"` satırı görünür.

3. **Ele geçirilen anahtarla ciphertext'i bağımsızca çöz** (uygulamaya ihtiyaç yok):
   ```
   python -c "import base64; from cryptography.fernet import Fernet; \
     k=base64.urlsafe_b64encode(b'hardcoded-demo-key-32-bytes-lo!!'); \
     print(Fernet(k).decrypt(b'<adim-1-ciphertext>').decode())"
   ```
   **Beklenen:** düz metin not geri gelir — anahtar bilindiği için şifreleme koruma sağlamadı.

**Test sonucu (curl ile doğrulandı):**
- **Vulnerable (8100):** `GET /source-leak` → kaynak kodu döndü; içinde `_HARDCODED_SECRET = b"hardcoded-demo-key-32-bytes-lo!!"` satırı **açıkça sızdı** — anahtar bu satırdan çıkarılıp tüm ciphertext bağımsızca çözülebilir. ✅
- **Fixed (8101):** `GET /source-leak` → **HTTP 404** (endpoint kaldırılmış). Anahtar zaten kaynakta olmadığından kaynak sızsa bile ciphertext güvende. ✅

## Etki
- **Şifrelemenin tamamen etkisizleşmesi:** Anahtar tek bir kaynak sızıntısıyla ele geçtiğinde geçmiş + gelecek tüm ciphertext çözülür.
- **Rotasyon zorluğu:** Gömülü anahtar, sızma sonrası acil rotasyonu kod dağıtımına bağımlı kılar; olay müdahalesi yavaşlar.

## Remediation Önerisi
```python
# fixed/main.py
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY").encode()   # kaynakta anahtar YOK
fernet = Fernet(ENCRYPTION_KEY)
```
- **Anahtar dışarıda:** Anahtar ortam değişkeninden / gizli yönetim sisteminden (Vault, AWS/GCP KMS, systemd `LoadCredential`, CI secret) yüklenir; kaynak kodda hiç geçmez (ASVS V6.4).
- **Kaynak sızıntısı yüzeyi kapatıldı:** `/source-leak` kaldırıldı; ayrıca kaynak sızsa bile anahtar orada olmadığından ciphertext güvende kalır.
- **Rotasyon:** Anahtar değişimi yalnızca ortam/secret güncellemesiyle yapılır; kod değişmez.
- **Ek:** Anahtarlar secret scanning ile repoya girmeden yakalanır (aşağıya bakınız).

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8101`.

**Kurulum (venv sonrası) — ENCRYPTION_KEY zorunlu:** Fixed sürüm *fail-secure*'dur; anahtar ortam değişkeninden gelmelidir, yoksa startup'ta `RuntimeError` fırlatıp başlamayı reddeder. Önce anahtarı üretip export edin, sonra çalıştırın:
```
export ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
./venv/bin/uvicorn main:app --port 8101
```

0. **Fail-secure kontrolü (anahtarsız başlatma):** `ENCRYPTION_KEY` set edilmeden `uvicorn main:app --port 8101` çalıştırılırsa uygulama ayağa **kalkmaz**; log'da `RuntimeError: ENCRYPTION_KEY environment variable is required ... Refusing to start with an insecure temporary key.` görünür. Bu, env eksikken sessizce geçici anahtarla çalışmanın (güvensiz mod) önüne geçer.

   **Fail-secure test sonucu (doğrulandı):** `ENCRYPTION_KEY` set edilmeden başlatma denemesinde uygulama `RuntimeError: ENCRYPTION_KEY environment variable is required and was not set. Refusing to start with an insecure temporary key.` fırlattı; uvicorn `Application startup failed. Exiting.` ile süreci sonlandırdı ve **port 8101 hiç dinlemeye açılmadı**. Bu, Modül 02'de kurulan fail-secure prensibinin çalışma zamanı kanıtıdır — eksik yapılandırmada güvensiz moda düşmek yerine hiç çalışmama. ✅
1. `/source-leak` artık yok:
   ```
   curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8101/source-leak
   ```
   **Beklenen:** `404`.
2. Not oluştur/oku akışı çalışır (`POST /notes`, `GET /notes/{id}`), ama anahtar hiçbir endpoint'ten veya kaynaktan elde edilemez. `GET /status` → `key_source: "environment-variable"`.

---

## Gerçek Dünyada Tespit / Önleme
- **Secret scanning:** `gitleaks`, `trufflehog`, GitHub Secret Scanning / push protection — anahtar/kimlik bilgisi repoya girmeden (pre-commit + CI) yakalanır.
- **Secret yönetimi:** HashiCorp Vault, AWS/GCP/Azure KMS & Secrets Manager; uygulama anahtarı çalışma anında çeker, diskte/kaynakta tutmaz.
- **Anahtar rotasyonu & envelope encryption:** KMS ile veri-anahtarı (DEK) ana-anahtarla (KEK) sarılır; rotasyon koda dokunmadan yapılır.
- **SAST:** Sabit anahtar/parola atamalarını yakalayan kurallar (Bandit `B105/B106`, Semgrep secrets kuralları) CI'da zorunlu.
- **Sır sızdıran endpoint denetimi:** `/source-leak` gibi kaynak/dosya döken uçlar üretim route envanterinde taranıp kaldırılır (Modül 02 ile bağlantılı).
