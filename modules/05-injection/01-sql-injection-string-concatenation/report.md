# [A05:2025] Injection → SQL Injection (String Concatenation)

**Modül:** 05-injection
**Senaryo:** `GET /api/accounts?id=...` endpoint'i, kullanıcı girdisini f-string ile doğrudan SQL sorgusuna gömer. Parametreleme olmadığından girdi, verinin değil sorgunun yapısal parçası olarak yorumlanır; `1' OR '1'='1` payload'ı WHERE koşulunu her zaman doğru yapıp tüm hesapları döndürür.
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

## Bu Kategori Nedir?
Kullanıcı girdisinin, veri yerine KOD olarak yorumlanmasıyla oluşur — SQL, komut, XSS hepsi bu ailenin üyesidir (2025'te XSS bu kategoriye dahil edildi). Temel korunma: parametreli sorgular, allowlist input validation, çıktı bağlamına uygun encoding, ORM'lerin DOĞRU kullanımı.

## CVSS 3.1
- **Skor:** 7.5 (High) — *bu endpoint salt-okunur bir SELECT; gerçek SQLi genelde stacked query / yazma ile Critical'e (9.8) çıkar.*
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

**Gerekçe:**
- **AV:N / AC:L / PR:N / UI:N** — HTTP üzerinden, tek istekle, anonim, etkileşimsiz.
- **C:H** — Tablodaki tüm hesapların (isim, e-posta, bakiye) tümü sızabilir.
- **I:N / A:N** — Bu endpoint yalnızca okuma yapar; yazma/silme modellenmedi.

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [x] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V5.3.4:** *"Verify that data selection or database queries use parameterized queries, ORMs, entity frameworks, or are otherwise protected from database injection attacks."*
- Destekleyici: **V5.3.5** — dinamik sorgularda uygun kaçış / parametreleme.
- **CWE-89:** Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)

## Açıklama
Endpoint, girdiyi sorgu metnine gömer:
```python
# vulnerable/main.py
query = f"SELECT id, name, email, balance FROM accounts WHERE id = '{id}'"
rows = conn.execute(query).fetchall()
```
`id = "1' OR '1'='1"` gönderildiğinde oluşan sorgu:
```sql
SELECT ... FROM accounts WHERE id = '1' OR '1'='1'
```
`OR '1'='1'` her satır için doğru olduğundan WHERE filtresi anlamsızlaşır ve **tüm** kayıtlar döner. Sorun, girdinin *veri* olması gerekirken *kod (SQL)* olarak yorumlanmasıdır.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8120`.
```
uvicorn main:app --port 8120
```
1. **Normal istek:**
   ```
   curl -s "http://127.0.0.1:8120/api/accounts?id=1"
   ```
   **Beklenen:** yalnızca id=1 (Alice) döner.
2. **Injection payload'ı** (URL-encode edilmiş `1' OR '1'='1`):
   ```
   curl -s "http://127.0.0.1:8120/api/accounts?id=1%27%20OR%20%271%27%3D%271"
   ```
   **Beklenen:** `results` içinde **tüm** hesaplar (Alice, Bob, Carol) döner; yanıttaki `query` alanı enjekte edilmiş sorguyu gösterir.

**Test sonucu (curl ile doğrulandı):**
- **Vulnerable (8120):** `id=1' OR '1'='1` → `query = SELECT ... WHERE id = '1' OR '1'='1'`; `results` içinde **3 hesap** (Alice/Bob/Carol) döndü — enjeksiyon WHERE filtresini anlamsızlaştırdı. ✅
- **Fixed (8121):** Aynı payload → `query = SELECT ... WHERE id = ?` (parametreli); `results: []` — girdi yalnızca değer olarak bağlandı, hiçbir kayıt eşleşmedi. ✅

## Etki
- **Toplu veri ifşası:** Tek istekle tüm tablo sızar (hesap sahibi, e-posta, bakiye).
- **Eskalasyon potansiyeli:** Gerçek dünyada UNION SELECT ile başka tablolar, stacked query ile yazma/silme, hatta bazı motorlarda komut çalıştırma mümkündür.

## Remediation Önerisi
```python
# fixed/main.py
query = "SELECT id, name, email, balance FROM accounts WHERE id = ?"
rows = conn.execute(query, (id,)).fetchall()
```
- **Parametreli sorgu:** `?` placeholder + değer tuple'ı; sürücü girdiyi yalnızca DEĞER olarak bağlar, asla SQL yapısı olarak yorumlamaz.
- **Ek katmanlar:** en az ayrıcalıklı DB kullanıcısı, girdi tipi doğrulama (id sayısal olmalı), ORM'un parametreli API'lerini kullanma.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8121`.
1. Aynı injection payload'ını gönder:
   ```
   curl -s "http://127.0.0.1:8121/api/accounts?id=1%27%20OR%20%271%27%3D%271"
   ```
   **Beklenen:** `results` **boş** — girdi tam olarak `1' OR '1'='1` string'ine sahip bir id arandı, eşleşen kayıt yok. Payload sorguyu bozamadı.
2. Normal `?id=1` isteği yine yalnızca Alice'i döndürür.

---

## Gerçek Dünyada Tespit / Önleme
- **Parametreli sorgu zorunluluğu:** Kod standardı olarak string concatenation ile sorgu kurmak yasaklanır; yalnızca prepared statement / ORM parametreli API kullanılır.
- **SAST:** Bandit (`B608` — hardcoded SQL string), Semgrep SQL-injection kuralları, CodeQL CI'da string-formatlı sorgu tespit eder.
- **DAST / fuzzing:** sqlmap ve benzeri araçlarla injection noktaları taranır.
- **Savunma katmanları:** En az ayrıcalık (read-only DB kullanıcısı), WAF (ikincil), girdi allowlist/tip doğrulama, hata mesajlarını jenerikleştirme (bkz. Modül 02 — Verbose Errors).
