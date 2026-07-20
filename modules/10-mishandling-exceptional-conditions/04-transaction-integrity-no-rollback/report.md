# [A10:2025] Mishandling of Exceptional Conditions → İşlem Bütünlüğü (Rollback Eksikliği)

**Modül:** 10-mishandling-exceptional-conditions
**Senaryo:** `POST /transfer` çok adımlı bir para transferi yapar. Gönderenin bakiyesi düşürüldükten **sonra** alıcı doğrulamasında istisna oluşursa, ilk adım geri alınmaz — para gönderenden düşer ama alıcıya ulaşmaz, sistemden **kaybolur**.
**Portlar:** vulnerable `8310`, fixed `8311`
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

## Bu Kategori Nedir?
2025'te eklenen tamamen yeni bir kategori. Uygulamaların beklenmedik/anormal durumlarla (hatalar, timeout'lar, kaynak tükenmesi, eşzamanlı hata koşulları) nasıl başa çıktığıyla ilgilidir. "Fail open" (hata durumunda güvensiz tarafa düşme) vs "fail secure" (güvenli tarafa düşme) ayrımı bu kategorinin kalbidir. Yetersiz kaynak temizliği, DB hatalarının sızdırılması, çok adımlı işlemlerde rollback eksikliği örnektir. Temel korunma: try/finally disiplini, fail-secure-by-default mimari, circuit breaker pattern, atomicity/transaction bütünlüğü.

## CVSS 3.1
- **Skor:** 7.5 (High)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`

**Gerekçe:**
- **AV:N / AC:L / PR:N / UI:N** — Uzaktan, tek istekle, güvenilir şekilde tetiklenir (yalnızca geçersiz bir alıcı hesabı yazmak yeterli).
- **C:N** — Veri okunmaz/sızmaz.
- **I:H** — **Finansal veri bütünlüğü tamamen bozulur:** sistemdeki toplam para azalır, bakiyeler gerçeği yansıtmaz. Bu, mutabakatı (reconciliation) bozan ve düzeltilmesi manuel müdahale gerektiren kalıcı bir tutarsızlıktır.
- **A:N** — Servis çalışmaya devam eder (sessizce yanlış çalışır — bu yüzden daha tehlikelidir).

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [x] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V11.1.x (İş Mantığı):** İş akışlarının bütünlüğü; işlemlerin tutarlı biçimde tamamlanması veya hiç uygulanmaması.
- **V7.4.x:** İstisna işleme; hata durumunda sistemin tutarlı bir duruma dönmesi.
- **CWE-460:** Improper Cleanup on Thrown Exception
- Destekleyici: **CWE-703** (Improper Check or Handling of Exceptional Conditions), **CWE-662** (Improper Synchronization — çok adımlı işlemlerin atomikliği)

## Açıklama
```python
# vulnerable/main.py
# --- ADIM 1: gönderenin bakiyesini düşür (UYGULANDI) ---
ACCOUNTS[req.from_account] -= req.amount

# --- ADIM 2: alıcıyı doğrula (HATA NOKTASI) ---
if req.to_account not in ACCOUNTS:
    # ZAFIYET: istisna fırlıyor ama ADIM 1 GERİ ALINMIYOR
    raise HTTPException(404, f"Alıcı hesap bulunamadı: {req.to_account}")

# --- ADIM 3: alıcının bakiyesini artır (HİÇ ÇALIŞMAZ) ---
ACCOUNTS[req.to_account] += req.amount
```
Kök neden, çok adımlı bir işlemin **atomik olmamasıdır**. Adımlar tek tek uygulanır; ortada bir hata oluştuğunda sistem "yarı uygulanmış" bir durumda kalır.

### ACID ve "Atomicity"
Veritabanı işlemlerinin ACID özelliklerinden ilki **Atomicity (bölünmezlik)**: bir işlem **ya tamamen** uygulanır **ya da hiç** uygulanmaz — arada bir durum olamaz. Klasik örnek tam da budur: para transferi iki yazma işlemi içerir (birinden düş, diğerine ekle) ve bunların **ikisi birden** başarılı olmalıdır.

Bu senaryoda atomicity ihlal edilmiştir:
- Adım 1 kalıcı oldu (para düştü).
- Adım 3 hiç çalışmadı (para eklenmedi).
- Sonuç: `total_balance` başlangıçtaki `1500`'den `1400`'e düştü — **100 TL sistemden kayboldu.**

Gerçek bir veritabanında bu, `BEGIN TRANSACTION` ... `COMMIT`/`ROLLBACK` bloğuyla önlenir; bu labda in-memory state üzerinde aynı semantik elle uygulanmıştır.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8310`.

1. **Başlangıç durumu (tutarlı):**
   ```
   curl -s -X POST http://127.0.0.1:8310/reset
   curl -s http://127.0.0.1:8310/total
   ```
   **Beklenen:** `{"total_balance": 1500.0, "expected_total": 1500.0, "consistent": true, "balances": {"alice": 1000.0, "bob": 500.0}}`

2. **Geçersiz alıcıya transfer dene (hata noktası tetiklenir):**
   ```
   curl -s -X POST http://127.0.0.1:8310/transfer -H "Content-Type: application/json" \
     -d '{"from_account":"alice","to_account":"gecersiz_hesap","amount":100}'
   ```
   **Beklenen:** `404` `"Alıcı hesap bulunamadı: gecersiz_hesap"` — istek başarısız göründü.

3. **Paranın gerçekten kaybolduğunu kanıtla:**
   ```
   curl -s http://127.0.0.1:8310/balance/alice
   curl -s http://127.0.0.1:8310/total
   ```
   **Beklenen:**
   - `alice` bakiyesi **900.0** (1000 değil) — transfer "başarısız" olmasına rağmen **para düştü**.
   - `total_balance: 1400.0`, `consistent: false` — **100 TL sistemden kayboldu**, hiçbir hesaba ulaşmadı.

4. **Tekrarlanabilirlik (kayıp birikir):** Adım 2'yi birkaç kez tekrarlayın → her denemede `alice`'ten 100 TL daha kaybolur. Saldırgan/hatalı istemci bunu tekrarlayarak bakiyeleri sistematik olarak bozabilir.

**Test sonucu (curl ile doğrulandı):**

*Vulnerable (8310):* — başlangıç `total_balance: 1500.0`, `consistent: true`. Geçersiz alıcıya (`gecersiz_hesap`) transfer → `404` (istek "başarısız" göründü), ama `alice` bakiyesi **900.0**'a düştü. Aynı geçersiz transfer **3 kez daha** tekrarlandı: kayıp her denemede birikti — `total_balance` **1500 → 1400 → 1100** oldu (4 denemede toplam 400 TL sistemden kayboldu, `consistent: false`). ✅

*Fixed (8311):* — başlangıç aynı (`total_balance: 1500.0`). Aynı geçersiz transfer → aynı `404` hatası, ama `alice` bakiyesi **1000.0** — **hiç değişmedi** (rollback çalıştı). Aynı deneme 3 kez daha tekrarlandı: `total_balance` her seferinde **1500.0 sabit** kaldı, `consistent: true`. Ardından geçerli bir transfer (`alice`→`bob`, 100) denendi: `200` başarılı, `alice: 900`, `bob: 600`, `total_balance: 1500.0` — commit yolu (happy path) regresyonsuz çalışıyor. ✅

## Etki
- **Finansal veri bütünlüğü kaybı:** Bakiyeler gerçeği yansıtmaz; toplam para azalır. Mutabakat (reconciliation) bozulur ve düzeltme manuel müdahale gerektirir.
- **Sessiz bozulma:** Sistem çalışmaya devam eder ve hata döndürür — kullanıcı "işlem başarısız" mesajı görür ama parası gitmiştir. Tutarsızlık genellikle çok sonra (gün sonu mutabakatında) fark edilir.
- **Kötüye kullanım potansiyeli:** Ters yönlü bir hata noktası (ör. adım 3 çalışıp adım 1 geri alınırsa) **para yaratma**ya bile yol açabilir; her iki yön de kritik finansal hatadır.
- **Genellik:** Aynı desen; stok düşürme + sipariş oluşturma, kredi çekme + kayıt yazma, rezervasyon + ödeme gibi tüm çok adımlı iş akışlarında geçerlidir.

## Remediation Önerisi
```python
# fixed/main.py — atomik işlem
snapshot = dict(ACCOUNTS)          # BEGIN TRANSACTION karşılığı
try:
    ACCOUNTS[req.from_account] -= req.amount        # ADIM 1
    if req.to_account not in ACCOUNTS:              # ADIM 2 (hata noktası)
        raise HTTPException(404, f"Alıcı hesap bulunamadı: {req.to_account}")
    ACCOUNTS[req.to_account] += req.amount          # ADIM 3
except Exception:
    ACCOUNTS.clear(); ACCOUNTS.update(snapshot)     # ROLLBACK — tüm adımlar geri alınır
    raise                                           # istisna yeniden yükseltilir
# buraya yalnızca tüm adımlar başarılıysa ulaşılır  # COMMIT karşılığı
```
- **Atomik işlem (all-or-nothing):** İşlem öncesi durum saklanır; herhangi bir adımda istisna oluşursa tüm değişiklikler geri alınır. Sistem asla "yarı uygulanmış" durumda kalmaz.
- **İstisnanın yeniden yükseltilmesi:** `raise` ile istisna korunur; istemci doğru hata kodunu alır (hata gizlenmez, yalnızca **yan etkisi** temizlenir).
- **Gerçek veritabanında:** `BEGIN` / `COMMIT` / `ROLLBACK` veya ORM transaction context manager'ı (`with db.begin():`) kullanılır — veritabanı atomikliği kendisi garanti eder, elle snapshot gerekmez.
- **Doğrulamayı öne al (defense in depth):** Alıcı hesabın varlığı gibi kontroller, **hiçbir yazma yapılmadan önce** yapılmalıdır; böylece hata noktası işlemin ortasına hiç düşmez. Rollback yine de gereklidir (beklenmeyen hatalar için).
- **Değişmezlik kontrolü (invariant):** Kritik akışlarda işlem sonrası bir doğrulama (`total_balance` sabit mi?) çalıştırılabilir; ihlal durumunda alarm üretilir.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8311`.

1. **Başlangıç durumu:**
   ```
   curl -s -X POST http://127.0.0.1:8311/reset
   curl -s http://127.0.0.1:8311/total
   ```
   **Beklenen:** `total_balance: 1500.0`, `consistent: true`.

2. **Aynı geçersiz transfer denemesi:**
   ```
   curl -s -X POST http://127.0.0.1:8311/transfer -H "Content-Type: application/json" \
     -d '{"from_account":"alice","to_account":"gecersiz_hesap","amount":100}'
   ```
   **Beklenen:** `404` — aynı hata mesajı (davranış değişmedi).

3. **Rollback'in çalıştığını kanıtla:**
   ```
   curl -s http://127.0.0.1:8311/balance/alice
   curl -s http://127.0.0.1:8311/total
   ```
   **Beklenen:**
   - `alice` bakiyesi **1000.0** — **değişmedi**, adım 1 geri alındı.
   - `total_balance: 1500.0`, `consistent: true` — hiç para kaybolmadı.

4. **Başarılı transfer hâlâ çalışıyor (regresyon kontrolü):**
   ```
   curl -s -X POST http://127.0.0.1:8311/transfer -H "Content-Type: application/json" \
     -d '{"from_account":"alice","to_account":"bob","amount":100}'
   curl -s http://127.0.0.1:8311/total
   ```
   **Beklenen:** `200`; `alice: 900`, `bob: 600`, `total_balance: 1500.0`, `consistent: true` — commit yolu doğru çalışıyor.

---

## Gerçek Dünyada Tespit / Önleme
- **Veritabanı transaction'ları:** Çok adımlı yazma işlemleri her zaman tek bir transaction içinde yürütülür (`BEGIN`/`COMMIT`/`ROLLBACK`, ORM'de `with session.begin():`). Atomiklik uygulamaya değil, veritabanına devredilir.
- **Distributed transaction ve Saga pattern:** İşlem birden fazla servise/veritabanına yayıldığında tek bir DB transaction'ı yetmez. İki yaygın yaklaşım:
  - **Two-phase commit (2PC):** Tüm katılımcılar önce "hazır mısın?" diye sorgulanır, sonra hep birlikte commit edilir. Güçlü tutarlılık sağlar ama yavaştır ve koordinatör tek hata noktasıdır.
  - **Saga pattern:** İşlem, her biri kendi lokal transaction'ına sahip adımlara bölünür; bir adım başarısız olursa önceki adımlar için **telafi edici işlemler** (compensating transactions — ör. "parayı geri yatır") çalıştırılır. Mikroservis mimarilerinde standart yaklaşımdır.
- **Idempotency:** Transfer gibi işlemler idempotency key ile korunur; ağ hatası sonrası tekrar denemeler çift işlem yaratmaz.
- **Fault injection testleri:** İşlemin *her adımı arasına* kasıtlı hata enjekte edilerek sistemin tutarlı kaldığı doğrulanır — bu senaryonun kendisi böyle bir testtir.
- **Invariant/mutabakat kontrolleri:** "Toplam bakiye sabit kalmalı" gibi değişmezler periyodik olarak (veya her işlem sonrası) doğrulanır; ihlal anında alarm üretilir (bkz. Modül 09 — alerting).
- **Olay kaydı (event sourcing / audit log):** Bakiye "durum" olarak değil, değişmez olay dizisi olarak tutulursa tutarsızlık hem tespit edilebilir hem yeniden hesaplanabilir hale gelir.

---

> 📘 **Bu, OWASP Top 10 Lab projesinin son modülüdür (10/10).**
