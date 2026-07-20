# [A10:2025] Mishandling of Exceptional Conditions → Veritabanı Hatası Üzerinden Bilgi Sızıntısı

**Modül:** 10-mishandling-exceptional-conditions
**Senaryo:** `GET /api/orders?order_id=...` bozuk girdilerde oluşan **veritabanı hatasının tam metnini** (tablo adı, sütun adları, sorgu yapısı) istemciye döndürür. Saldırgan farklı bozuk girdilerle farklı hatalar tetikleyerek şemayı adım adım haritalar.
**Portlar:** vulnerable `8300`, fixed `8301`
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

## Bu Kategori Nedir?
2025'te eklenen tamamen yeni bir kategori. Uygulamaların beklenmedik/anormal durumlarla (hatalar, timeout'lar, kaynak tükenmesi, eşzamanlı hata koşulları) nasıl başa çıktığıyla ilgilidir. "Fail open" (hata durumunda güvensiz tarafa düşme) vs "fail secure" (güvenli tarafa düşme) ayrımı bu kategorinin kalbidir. Yetersiz kaynak temizliği, DB hatalarının sızdırılması, çok adımlı işlemlerde rollback eksikliği örnektir. Temel korunma: try/finally disiplini, fail-secure-by-default mimari, circuit breaker pattern, atomicity/transaction bütünlüğü.

## CVSS 3.1
- **Skor:** 5.3 (Medium)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

**Gerekçe:**
- **AV:N / AC:L / PR:N / UI:N** — Anonim, tek istekle, güvenilir şekilde tekrarlanabilir.
- **C:L** — Sızan şey doğrudan müşteri verisi değil, **şema/yapı bilgisidir** (tablo/sütun adları, sorgu şekli). Bu bilgi tek başına sınırlı zarar verir; asıl değeri bir sonraki saldırıyı (SQLi, veri hedefleme) hazırlamasıdır.
- **I:N / A:N** — Veri değiştirilmez, hizmet kesilmez.

**Not:** Bu bulgunun gerçek riski **birleşiktir**: keşif zafiyeti olarak, Modül 05/S1'deki (SQL Injection) gibi bir sömürüyü çok daha hızlı ve güvenilir hale getirir. Error-based keşif, saldırganın "kör" denemeler yerine şemayı bilerek hareket etmesini sağlar.

## Risk Seviyesi
- [ ] Low
- [x] Medium
- [ ] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V7.4.1:** *"Verify that a generic message is shown when an unexpected or security sensitive error occurs, potentially with a unique id which support personnel can use to investigate."*
- **V7.4.2 / V7.4.3:** İstisna işleme; hata detaylarının yalnızca sunucu tarafında tutulması.
- **CWE-209:** Generation of Error Message Containing Sensitive Information
- Destekleyici: **CWE-215** (Insertion of Sensitive Information Into Debugging Code), **CWE-200** (Exposure of Sensitive Information)

## Modül 02/S3 ile İlişki
Bu senaryo, **Modül 02 / Senaryo 3 (Verbose Error Messages)** ile aynı temel prensibi (CWE-209) paylaşır ama farklı bir açıdan ele alır:

| | **Modül 02/S3** | **Modül 10/S3 (bu senaryo)** |
|---|---|---|
| Hata kaynağı | Genel uygulama hatası (`ValueError`) | **Veritabanı sorgu hatası** (`sqlite3.Error`) |
| Sızan bilgi | Framework stack trace, kütüphane sürümleri, dosya yolları | **Şema bilgisi**: tablo adı, sütun adları, sorgu yapısı |
| Saldırgan için değeri | Teknoloji/sürüm parmak izi → bilinen CVE araması | **Veri modeli haritası** → hedefli SQLi/veri çekme |
| Vurgu | Tek bir hatanın *ne kadar* şey sızdırdığı | Saldırganın **tekrarlı ve bilinçli** tetiklemeyle bilgi *topladığı* keşif süreci |

Kısaca: oradaki fark *framework/stack trace* bilgisiydi, buradaki fark *şema/sorgu yapısı* bilgisidir ve odak, tek bir sızıntıdan çok **error-based keşif metodolojisidir**.

## Açıklama
```python
# vulnerable/main.py
query = f"SELECT order_id, customer_email, product_name, total_amount FROM customer_orders WHERE order_id = {order_id}"
try:
    rows = conn.execute(query).fetchall()
except sqlite3.Error as e:
    return JSONResponse(500, {
        "db_error": str(e),          # ← sqlite'ın ham mesajı
        "executed_query": query,     # ← sorgu yapısı
    })
```
Saldırgan farklı bozuk girdiler göndererek **farklı hata mesajları** alır ve her mesajdan şemanın bir parçasını öğrenir. Bu, bir **oracle**'dır: uygulama, saldırganın sorularına farklı cevaplar vererek bilgi sızdırır.

Tipik keşif zinciri:
1. Bir harf gönder (`abc`) → `no such column: abc` → *sorgunun WHERE koşulunda sütun karşılaştırması yapıldığı* ve girdinin doğrudan gömüldüğü anlaşılır.
2. Tek tırnak gönder (`'`) → `unrecognized token: "'"` → *sorgunun string olarak birleştirildiği* doğrulanır (SQLi sinyali).
3. Sözdizimini bozan bir ifade gönder (`1 AND`) → `incomplete input` / `near "AND"` → sorgunun tam yapısı görülür.
4. `executed_query` alanı zaten **tablo adını (`customer_orders`) ve tüm seçilen sütunları** açıkça verir.

Birkaç istekte saldırgan; tablo adını, sütun adlarını ve sorgu yapısını öğrenmiş olur — bir sonraki adım hedefli veri çekmedir.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8300`.

1. **Meşru istek (temel davranış):**
   ```
   curl -s "http://127.0.0.1:8300/api/orders?order_id=1"
   ```
   **Beklenen:** `200` — sipariş verisi döner.

2. **Keşif adımı A — harf gönder:**
   ```
   curl -s "http://127.0.0.1:8300/api/orders?order_id=abc"
   ```
   **Beklenen:** `500` + `db_error: "no such column: abc"` + `executed_query` içinde **`FROM customer_orders`** ve tüm sütun adları görünür.

3. **Keşif adımı B — tek tırnak gönder:**
   ```
   curl -s "http://127.0.0.1:8300/api/orders?order_id='"
   ```
   **Beklenen:** `500` + farklı bir hata (`unrecognized token` / `syntax error`) — string birleştirme doğrulanır.

4. **Keşif adımı C — sözdizimi boz:**
   ```
   curl -s "http://127.0.0.1:8300/api/orders?order_id=1%20AND"
   ```
   **Beklenen:** `500` + `incomplete input` benzeri hata — sorgu yapısı hakkında ek bilgi.

5. **Toplanan bilgi:** Bu 3 istekten sonra saldırgan; tablo adını (`customer_orders`), sütunları (`order_id, customer_email, product_name, total_amount`) ve sorgunun string birleştirmeyle kurulduğunu bilir. **Farklı girdiler farklı cevaplar verdiği için keşif mümkün oldu.**

## Etki
- **Şema keşfi:** Tablo/sütun adları ve sorgu yapısı öğrenilir; sonraki saldırılar (SQLi, hedefli veri çekme) çok daha verimli hale gelir.
- **SQLi doğrulaması:** Hata mesajları, enjeksiyonun mümkün olup olmadığını **doğrudan** teyit eder — saldırgan kör deneme yapmak zorunda kalmaz.
- **Hassas alan adlarının ifşası:** `customer_email`, `internal_notes` gibi sütun adları, verinin niteliği hakkında bilgi verir ve saldırganın önceliklerini belirler.

## Remediation Önerisi
```python
# fixed/main.py — iki katman
# KATMAN 1: hata OLUŞMASINI engelle
try:
    parsed_id = int(order_id)
except ValueError:
    _log(f"WARN Invalid order_id format ...")
    raise HTTPException(400, GENERIC_ERROR)          # her zaman aynı mesaj

rows = conn.execute("... WHERE order_id = ?", (parsed_id,))   # parametreli sorgu

# KATMAN 2: hata oluşursa SIZDIRMA
except sqlite3.Error as e:
    _log(f"ERROR sqlite {type(e).__name__}: {e}")    # detay yalnızca SUNUCU log'una
    raise HTTPException(400, GENERIC_ERROR)          # istemciye aynı jenerik mesaj
```
- **Jenerik hata mesajı:** İstemci her bozuk girdide **aynı** yanıtı (`400 "Geçersiz istek"`) alır. Farklı girdiler farklı cevaplar üretmediği için **oracle kapanır** — error-based keşif imkânsız hale gelir.
- **Detay sunucu tarafında:** Hata teşhisi kaybolmaz; tip ve mesaj sunucu log'una yazılır. Modül 09'un prensibiyle tutarlı olarak log'a **müşteri verisi yazılmaz** (yalnızca hata tipi/uzunluk gibi teşhis bilgisi).
- **Girdi doğrulama + parametreli sorgu:** Bozuk değer DB'ye hiç ulaşmaz; hata çoğunlukla *oluşmaz bile*. Bu, sızıntıyı gizlemek yerine kaynağını ortadan kaldırır (ayrıca SQLi'yi de engeller — bkz. Modül 05/S1).
- **Korelasyon kimliği (öneri):** Gerçek sistemlerde jenerik mesaja bir `error_id` eklenir; destek ekibi bu id ile log'daki detayı bulur — kullanıcı deneyimi korunur, bilgi sızmaz.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8301`.

1. **Meşru istek hâlâ çalışıyor:**
   ```
   curl -s "http://127.0.0.1:8301/api/orders?order_id=1"
   ```
   **Beklenen:** `200` — sipariş verisi döner (regresyon yok).

2. **Aynı keşif adımlarının hepsi AYNI yanıtı veriyor:**
   ```
   for v in abc "'" "1 AND" "999999999999999999999"; do
     curl -s -o /dev/null -w "$v -> %{http_code}\n" --get --data-urlencode "order_id=$v" http://127.0.0.1:8301/api/orders
   done
   curl -s --get --data-urlencode "order_id=abc" http://127.0.0.1:8301/api/orders
   ```
   **Beklenen:** Hepsi **`400`** ve gövde her seferinde aynı: `{"detail": "Geçersiz istek"}` — hiçbir şema/sorgu bilgisi yok, girdiler arasında **ayırt edici fark yok**.

3. **Detayın gerçekten loglandığını doğrula:**
   ```
   curl -s http://127.0.0.1:8301/server-log
   ```
   **Beklenen:** `WARN Invalid order_id format ...` satırları — teşhis bilgisi sunucuda mevcut, istemciye hiç dönmedi.

**Test sonucu (curl ile doğrulandı):**

*Vulnerable (8300):* — meşru istek `200` (sipariş verisi). Ardından 3 farklı bozuk girdi, 3 **farklı** ham hata döndü:

| Girdi | `db_error` | Sızan bilgi |
|---|---|---|
| `abc` | `no such column: abc` | Sorgunun sütun karşılaştırması yaptığı |
| `'` | `unrecognized token: "'"` | Sorgunun string birleştirmeyle kurulduğu |
| `1 AND` | `incomplete input` | Sorgunun tam yapısı |

Her yanıtta `executed_query` alanı **`FROM customer_orders`** tablo adını ve tüm sütun adlarını (`order_id, customer_email, product_name, total_amount`) açıkça verdi — şema birkaç istekte haritalandı. ✅

*Fixed (8301):* — meşru istek `200` (regresyon yok). Aynı 3 girdi + ek girdilerle **6 farklı bozuk değer** (`abc`, `'`, `1 AND`, `999999999999999999999`, `-99999999999999999999999`, `1.5`) test edildi; **hepsi birebir aynı** `400 {"detail":"Geçersiz istek"}` yanıtını verdi — girdiler arasında ayırt edici hiçbir fark yok, oracle tamamen kapalı. `GET /server-log` ile detayların (`WARN Invalid order_id format ...`) sunucu tarafında loglandığı, istemciye hiç dönmediği doğrulandı. ✅

> **Not:** Test sırasında ek bir edge case bulundu ve düzeltildi: çok büyük tam sayı girdisi (int64 sınırını aşan) SQLite'ta OverflowError'a yol açıyordu, bu sqlite3.Error değil genel Exception olarak fırlıyordu ve orijinal except bloğu bunu yakalamıyordu — farklı bir yanıt (500) dönerek oracle'ı kısmen açık bırakıyordu. `except Exception`'a genişletilip ek int64 aralık kontrolü eklenerek düzeltildi.

---

## Gerçek Dünyada Tespit / Önleme
- **Merkezî hata yakalayıcı (global exception handler):** Uygulama genelinde tek bir handler tüm beklenmeyen istisnaları yakalar, jenerik yanıt döner ve detayı `error_id` ile loglar — her endpoint'te elle yapılmaz.
- **Production'da debug kapalı:** Framework debug modu, ayrıntılı hata sayfaları ve DB sürücü hata aktarımı üretimde kapatılır (bkz. Modül 02/S3).
- **Fault injection testleri:** Bozuk girdilerle hata yolları kasıtlı tetiklenir ve **yanıt gövdelerinin ayırt edilemez olduğu** doğrulanır (oracle testi).
- **DAST / otomatik tarama:** Tarayıcılar farklı girdilere farklı hata yanıtları arayarak bu sınıfı bulur; CI'a eklenerek regresyon önlenir.
- **Saldırgan davranışı tespiti:** Aynı istemciden kısa sürede çok sayıda `4xx/5xx` üreten istek (keşif imzası) alarm üretmelidir (bkz. Modül 09 — alerting).
- **En az bilgi ilkesi:** Hata yanıtları yalnızca kullanıcının düzeltebileceği kadar bilgi verir; sistemin iç yapısına dair hiçbir şey söylemez.

---

> 📘 **Bu, OWASP Top 10 Lab projesinin son modülüdür (10/10).**
