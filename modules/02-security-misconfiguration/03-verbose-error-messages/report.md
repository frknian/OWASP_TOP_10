# [A02:2025] Security Misconfiguration → Verbose Error Messages

**Modül:** 02-security-misconfiguration
**Senaryo:** `GET /api/process/{item_id}` sayısal olmayan input ile yakalanmamış bir `ValueError` fırlatıyor; production'da açık kalmış "debug" davranışını taklit eden bir exception handler, yanıt gövdesinde tam stack trace ve kütüphane sürümlerini istemciye döndürüyor
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed) — Burp Suite görsel kanıtları için bkz. [evidence/](evidence/)

## Bu Kategori Nedir?
Bu kategori kod hatası değil, unutulmuş/varsayılan bırakılmış ayarlardan doğar — kurulum panelleri, açık dizin listeleme, aşırı detaylı hata mesajları, yanlış izin verilmiş depolama. Temel korunma: production ortamını sertleştirme (hardening) checklist'i, gereksiz özellik/endpoint'lerin kaldırılması, güvenli varsayılanlar.

## CVSS 3.1
- **Skor:** 5.3 (Medium)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

**Gerekçe:**
- **AV:N** — Endpoint HTTP üzerinden erişilebilir.
- **AC:L** — Hatayı tetiklemek için tek gereken sayısal olmayan bir `item_id` göndermek (`/api/process/abc`).
- **PR:N** — Anonim; hiçbir ayrıcalık gerekmiyor.
- **UI:N** — Kullanıcı etkileşimi gerekmiyor.
- **S:U** — Etki aynı uygulama sınırında.
- **C:L** — Sızan bilgi stack trace (dosya yolları, iç kod yapısı) ve kütüphane sürümleri; doğrudan kullanıcı verisi değil ama hedefli saldırı için keşif değeri taşıyan gizlilik ihlali.
- **I:N / A:N** — Bilgi ifşası; bütünlük/erişilebilirlik etkisi yok.

## Risk Seviyesi
- [ ] Low
- [x] Medium
- [ ] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V7.4.1:** *"Verify that a generic message is shown when an unexpected or security sensitive error occurs, potentially with a unique ID which support personnel can use to investigate."*
- Destekleyici: **V7.4.3** — *"Verify that a 'last resort' error handler is defined which will catch all unhandled exceptions."*
- **CWE-209:** Generation of Error Message Containing Sensitive Information

## Açıklama
`vulnerable/main.py` içindeki `process_item`, path parametresini `str` olarak alıp doğrudan `int(item_id)`'e veriyor; sayısal olmayan bir değerde `ValueError` fırlar ve yakalanmaz. Uygulama, production'da açık unutulmuş bir debug davranışını taklit eden özel bir handler ile bu hatayı istemciye **tüm iç detaylarıyla** döndürüyor:

```python
@app.exception_handler(Exception)
async def verbose_exception_handler(request, exc):
    return JSONResponse(status_code=500, content={
        "error": str(exc),
        "traceback": traceback.format_exc(),   # dosya yolları, satır no, iç fonksiyonlar
        "dependencies": _dependency_versions(), # fastapi/starlette/pydantic/uvicorn sürümleri
    })
```

Bu bir **Security Misconfiguration**'dır: hata ayıklama çıktısı geliştirme ortamına ait olmalıyken production yanıtında görünüyor. Stack trace iç dosya yollarını ve kod yapısını, sürüm listesi ise bilinen CVE eşlemesi için gereken parmak izini saldırgana veriyor.

## Repro Adımları

**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8030`.
```
uvicorn main:app --port 8030
```

1. **Geçerli (sayısal) istek — beklenen normal davranış:**
   ```
   curl -i http://127.0.0.1:8030/api/process/42
   ```
   **Beklenen:** `200 OK`, `{"item_id": 42, "status": "processed"}`.

2. **Hatayı tetikle (sayısal olmayan input):**
   ```
   curl -i http://127.0.0.1:8030/api/process/abc
   ```
   **Beklenen:** `500` + gövdede tam ifşa:
   ```json
   {
     "error": "invalid literal for int() with base 10: 'abc'",
     "exception_type": "ValueError",
     "traceback": "Traceback (most recent call last): ... /.../vulnerable/main.py, line ...",
     "dependencies": {"fastapi": "0.x.y", "starlette": "0.x.y", "pydantic": "2.x.y", "uvicorn": "0.x.y"}
   }
   ```
   Saldırgan; sunucudaki dosya yollarını, kod yapısını ve tam kütüphane sürümlerini tek istekte elde etti.

## Etki
- **Gizlilik (bilgi ifşası):** Stack trace iç dosya yollarını/kod yapısını, sürüm listesi ise bilinen CVE eşlemesi için gereken parmak izini verir — hedefli exploit seçimini kolaylaştırır.
- **Keşif hızlandırma:** Saldırgan, farklı bozuk girdilerle farklı kod yollarını tetikleyerek uygulamanın iç işleyişini haritalayabilir.

## Remediation Önerisi
`fixed/main.py` içinde uygulanan çözüm: **jenerik (last-resort) exception handler**. Beklenmeyen hata olduğunda istemciye yalnızca ayrıntısız bir mesaj döner; tüm detay sunucu log'una yazılır.

```python
@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    logger.exception("Unhandled error while processing %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
```

- `logger.exception(...)` tam stack trace'i **sunucu console/log'una** yazar (destek/geliştirme için erişilebilir kalır), fakat istemci ayrıntı görmez.
- İsteğe bağlı iyileştirme: yanıta korelasyon için benzersiz bir `error_id` eklenip aynı ID log'a yazılabilir (ASVS V7.4.1) — böylece kullanıcı destek talebinde bu ID'yi verir, detay yine sızmaz.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, ayrı portta (`8031`).

1. `curl -i http://127.0.0.1:8031/api/process/42` → **Beklenen:** `200 OK`, `{"item_id": 42, "status": "processed"}` (meşru davranış korunuyor).
2. `curl -i http://127.0.0.1:8031/api/process/abc` → **Beklenen:** `500` + gövde yalnızca:
   ```json
   {"detail": "Internal server error"}
   ```
   Aynı anda sunucu **console'unda** tam stack trace log'lanır (istemciye gitmez).

Vulnerable sürümde stack trace + sürüm bilgisini sızdıran istek, fixed sürümde jenerik mesaja indirgeniyor; hata ayıklama bilgisi yalnızca sunucu tarafında kalıyor.

### Curl Doğrulama Sonuçları (gerçekleşen)

Vulnerable (`8030`) ve fixed (`8031`) sürümler aynı anda ayağa kaldırılıp aynı bozuk girdi gönderildi:

| İstek | Vulnerable (8030) | Fixed (8031) |
|-------|-------------------|--------------|
| `GET /api/process/abc` | **`500`** — tam stack trace + kütüphane sürümleri response body'sinde | **`500`** — yalnızca `{"detail": "Internal server error"}` |

Vulnerable yanıtı; `ValueError: invalid literal for int() with base 10: 'abc'` mesajını, **tam traceback'i** (sunucudaki mutlak dosya yolları + satır numaraları, örn. `.../vulnerable/main.py, line 40, in process_item`) ve bağımlılık sürümlerini döndürdü:
```json
"dependencies": {"fastapi": "0.139.0", "starlette": "1.3.1", "pydantic": "2.13.4", "uvicorn": "0.51.0"}
```

Fixed yanıtı yalnızca:
```json
{"detail": "Internal server error"}
```

**Sunucu tarafı log doğrulaması (fixed):** İstemci ayrıntı görmezken, fixed sürümün sunucu console'unda tam stack trace ve `Unhandled error while processing GET /api/process/abc` kaydı log'landığı doğrulandı (`logger.exception`). Yani hata ayıklama bilgisi kaybolmuyor — sadece istemciye sızmıyor, ekip tarafında erişilebilir kalıyor.

**Sonuç:** ✅ Verbose error ifşası (stack trace + sürümler) remediation sonrası jenerik mesaja indirgendi; detay yalnızca sunucu log'unda tutuluyor.
