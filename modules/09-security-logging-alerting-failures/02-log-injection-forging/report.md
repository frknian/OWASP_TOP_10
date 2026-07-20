# [A09:2025] Security Logging and Alerting Failures → Log Injection / Forging

**Modül:** 09-security-logging-alerting-failures
**Senaryo:** `POST /report-issue` gelen `message` alanını hiçbir temizlik yapmadan log satırına gömer. Saldırgan `message` içine gerçek bir newline (`\n`) koyarak, log'a sahte ve meşru görünümlü ek satırlar enjekte edebilir (log forging).
**Portlar:** vulnerable `8260`, fixed `8261`
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

> ✅ **Bu senaryo gerçekten çalışır (defanged değil):** Enjekte edilen `\n`, log listesinde ayrı bir kayıt üretir. `GET /logs` ile satır sayısının arttığı ve sahte satırın gerçek bir sistem mesajı gibi durduğu doğrudan görülür.

## Bu Kategori Nedir?
Bir saldırı, fark edilmezse sonsuza kadar sürebilir. Bu kategori, güvenlik olaylarının loglanmaması, loglara hassas veri yazılması, log bütünlüğünün korunmaması (log injection/forging) ve en önemlisi "loglama var ama kimse/hiçbir şey tepki vermiyor" (alerting eksikliği) sorunlarını kapsar. 2021'deki adı "Monitoring"den 2025'te "Alerting"e değişti — vurgu, sadece kayıt tutmaktan aktif tepkiye kaydı. Temel korunma: structured logging, log redaksiyonu, log bütünlüğü koruması, eşik-tabanlı alerting, SIEM entegrasyonu.

## CVSS 3.1
- **Skor:** 5.3 (Medium)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`

**Gerekçe:**
- **AV:N / AC:L / PR:N / UI:N** — Anonim, tek istekle; herhangi bir "sorun bildir" formu bu yüzeyi açar.
- **I:L** — Log'un bütünlüğü bozulur: sahte kayıtlar eklenir. Etki "Low" çünkü uygulamanın *çekirdek* verisini değil, log kaydını hedefler — ama adli analiz ve tespit süreçleri buna güvendiğinden dolaylı etkisi büyüktür (aşağıda "Etki").
- **C:N / A:N** — Doğrudan veri okuma veya hizmet kesintisi yok.

**Not:** Log injection genelde daha büyük bir saldırının **örtbas/yanıltma** bileşenidir; tek başına düşük skorlu görünse de, bir olay müdahalesini (IR) saptırma değeri yüksektir.

## Risk Seviyesi
- [ ] Low
- [x] Medium
- [ ] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V8.3.x / Logging:** Log kayıtlarının bütünlüğü; kullanıcı girdisinin loglara güvenli şekilde yazılması (kontrol karakterlerinin nötralize edilmesi).
- **CWE-117:** Improper Output Neutralization for Logs
- Destekleyici: **CWE-93** (Improper Neutralization of CRLF Sequences), **CWE-116** (Improper Encoding or Escaping of Output)

## Açıklama
```python
# vulnerable/main.py
_log(f"INFO User {req.username} reported: {req.message}")
# _log, gelen string'i "\n" ile bölüp her parçayı AYRI log kaydı olarak ekliyor
# (gerçek log dosyası davranışı). message içindeki gerçek \n → yeni log satırı.
```
Log injection, kullanıcı girdisindeki kontrol karakterlerinin (özellikle `\n`/`\r`) log'a yazılmadan önce nötralize edilmemesidir. Log satırları newline ile ayrıldığından, girdiye gömülen gerçek bir newline, log'da **yeni bir satır** açar. Saldırgan bu satırın ardına, sistemin ürettiğine benzeyen sahte bir kayıt yazabilir:

```
message = "mesajım\n2025-01-01T00:00:00Z [ADMIN] alice tarafından yetkilendirme onaylandı: yetki=admin"
```
Bu, log'da iki ayrı satır oluşturur; ikincisi, gerçek bir yönetici işlemi kaydı gibi görünür. Bir analist veya SIEM kuralı bu satırı meşru sanabilir.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8260`.

1. **Önce normal bir bildirim (temel satır sayısını gör):**
   ```
   curl -s -X POST http://127.0.0.1:8260/report-issue -H "Content-Type: application/json" \
     -d '{"username":"attacker","message":"her sey yolunda"}'
   curl -s http://127.0.0.1:8260/logs
   ```

2. **Log forging — message içine gerçek newline + sahte kayıt enjekte et:**
   ```
   curl -s -X POST http://127.0.0.1:8260/report-issue -H "Content-Type: application/json" \
     -d '{"username":"attacker","message":"mesajim\n[ADMIN] alice tarafindan yetki onaylandi: yetki=admin"}'
   curl -s http://127.0.0.1:8260/logs
   ```
   **Beklenen:** `count` iki artar (bir istek → iki log satırı). `log_lines` içinde sahte satır (`... [ADMIN] alice tarafindan yetki onaylandi: yetki=admin`) ayrı, meşru görünümlü bir kayıt olarak durur. **JSON body'de `\n` gerçek bir newline'a çevrilir**, bu yüzden enjeksiyon çalışır.

**Test sonucu (curl ile doğrulandı — gerçek `\n` karakteri içeren payload):**

Payload (her iki sürüme de aynısı gönderildi):
```json
{"username":"bob","message":"sorun var\n[ADMIN] bob tarafından yetkilendirme onaylandı: yetki=admin"}
```

*Vulnerable (8260):* — normal bir mesajla `count: 1` iken, forging payload'ı sonrası **`count: 3`** (tek istek **iki** log satırı üretti):
```
2026-07-20T09:46:25Z INFO User bob reported: her sey yolunda
2026-07-20T09:46:25Z INFO User bob reported: sorun var
2026-07-20T09:46:25Z [ADMIN] bob tarafından yetkilendirme onaylandı: yetki=admin
```
Sahte `[ADMIN]` kaydı **kendi zaman damgasıyla ayrı bir satır** olarak duruyor — gerçek bir sistem mesajından ayırt edilemez. ✅

*Fixed (8261):* — normal mesajla `count: 1` iken, **aynı** payload sonrası **`count: 2`** (tek istek → **tek** satır):
```
2026-07-20T09:46:39Z INFO User bob reported: her sey yolunda
2026-07-20T09:46:39Z INFO User bob reported: sorun var\n[ADMIN] bob tarafından yetkilendirme onaylandı: yetki=admin
```
Enjekte edilen `\n` **görünür kaçış karakteri** olarak tek satırda kaldı — sahte kayıt oluşturulamadı. ✅

## Etki
- **Adli analizin yanıltılması:** Saldırgan, gerçek saldırısının izlerini gömmek için sahte "her şey normal" kayıtları ya da yanlış bir kullanıcıyı suçlayan kayıtlar üretebilir.
- **SIEM / log analiz kurallarının kandırılması:** Sahte ama "meşru formatlı" kayıtlar, otomatik korelasyon kurallarını tetikleyebilir veya gerçek alarmları gürültüde boğabilir.
- **Sorumluluk reddi (repudiation):** Log bütünlüğü bozulduğundan, "logda yazıyor" artık güvenilir bir kanıt değildir — olay müdahalesi ve denetim zayıflar.
- **Zincirleme:** Log'lar başka bir sistem tarafından işleniyorsa (ör. HTML rapor üreten bir panel), enjekte edilen içerik ikincil bir XSS/enjeksiyon vektörü olabilir.

## Remediation Önerisi
```python
# fixed/main.py
def sanitize_for_log(value: str) -> str:
    return (value.replace("\\","\\\\").replace("\n","\\n").replace("\r","\\r").replace("\t","\\t"))

safe_msg = sanitize_for_log(req.message)
_log(f"INFO User {safe_user} reported: {safe_msg}")   # \n artık satır AÇMAZ
```
- **Kontrol karakterlerini escape et:** `\n`, `\r`, `\t` görünür kaçış dizilerine (`\\n`...) çevrilir. Enjekte edilen newline artık gerçek satır sonu üretmez; girdi tek bir log satırı içinde, kaçış karakteri olarak kalır.
- **Ters bölü önce kaçırılır:** `\\` → `\\\\` sırası önemlidir; aksi halde saldırgan `\\n` yazıp escape'i atlatabilir.
- **Structured logging (daha güçlü):** Girdi, log satırına string olarak gömülmek yerine ayrı bir alan (JSON değeri) olarak loglanır; alan değerleri satır sonu semantiği taşımaz, forging yapısal olarak imkânsızlaşır.
- **Append-only + imzalı loglar:** Kritik ortamlarda log bütünlüğü, WORM depolama veya hash zincirleme ile korunur — enjekte edilse bile sonradan tespit edilebilir.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8261`.

1. **Aynı forging payload'ı:**
   ```
   curl -s -X POST http://127.0.0.1:8261/report-issue -H "Content-Type: application/json" \
     -d '{"username":"attacker","message":"mesajim\n[ADMIN] alice tarafindan yetki onaylandi: yetki=admin"}'
   curl -s http://127.0.0.1:8261/logs
   ```
   **Beklenen:** `count` yalnızca **bir** artar (bir istek → tek log satırı). Enjekte edilen içerik `... reported: mesajim\n[ADMIN] alice tarafindan...` şeklinde, `\n` **görünür kaçış karakteri** olarak tek satırda kalır — ayrı bir sahte kayıt oluşmaz.

---

## Gerçek Dünyada Tespit / Önleme
- **Structured logging benimsenmesi:** `structlog`, `zap`, `serilog` gibi kütüphanelerle key-value/JSON loglama; kullanıcı girdisi asla log formatının kontrol karakterlerini etkileyemez.
- **Çıktı nötralizasyonu:** Serbest-metin loglama zorunluysa, tüm kullanıcı-kontrollü değerler için merkezi bir `sanitize_for_log` uygulanır (elle değil, logger katmanında).
- **Log bütünlüğü:** WORM/append-only depolama, hash-chain (ör. her satırın önceki satırın hash'ini içermesi) veya imzalı log segmentleri ile forging sonradan tespit edilebilir hale getirilir.
- **SIEM tarafı doğrulama:** Log toplama katmanında beklenmeyen satır kalıpları (ör. bir "report" kaydından sonra gelen "[ADMIN]" satırı) anomali olarak işaretlenir; ham kaynak ile normalize edilmiş kayıt tutarlılığı kontrol edilir.
- **OWASP WSTG / kod review:** Kullanıcı girdisini log'a yazan her nokta, CRLF/kontrol karakteri nötralizasyonu açısından denetlenir (CWE-117 kontrol maddesi).
