# [A06:2025] Insecure Design → Business Logic Bypass (Grup Rezervasyonu)

**Modül:** 06-insecure-design
**Senaryo:** Sinema, grup rezervasyonlarını teşvik etmek için "15 kişiye kadar depozito isteme" kuralını koyar. Kural yalnızca *15 ve altı* için tanımlanmıştır; **15'in üstü için hiçbir kural yoktur**. Saldırgan tek istekte 600 koltuğu depozitosuz rezerve edebilir, ya da arka arkaya isteklerle kümülatif olarak salonu doldurabilir.
**Portlar:** vulnerable `8170`, fixed `8171`
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

## Bu Kategori Nedir?
Bu kategori bir KOD hatası değil, bir TASARIM/mimari eksikliğidir — düzeltmesi bir satır kod değil, akışın/kuralın yeniden tasarlanmasıdır. Güvensiz parola kurtarma soruları, iş mantığı bypass'ları, bot/rate limiting eksikliği örnektir. Temel korunma: threat modeling, abuse case analizi, secure design patterns.

## CVSS 3.1
- **Skor:** 8.2 (High)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L`

**Gerekçe:**
- **AV:N / AC:L / PR:N / UI:N** — Tek bir HTTP POST; özel koşul, kimlik doğrulama veya kurban etkileşimi gerekmez. Saldırı %100 güvenilir tekrarlanır.
- **C:N** — Hiçbir veri okunmuyor/sızmıyor; bu bir gizlilik zafiyeti değil.
- **I:H** — Rezervasyon kayıtlarının ve iş kurallarının bütünlüğü tamamen bozuluyor: sistem, gerçekliği yansıtmayan (salon kapasitesini aşan) kayıtlar üretiyor ve depozito kuralı işlevsizleşiyor. Finansal/ticari kayıt bütünlüğü kaybı tam.
- **A:L** — Meşru müşteriler için koltuklar bloke olur (kısmi hizmet kaybı); servisin kendisi ayakta kaldığı için H değil L.

**Not:** Kimlik doğrulaması gerektiren bir gerçek dağıtımda `PR:L` alınırsa skor **7.1 (High)** olur; bu labda endpoint anonim olduğu için PR:N kullanıldı.

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [x] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V11.1.1:** *"Verify that the application will only process business logic flows for the same user in sequential step order and without skipping steps."*
- **V11.1.2:** İş mantığı limitlerinin, gerçekçi insan kullanımına uygun şekilde uygulanması.
- **V11.1.3:** *"Verify the application has business limits and enforces them server-side"* — aşırı/anormal hacimli işlemlerin engellenmesi.
- **V11.1.4:** Otomatik/toplu kullanıma karşı anti-automation kontrolleri.
- **CWE-841:** Improper Enforcement of Behavioral Workflow
- **CWE-770:** Allocation of Resources Without Limits or Throttling
- Destekleyici: **CWE-840** (Business Logic Errors)

## Açıklama
```python
# vulnerable/main.py
deposit_required = False
if req.seats <= FREE_GROUP_LIMIT:      # 15
    deposit_required = False
# (else dalı YOK — asıl tasarım boşluğu burası)

entry["seats"] += req.seats            # kümülatif kontrol yok
                                       # kapasite kontrolü de yok
```
Kod, iş kuralını **yazıldığı gibi** uyguluyor: "15 ve altı depozitosuz." Sorun, kuralın **yarım tasarlanmış** olması. Üç ayrı boşluk var:

1. **Eşiğin üstü tanımsız.** `if seats <= 15` dalının bir `else`'i yok; `deposit_required` her durumda `False` kalıyor. `seats=600` isteği kuralın *dışında* değil, kuralın *hiç düşünülmemiş* bölgesinde. Tasarım toplantısında "ya 600 isterse?" sorusu sorulmamış.
2. **Kümülatif takip yok.** Eşik doğru uygulansa bile, saldırgan 15'er 15'er 100 istek atarak 1500 koltuğa ulaşır — her istek tek başına kurala **uygundur**. Kural "istek başına" tasarlanmış, oysa iş gerçekliği "kullanıcı başına toplam"dır.
3. **Kapasite tavanı yok.** Salon 500 koltukluk olmasına rağmen sistem 600 koltuk onaylıyor; yazılım fiziksel gerçeklikle bağını koparmış durumda (overbooking).

Saldırgan hiçbir noktada **anormal bir istek göndermiyor**: `{"seats": 600}` geçerli JSON, geçerli tip, geçerli aralık (üst sınır tanımlı değil ki). Sunucu her isteği doğru işliyor.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8170`.

1. **Sayaçları sıfırla:**
   ```
   curl -s -X POST http://127.0.0.1:8170/reset
   ```

2. **Normal kullanım (kuralın tasarlandığı happy path):**
   ```
   curl -s -X POST http://127.0.0.1:8170/book \
     -H "Content-Type: application/json" -d '{"username": "normal-user", "seats": 10}'
   ```
   **Beklenen:** `confirmed: true`, `deposit_required: false` — kural doğru çalışıyor.

3. **Tek istekte 600 koltuk (asıl bypass):**
   ```
   curl -s -X POST http://127.0.0.1:8170/book \
     -H "Content-Type: application/json" -d '{"username": "attacker", "seats": 600}'
   ```
   **Beklenen:** `confirmed: true`, `deposit_required: false`, `"600 koltuk depozitosuz rezerve edildi."`, `overbooked: true` (salon kapasitesi 500) — **72.000 TL değerinde koltuk, 0 TL depozitoyla bloke edildi.**

4. **Kümülatif aşındırma (her istek "kurala uygun"):**
   ```
   curl -s -X POST http://127.0.0.1:8170/reset >/dev/null
   for i in $(seq 1 100); do
     curl -s -o /dev/null -X POST http://127.0.0.1:8170/book \
       -H "Content-Type: application/json" -d '{"username": "attacker", "seats": 15}'
   done
   curl -s http://127.0.0.1:8170/bookings
   ```
   **Beklenen:** `total_seats_booked: 1500`, `overbooked: true` — hiçbir istek 15'i aşmadı, hepsi kurala uygundu, sonuç yine felaket.

**Test sonucu (curl ile doğrulandı):**

*Vulnerable (8170):*
- **Tek istekte 600 koltuk:** `{"username":"attacker","seats":600}` → `200` `{"confirmed":true,"deposit_required":false,"deposit_amount":0,"value_locked_tl":72000,"hall_capacity":500,"overbooked":true}` — **600 koltuk sıfır depozitoyla onaylandı**, üstelik salon kapasitesinin (500) üzerinde. ✅
- **Kümülatif aşındırma:** 100 istek × 15 koltuk (her biri "15 ve altı" kuralına **uygun**) → `GET /bookings`: `{"total_seats_booked":1500,"overbooked":true,"per_user":{"attacker":1500}}` — **kapasitenin 3 katı**, hiçbir kural ihlal edilmeden. ✅

*Fixed (8171):*
- **Tek istek tavanı:** `{"seats":600}` → **`400`** *"Tek istekte en fazla 100 koltuk rezerve edilebilir. Daha büyük gruplar için kurumsal satış sürecine yönlendirilirsiniz."* ✅
- **Eşik üstü artık tanımlı:** `{"seats":20}` → **`402`** `{"status":"PENDING_DEPOSIT","free_group_limit":15,"deposit_amount_tl":600.0}` — otomatik onay yok, depozitoya yönlendirildi. ✅
- **Kümülatif limit:** 3 × 15 koltuk → istek 1 `200`, istek 2 `200` (toplam 30), **istek 3 `409`** *"Kümülatif rezervasyon limiti aşıldı"* — "15'er 15'er aşındırma" saldırısı kapandı. ✅
- **Happy path bozulmadı (regresyon):** `{"username":"normal-user","seats":10}` → `200` `{"confirmed":true,"deposit_required":false}` — meşru grup rezervasyonu hâlâ çalışıyor. ✅
- **Kimlik zorunlu:** `{"seats":10}` (username'siz) → **`422`** — kümülatif kuralın bağlanacağı özne olmadan istek kabul edilmiyor. ✅

## Etki
- **Doğrudan gelir kaybı:** Depozitosuz bloke edilen koltuklar gösteri günü boş kalır; bilet geliri ve yan gelirler (büfe vb.) tamamen kaybedilir.
- **Overbooking / itibar hasarı:** Kapasitenin üstünde satış yapılırsa, salona alınamayan müşterilere iade ve tazminat gerekir.
- **Rakip/kötü niyetli sabotaj:** Rakip bir işletme veya trol, sıfır maliyetle bir gösterimi tamamen doldurup meşru satışı engelleyebilir (denial of inventory).
- **Karaborsa:** Toplu bloke edilen koltuklar ikincil piyasada yeniden satılabilir.
- **Tespit gecikmesi:** İstekler "normal" göründüğü için WAF/IDS alarm üretmez; sorun ancak gösteri günü fark edilir.

## Remediation Önerisi
```python
# fixed/main.py — iş kuralı yeniden tasarlandı (üç katman)
if req.seats > MAX_SEATS_PER_REQUEST:                      # (0) mutlak tavan: 100
    raise HTTPException(400, ...)
if entry["seats"] + req.seats > MAX_OPEN_SEATS_PER_USER:   # (b) kümülatif: 30
    raise HTTPException(409, ...)
if total_all + req.seats > HALL_CAPACITY:                  # (c) kapasite: 500
    raise HTTPException(409, ...)
if req.seats > FREE_GROUP_LIMIT:                           # (a) eşik ARTIK TANIMLI
    raise HTTPException(402, {"status": "PENDING_DEPOSIT", "deposit_amount_tl": deposit})
```
- **(a) Eşiğin üstünü tanımla:** `seats > 15` artık **depozito zorunlu**. Rezervasyon otomatik onaylanmaz; `PENDING_DEPOSIT` durumuna düşer ve `402 Payment Required` ile ödemeye yönlendirilir. Depozito = koltuk bedelinin %25'i.
- **(b) Kümülatif limit:** Kullanıcı başına toplam açık rezervasyon **30 koltuk**. "15'er 15'er" aşındırma saldırısı kapanır — kural artık *istek* başına değil *özne* başına.
- **(c) Kapasite tavanı:** Toplam rezervasyon salon kapasitesini (500) aşamaz → overbooking **yapısal olarak imkânsız**.
- **(0) Mutlak üst sınır:** Tek istekte en fazla 100 koltuk; saçma değerler iş akışına hiç girmez, kurumsal satış sürecine yönlendirilir.
- **Kimlik zorunlu kılındı:** `username` artık opsiyonel değil — kümülatif kural bir özneye bağlanamazsa uygulanamaz. Anonim toplu rezervasyon tasarımdan çıkarıldı.
- **Sunucu tarafı zorunluluğu:** Tüm limitler sunucuda uygulanır; istemci tarafı kısıtları yalnızca kullanıcı deneyimi içindir.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8171`.

1. **600 koltuk artık mutlak tavana takılır:**
   ```
   curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8171/book \
     -H "Content-Type: application/json" -d '{"username": "attacker", "seats": 600}'
   ```
   **Beklenen:** `400` — "Tek istekte en fazla 100 koltuk...".

2. **Eşik üstü artık tanımlı — depozitoya yönlendiriliyor:**
   ```
   curl -s -X POST http://127.0.0.1:8171/book \
     -H "Content-Type: application/json" -d '{"username": "attacker", "seats": 20}'
   ```
   **Beklenen:** `402` + `status: PENDING_DEPOSIT`, `deposit_amount_tl: 600.0` — otomatik onay YOK.

3. **Happy path korunuyor (regresyon kontrolü):**
   ```
   curl -s -X POST http://127.0.0.1:8171/book \
     -H "Content-Type: application/json" -d '{"username": "normal-user", "seats": 10}'
   ```
   **Beklenen:** `confirmed: true`, `deposit_required: false` — meşru grup rezervasyonu hâlâ çalışıyor.

4. **Kümülatif aşındırma kapandı:**
   ```
   curl -s -X POST http://127.0.0.1:8171/reset >/dev/null
   for i in 1 2 3; do
     curl -s -o /dev/null -w "istek $i -> %{http_code}\n" -X POST http://127.0.0.1:8171/book \
       -H "Content-Type: application/json" -d '{"username": "attacker", "seats": 15}'
   done
   ```
   **Beklenen:** 1. istek `200`, 2. istek `200` (toplam 30), 3. istek **`409`** — "Kümülatif rezervasyon limiti aşıldı".

5. **Kimlik zorunlu:**
   ```
   curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8171/book \
     -H "Content-Type: application/json" -d '{"seats": 10}'
   ```
   **Beklenen:** `422` — `username` zorunlu alan.

---

## Tasarım Kusuru vs Uygulama Hatası
Bu senaryo, "güvenlik = kötü girdiyi filtrelemek" anlayışının neden yetersiz olduğunun en net örneği.

**Saldırgan uygulamayı KURALLARA UYGUN kullanıyor.** `{"username": "attacker", "seats": 600}` isteğinde:
- Geçerli JSON, geçerli şema, doğru tipler.
- Hiçbir özel karakter, kaçış dizisi, payload yok.
- Hiçbir yetkilendirme kontrolü atlanmıyor.
- Endpoint tam da yapması gereken şeyi yapıyor: koltuk rezerve ediyor.

Bu yüzden **hiçbir teknik savunma katmanı bunu yakalayamaz:**

| Kontrol | Neden yakalayamaz |
|---|---|
| WAF | İstekte imzalanacak bir saldırı deseni yok; `600` sayısı `6`dan farksız görünür |
| Girdi doğrulama | `seats` zaten geçerli bir tamsayı — hangi üst sınır? Bu bir **iş kararı**, teknik kural değil |
| Statik analiz (SAST) | Kodda bug yok; `if seats <= 15` mükemmel derleniyor ve doğru çalışıyor |
| Yetkilendirme kontrolü | Erişim kontrolü ihlali yok; kullanıcı kendi rezervasyonunu yapıyor |
| Kod review | "15 ve altı depozitosuz" gereksinimini doğru uygulamış — kod, spesifikasyona **uygun** |

Kusur koddan **önce**, kuralın kendisinde: "15 kişiye kadar depozito isteme" cümlesi eksik yazılmış bir iş kuralı. `else` dalının olmaması bir yazım hatası değil, **spesifikasyonun kendisindeki boşluğun kodda yansıması**. Geliştirici gereksinimi doğru uyguladı; gereksinim yanlıştı.

**Threat modeling'de nasıl yakalanırdı — abuse case analizi:** Tasarımcılar yalnızca *happy path*'i (bir öğretmen sınıfı için 12 bilet alır) düşünmüş. Abuse case analizi, her iş kuralı için "**kötü niyetli biri bu kuralı sonuna kadar zorlarsa ne olur?**" sorusunu sorar:
- *"seats alanına yazabileceğim en büyük sayı ne?"* → tanımsız → **bulgu**
- *"Bu isteği 1000 kez tekrarlasam?"* → kümülatif kontrol yok → **bulgu**
- *"Salonda olmayan koltuğu satabilir miyim?"* → kapasite kontrolü yok → **bulgu**

Kural şu şekilde yazılsaydı sorun hiç doğmazdı: *"Kullanıcı başına, aynı gösterim için, toplam en fazla 30 koltuk; 15'in üzerindeki her rezervasyon %25 depozito ile onaylanır; toplam rezervasyon salon kapasitesini aşamaz."* Bu, kodun değil **tasarımın** cümlesidir.

## Gerçek Dünyada Tespit / Önleme
- **Abuse case / misuse case analizi:** Her user story'ye eşlik eden bir "abuser story" yazılır: *"Bir spekülatör olarak, tüm koltukları ödemeden bloke etmek istiyorum."* Kabul kriterleri bu senaryoyu engelleyecek şekilde tanımlanır.
- **Threat modeling (STRIDE → Tampering / DoS):** İş akışları veri akış diyagramı üzerinde modellenir; her kaynak tahsisi noktasında "limit kim tarafından, nerede uygulanıyor?" sorusu cevaplanır.
- **İş kurallarının tam tanımlanması:** Her eşik için üç şey zorunlu tutulur: (1) eşiğin altı ne olacak, (2) **eşiğin üstü ne olacak**, (3) kümülatif davranış ne olacak. "else" dalı olmayan iş kuralı, eksik gereksinim sayılır.
- **Secure design pattern — resource limiting:** Kaynak tahsis eden her akış için standart desen: özne başına kota + global kapasite tavanı + mutlak istek tavanı + onay öncesi PENDING durumu.
- **Business logic testing (manuel pentest):** Otomatik tarayıcılar bu sınıfı bulamaz; OWASP WSTG **WSTG-BUSL** serisi (özellikle BUSL-03 Integrity Checks, BUSL-05 Function Limits) manuel test planına eklenir.
- **Davranışsal izleme:** "Tek kullanıcı, tek işlemde kapasitenin %10'undan fazlasını rezerve etti" gibi iş metriği alarmları kurulur — teknik loglar değil, **iş metrikleri** izlenir.
- **Fraud/anomali analizi:** Rezervasyon-gösterim oranı, iptal oranı ve kullanıcı başına ortalama koltuk gibi göstergeler düzenli raporlanır; sapmalar incelenir.
