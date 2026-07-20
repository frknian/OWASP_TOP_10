# [A06:2025] Insecure Design → Missing Rate Limiting / Bot Protection

**Modül:** 06-insecure-design
**Senaryo:** Sınırlı stoklu bir ürün (ekran kartı, 100 adet) satın alma endpoint'i, tek tek insan alıcılar varsayımıyla tasarlanmıştır. Ne istek frekansı ne de kişi başına satın alma sınırı vardır; tek bir istemci (scalper botu) saniyeler içinde tüm stoğu tüketebilir.
**Portlar:** vulnerable `8180`, fixed `8181`
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

## Bu Kategori Nedir?
Bu kategori bir KOD hatası değil, bir TASARIM/mimari eksikliğidir — düzeltmesi bir satır kod değil, akışın/kuralın yeniden tasarlanmasıdır. Güvensiz parola kurtarma soruları, iş mantığı bypass'ları, bot/rate limiting eksikliği örnektir. Temel korunma: threat modeling, abuse case analizi, secure design patterns.

## CVSS 3.1
- **Skor:** 7.5 (High)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

**Gerekçe:**
- **AV:N / AC:L / PR:N / UI:N** — Uzaktan, kimlik doğrulamasız, basit bir döngüyle; hiçbir özel koşul gerekmez.
- **C:N / I:N** — Veri sızmıyor; kayıtlar da (her satış tek tek meşru biçimde işleniyor) bozulmuyor. Saldırgan hiçbir veriyi izinsiz okumuyor veya değiştirmiyor.
- **A:H** — **Asıl etki erişilebilirlikte:** sınırlı kaynak (stok) tek elde tükendiği için hizmet, hedef kitlesinin tamamı açısından kullanılamaz hale gelir. Ürün "satılmış" görünse de meşru müşteriler için erişilebilirlik tam kaybolmuştur (denial of inventory).

**Not:** Aynı zafiyet, satın alma yerine hesap oluşturma/SMS gönderme gibi maliyetli işlemlerde kullanılırsa doğrudan finansal etki (`I:L`) da eklenir ve skor **8.2**'ye çıkar.

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [x] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V11.1.4:** *"Verify that the application has anti-automation controls to protect against excessive calls such as mass data exfiltration, business logic requests, file uploads or denial of service attacks."*
- **V11.1.3:** İş limitlerinin sunucu tarafında uygulanması.
- **V11.1.5:** Anormal/otomatik aktiviteye karşı uyarı ve tepki mekanizmaları.
- Destekleyici: **V2.2.1** (anti-automation kontrolleri), **V13.2.3** (API rate limiting).
- **CWE-770:** Allocation of Resources Without Limits or Throttling
- **CWE-799:** Improper Control of Interaction Frequency
- Destekleyici: **CWE-837** (Improper Enforcement of a Single, Unique Action)

## Açıklama
```python
# vulnerable/main.py
@app.post("/purchase")
def purchase(req: PurchaseRequest, request: Request):
    # rate limit YOK, kişi başı limit YOK, bot tespiti YOK
    product["stock"] -= req.quantity
    return {"purchased": True, "remaining_stock": product["stock"], ...}
```
Endpoint'in **iş mantığı doğrudur**: stok kontrol ediliyor, eksiltiliyor, tükenince `409` dönüyor. Eksik olan tek şey, tasarım aşamasında sorulmamış bir sorunun cevabı: ***"Bu endpoint insan hızında değil, makine hızında çağrılırsa ne olur?"***

İki ayrı boyut birden eksik:
1. **Etkileşim frekansı (CWE-799):** Aynı istemcinin saniyede kaç istek atabileceğine dair hiçbir sınır yok. Bir insan dakikada belki 2-3 kez "satın al"a basar; bot saniyede yüzlerce istek atar.
2. **Adil kaynak dağıtımı (CWE-770):** Bir istemcinin toplamda kaç adet alabileceğine dair sınır yok. Frekans sınırlansa bile, bot yavaşça tüm stoğu toplayabilir.

Bu iki kontrol **farklı tehditleri** karşılar ve biri diğerinin yerine geçemez — fixed sürümün ikisini birden uygulamasının nedeni budur.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8180`.

1. **Başlangıç stoğunu doğrula:**
   ```
   curl -s -X POST http://127.0.0.1:8180/reset
   curl -s http://127.0.0.1:8180/stock
   ```
   **Beklenen:** `stock: 100`.

2. **Tek istemciden arka arkaya 50 istek (scalper botu simülasyonu):**
   ```
   for i in $(seq 1 50); do
     curl -s -o /dev/null -w "%{http_code} " -X POST http://127.0.0.1:8180/purchase \
       -H "Content-Type: application/json" -d '{"product_id": "gpu-5090", "quantity": 1}'
   done; echo
   ```
   **Beklenen:** 50 isteğin **50'si de `200`** — hiçbiri engellenmiyor, hiç gecikme yok.

3. **Stoğun tek elde toplandığını göster:**
   ```
   curl -s http://127.0.0.1:8180/stock
   ```
   **Beklenen:** `stock: 50`, `per_client: {"127.0.0.1": 50}` — stoğun yarısı tek istemcide.

4. **Stoğu tamamen tüket:**
   ```
   for i in $(seq 1 50); do
     curl -s -o /dev/null -X POST http://127.0.0.1:8180/purchase \
       -H "Content-Type: application/json" -d '{"product_id": "gpu-5090", "quantity": 1}'
   done
   curl -s http://127.0.0.1:8180/stock
   ```
   **Beklenen:** `stock: 0` — **100 adedin tamamı tek istemcide.** Bu noktadan sonra meşru müşteriler `409 Stok tükendi` alır.

5. **Toplu alım tek istekte de mümkün:**
   ```
   curl -s -X POST http://127.0.0.1:8180/reset >/dev/null
   curl -s -X POST http://127.0.0.1:8180/purchase \
     -H "Content-Type: application/json" -d '{"product_id": "gpu-5090", "quantity": 100}'
   ```
   **Beklenen:** Tek istekte 100 adet — `remaining_stock: 0`.

**Test sonucu (curl ile doğrulandı):**

*Vulnerable (8180):*
- **50 isteğin 50'si de geçti:** Arka arkaya 50 `POST /purchase` → **50/50 `200`, 0 reddedildi.** Hiçbir gecikme, throttling veya bot kontrolü devreye girmedi. `GET /stock` → `stock: 50`, `per_client: {"127.0.0.1": 50}`. ✅
- **Stoğun tamamı tek istemcide:** 50 istek daha → `stock: 0`, `per_client: {"127.0.0.1": 100}` — **100 adedin %100'ü tek istemciye gitti.** ✅
- **Meşru müşteri dışlandı:** Bu noktadan sonra normal bir satın alma isteği → **`409` "Stok tükendi"** (denial of inventory). ✅

*Fixed (8181):*
- **Aynı client'tan 8 istek → 2 geçti / 6 reddedildi:**

  | İstek | HTTP | Devreye giren kontrol |
  |---|---|---|
  | 1, 2 | `200` | — (limit içinde) |
  | 3, 4, 5 | **`403`** | Kişi başı tahsis limiti (max 2 adet) |
  | 6, 7, 8 | **`429`** | Rate limit (5 istek / 60 sn) |

  İki kontrolün **sırayla ve bağımsız** devreye girdiği gözlendi: önce adil dağıtım limiti, ardından frekans limiti. ✅
- **`Retry-After` header:** `429` yanıtıyla birlikte `retry-after: 52` döndü — istemciye ne zaman tekrar deneyeceği bildiriliyor. ✅
- **Bot 100 yerine 2 adet alabildi:** `GET /stock` → `stock: 98`, `per_client: {"bot-1": 2}`. ✅
- **Meşru müşteriler etkilenmedi:** `X-Client-Id` ile 3 farklı müşteri (`musteri-a/b/c`) → **üçü de `200`.** Kontroller yalnızca aşırı kullanan istemciyi sınırlıyor. ✅
- **Toplu alım da kapalı:** Tek istekte `quantity: 100` → **`403`** `{"error":"Kişi başı satın alma limiti aşıldı","requested":100,"max_units_per_client":2}` — bot, isteği tekrarlamak yerine büyüterek de limiti aşamıyor. ✅

## Etki
- **Denial of inventory:** Meşru müşteriler ürüne hiç ulaşamaz; ürün saniyeler içinde "tükendi" görünür.
- **Karaborsa / scalping:** Toplanan stok ikincil piyasada kat kat fiyata satılır; değer üreticiden değil müşteriden spekülatöre akar.
- **Marka ve müşteri güveni hasarı:** Her lansmanda aynı deneyimi yaşayan müşteriler markadan uzaklaşır; sosyal medyada itibar krizi oluşur.
- **Altyapı yükü:** Bot trafiği normal trafiğin katlarına çıkarak gerçek DoS'a dönüşebilir; ölçekleme maliyeti artar.
- **Aynı desenin diğer sonuçları:** Sınırsız çağrı imkânı, bu endpoint'te stok tükenmesi; başka endpoint'lerde toplu veri sızdırma (mass scraping), SMS/e-posta maliyet suistimali veya kimlik bilgisi doldurma (credential stuffing) anlamına gelir.

## Remediation Önerisi
```python
# fixed/main.py — iki bağımsız tasarım kontrolü
def _check_rate_limit(client):           # (1) FREKANS: 5 istek / 60 sn, kayan pencere
    times = [t for t in REQUEST_TIMES.get(client, []) if t > now - 60]
    if len(times) >= 5:
        raise HTTPException(429, {...}, headers={"Retry-After": str(retry_after)})

if already + req.quantity > MAX_UNITS_PER_CLIENT:   # (2) ADİL DAĞITIM: kişi başı 2 adet
    raise HTTPException(403, {"error": "Kişi başı satın alma limiti aşıldı", ...})
```
- **(1) Rate limiting:** İstemci başına 60 saniyelik **kayan pencerede** en fazla 5 istek. Aşılırsa `429 Too Many Requests` + `Retry-After` header'ı. Dış bağımlılık yok — zaman damgası listeleriyle in-memory uygulanır.
- **(2) Kişi başı tahsis limiti:** İstemci başına en fazla **2 adet**. Aşılırsa `403`. Bot yavaşlatılsa bile stoğun tek elde toplanmasını engeller.
- **Kontrol sırası önemli:** Rate limit, stok mantığına **girmeden önce** uygulanır — böylece reddedilen istekler iş mantığı ve veritabanı kaynağı tüketmez.
- **İstemci kimliği:** Bu labda IP (test için opsiyonel `X-Client-Id` header'ı ile farklı istemciler simüle edilebilir). Gerçek dağıtımda kimlik doğrulanmış kullanıcı + cihaz parmak izi + IP birleşimi kullanılmalı; tek başına IP, NAT arkasındaki meşru kullanıcıları cezalandırır ve proxy havuzlarıyla atlatılabilir.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8181`.

1. **Kişi başı limit — 3. adet reddedilir:**
   ```
   curl -s -X POST http://127.0.0.1:8181/reset >/dev/null
   for i in 1 2 3; do
     curl -s -o /dev/null -w "istek $i -> %{http_code}\n" -X POST http://127.0.0.1:8181/purchase \
       -H "Content-Type: application/json" -d '{"product_id": "gpu-5090", "quantity": 1}'
   done
   ```
   **Beklenen:** `200`, `200`, **`403`** — "Kişi başı satın alma limiti aşıldı" (max 2 adet).

2. **Rate limit — 6. istek 429:**
   ```
   curl -s -X POST http://127.0.0.1:8181/reset >/dev/null
   for i in $(seq 1 7); do
     curl -s -o /dev/null -w "istek $i -> %{http_code}\n" -X POST http://127.0.0.1:8181/purchase \
       -H "Content-Type: application/json" -d '{"product_id": "gpu-5090", "quantity": 1}'
   done
   ```
   **Beklenen:** İlk 5 istek işlenir (2'si `200`, sonrakiler `403` kişi-başı limitten), **6. ve 7. istek `429`** — frekans sınırı devreye girer.

3. **Toplu alım engellendi:**
   ```
   curl -s -X POST http://127.0.0.1:8181/reset >/dev/null
   curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8181/purchase \
     -H "Content-Type: application/json" -d '{"product_id": "gpu-5090", "quantity": 100}'
   ```
   **Beklenen:** `403` — kişi başı limit (2) aşıldığı için tek istekte 100 adet alınamaz.

4. **Farklı istemciler bağımsız (adil dağıtım çalışıyor):**
   ```
   curl -s -X POST http://127.0.0.1:8181/reset >/dev/null
   for c in musteri-a musteri-b musteri-c; do
     curl -s -o /dev/null -w "$c -> %{http_code}\n" -X POST http://127.0.0.1:8181/purchase \
       -H "Content-Type: application/json" -H "X-Client-Id: $c" \
       -d '{"product_id": "gpu-5090", "quantity": 1}'
   done
   ```
   **Beklenen:** Üçü de `200` — meşru müşteriler etkilenmiyor; stok tek elde toplanmıyor.

---

## Tasarım Kusuru vs Uygulama Hatası
Vulnerable sürümde **eksik olan bir kontrol değil, eksik olan bir gereksinimdir.** Kod, kendisinden isteneni eksiksiz yapıyor: ürünü buluyor, stok kontrol ediyor, düşüyor, kaydediyor. Hiçbir satırda hata yok. Kusur, ürün gereksinimlerinde *"bu endpoint otomatik/toplu kullanılırsa ne olmalı?"* sorusunun hiç sorulmamış olmasıdır.

**Rate limiting'i sonradan "yama" olarak eklemek neden zordur?** Bu, senaryonun asıl dersi:

1. **Mimari genelinde tutarlılık gerektirir.** Tek endpoint'e rate limit eklemek yeterli değildir; saldırgan aynı sonuca ulaştıran korumasız bir başka yolu (farklı endpoint, eski API sürümü, mobil API, GraphQL mutation, toplu/batch endpoint) bulur. Kontrolün *her* giriş noktasında aynı şekilde uygulanması gerekir — bu bir mimari karardır, lokal bir düzeltme değil.
2. **"İstemci kimliği" tanımı bir tasarım sorunudur.** Neye göre sınırlayacağız — IP mi? NAT arkasındaki bir okulun tamamını cezalandırır. Hesap mı? Saldırgan 1000 hesap açar (o zaman hesap açmayı da sınırlamak gerekir → yeni tasarım). Cihaz parmak izi mi? Gizlilik ve doğruluk sorunları. Bu sorunun doğru cevabı uygulamanın kimlik modeline bağlıdır ve **sonradan** verilmesi çok zordur.
3. **Durum (state) paylaşımı gerektirir.** Tek süreçte in-memory sayaç yeterlidir; birden fazla replika/bölgeye ölçeklenen bir sistemde sayaçların paylaşılan bir katmanda (Redis vb.) tutulması gerekir. Bu, dağıtım mimarisini ve bağımlılıkları değiştirir — sonradan eklenmesi altyapı projesi demektir.
4. **İş kararı gerektirir, teknik karar değil.** "Kişi başına 2 adet" limitini geliştirici belirleyemez; bu bir ürün/ticaret kararıdır. Sonradan eklendiğinde meşru kullanıcıları etkileme riski taşıdığı için organizasyonel onay süreci gerekir ve genellikle ertelenir.
5. **Geriye dönük uyumluluk kırar.** Yayında olan bir API'ye limit eklemek, o güne kadar sınırsız çağıran meşru entegrasyonları bozar. Tasarım aşamasında konsaydı hiçbir maliyeti olmayan kontrol, sonradan bir "kırıcı değişiklik" halini alır.

Kısacası: rate limiting **çapraz kesen (cross-cutting) bir mimari kontroldür**. Tasarım aşamasında sistemin geneline yerleştirilmesi ucuz ve doğaldır; üretimde bir endpoint'e yamanması pahalı, eksik ve kırılgandır.

**Threat modeling'de nasıl yakalanırdı:** Her endpoint için sorulması gereken soru — ***"Bu endpoint otomatik/toplu kullanılırsa ne olur?"*** Bu sorunun cevabı "sınırlı bir kaynak tükenir" ise, kaynak tahsis kontrolü **fonksiyonel gereksinim** olarak yazılır. STRIDE'da bu bir **Denial of Service** bulgusudur; ancak buradaki DoS servisi çökertmez, **kaynağı** tüketir — bu yüzden klasik altyapı DoS korumaları (yük dengeleyici, otomatik ölçekleme) hiçbir işe yaramaz, hatta saldırıyı daha verimli hale getirir.

## Gerçek Dünyada Tespit / Önleme
- **Threat modeling — kaynak envanteri:** Tasarımda "sınırlı/pahalı" olan her kaynak (stok, SMS kredisi, e-posta kotası, ödeme çağrısı, hesap oluşturma) listelenir ve her biri için tahsis kontrolü zorunlu tutulur.
- **Anti-automation'ın baseline gereksinim olması:** ASVS V11.1.4 "definition of done"a eklenir; rate limit'siz endpoint tasarımı review'dan geçmez (shift-left).
- **Merkezi uygulama (cross-cutting):** Limit, her endpoint'te elle değil; API gateway / middleware / servis mesh gibi tek bir katmanda tanımlanır. Böylece yeni endpoint'ler otomatik olarak korunur ve unutulma riski kalkar.
- **Katmanlı bot koruması:** Rate limit tek başına yeterli değildir — sıraya alma (waiting room / kuyruk sistemi), yüksek talepli lansmanlarda ön kayıt, cihaz parmak izi, davranışsal analiz ve gerektiğinde CAPTCHA birlikte kullanılır.
- **Abuse case testing:** Kabul testlerine "tek istemci N istek atarsa" senaryosu eklenir; limit değerleri regresyon testiyle korunur (bkz. yukarıdaki doğrulama adımları).
- **Davranışsal izleme ve alarm:** "Tek istemci stoğun %X'ini aldı", "istek/dakika normalin N katı", "satın alma başına oturum süresi insan-dışı kısa" gibi **iş metriği** alarmları kurulur; ASVS V11.1.5 gereği anormallik tespitinde otomatik tepki verilir.
- **Load/stress testinin güvenlik amacıyla kullanımı:** Performans testleri yalnızca "dayanıyor mu?" değil, "sınırsız çağrı iş kurallarını bozuyor mu?" sorusunu da yanıtlayacak şekilde tasarlanır.
