# [A10:2025] Mishandling of Exceptional Conditions → Fail-Open Kimlik Doğrulama

**Modül:** 10-mishandling-exceptional-conditions
**Senaryo:** `GET /admin/dashboard`, erişim kararı için bir "policy engine" (yetki servisi) çağırır. Servis istisna fırlattığında kod kararı **"izin ver"** olarak verir (fail open) — yetki servisi çöktüğünde kimlik doğrulaması olmayan herkes admin paneline girer.
**Portlar:** vulnerable `8290`, fixed `8291`
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

## Bu Kategori Nedir?
2025'te eklenen tamamen yeni bir kategori. Uygulamaların beklenmedik/anormal durumlarla (hatalar, timeout'lar, kaynak tükenmesi, eşzamanlı hata koşulları) nasıl başa çıktığıyla ilgilidir. "Fail open" (hata durumunda güvensiz tarafa düşme) vs "fail secure" (güvenli tarafa düşme) ayrımı bu kategorinin kalbidir. Yetersiz kaynak temizliği, DB hatalarının sızdırılması, çok adımlı işlemlerde rollback eksikliği örnektir. Temel korunma: try/finally disiplini, fail-secure-by-default mimari, circuit breaker pattern, atomicity/transaction bütünlüğü.

## CVSS 3.1
- **Skor:** 9.1 (Critical)
- **Vektör:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`

**Gerekçe:**
- **AV:N / PR:N / UI:N** — Kesinti anında saldırgan uzaktan, kimlik doğrulamasız, tek istekle admin paneline erişir.
- **AC:H** — Saldırının başarısı, yetki servisinin **erişilemez olduğu** bir zaman penceresine denk gelmeyi gerektirir (saldırganın doğrudan kontrolünde olmayan bir koşul). Not: Bu koşul saldırgan tarafından *tetiklenebiliyorsa* (ör. yetki servisine DoS ile) AC:L olur ve skor **9.8 Critical**'a çıkar — bu, gerçek saldırılarda sık görülen bir zincirdir.
- **C:H / I:H** — Admin paneli tüm kullanıcı verilerine erişim ve sistem ayarlarını değiştirme yetkisi verir.
- **A:N** — Erişilebilirlik doğrudan etkilenmez.

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [ ] High
- [x] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V1.1.x / V1.4.x (Genel Mimari & Erişim Kontrolü Mimarisi):** Güvenlik kontrollerinin merkezî, güvenilir bir noktada ve **güvenli varsayılanla** uygulanması.
- **V4.1.5:** *"Verify that access controls fail securely including when an exception occurs."* — bu senaryonun birebir karşılığı.
- **CWE-636:** Not Failing Securely ('Failing Open')
- Destekleyici: **CWE-703** (Improper Check or Handling of Exceptional Conditions), **CWE-280** (Improper Handling of Insufficient Permissions)

## Açıklama
```python
# vulnerable/main.py
try:
    allowed = policy_engine_check(user)
except PolicyEngineError as e:
    # ZAFIYET (FAIL OPEN): karar verilemiyor → İZİN VER
    return {"access": "granted", "degraded_mode": True, "data": "GİZLİ: admin paneli verileri"}
```

### Fail Open vs Fail Secure
Bir güvenlik kontrolü kararını veremediğinde (bağımlı servis çöktü, zaman aşımı, beklenmeyen istisna) iki olası varsayılan vardır:

| | **Fail Open (fail insecure)** | **Fail Secure (fail closed)** |
|---|---|---|
| Belirsizlikte cevap | "İzin ver" | "Reddet" |
| Kesinti anında sonuç | Erişim kontrolü **devre dışı** | Hizmet kesintisi (herkes reddedilir) |
| Kaybedilen | **Güvenlik** | Kullanılabilirlik |
| Ne zaman doğru? | Yangın kapısı gibi **can güvenliği** sistemlerinde | **Neredeyse tüm** bilgi güvenliği kontrollerinde |

Kritik nokta: Fail-open genellikle kötü niyetle değil, **iyi niyetle** yazılır — "servis çöktü diye kullanıcıları mağdur etmeyelim" refleksiyle. Ancak erişim kontrolünde "bilmiyorum" durumu, **"hayır"** ile eşlenmelidir; aksi halde saldırganın tek yapması gereken, kontrolü *bozmaktır*.

**Gerçek dünya örnekleri:**
- Kimlik doğrulama servisi veritabanına ulaşamayınca, uygulamanın tüm istekleri "doğrulanmış" kabul etmesi.
- LDAP/AD bağlantısı zaman aşımına uğradığında yetki kontrolünün atlanması.
- Lisans/abonelik servisi çöktüğünde tüm premium özelliklerin herkese açılması (güvenlik dışı ama aynı desen).
- WAF/API gateway arka uç sağlık kontrolü başarısız olduğunda trafiği **doğrulamadan** geçirmesi.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8290`.

1. **Normal durumda erişim kontrolü çalışıyor:**
   ```
   curl -s "http://127.0.0.1:8290/admin/dashboard"              # kullanıcı yok
   curl -s "http://127.0.0.1:8290/admin/dashboard?user=alice"   # yetkisiz kullanıcı
   ```
   **Beklenen:** İkisi de `{"access": "denied", ...}` — kontrol düzgün çalışıyor.

2. **Yetki servisi kesintisini tetikle:**
   ```
   curl -s -X POST http://127.0.0.1:8290/simulate-outage
   ```
   **Beklenen:** `{"auth_service_down": true, ...}`

3. **Kesinti sırasında kimlik doğrulamasız erişim (asıl zafiyet):**
   ```
   curl -s "http://127.0.0.1:8290/admin/dashboard"
   ```
   **Beklenen:** **`200`** `{"access": "granted", "degraded_mode": true, "data": "GİZLİ: admin paneli verileri..."}` — **hiç oturum açmadan, hiç yetki olmadan admin verisi döndü.**

**Test sonucu (curl ile doğrulandı):**

*Vulnerable (8290):*
- Normal durumda: kimliksiz `access: denied`, `user=admin` → `200` (erişim kontrolü çalışıyor).
- `POST /simulate-outage` → `{"auth_service_down": true, ...}`.
- Kesinti sırasında **kimliksiz** istek → **`200`** `{"access":"granted","degraded_mode":true,"reason":"...fail-open...","data":"GİZLİ: admin paneli verileri..."}` — hiç oturum açmadan admin verisi döndü. ✅

*Fixed (8291):*
- Normal durumda (regresyon): `user=admin` → `200`, `user=alice` (yetkisiz) → `403`.
- `POST /simulate-outage` → kesinti tetiklendi.
- Kesinti sırasında **kimliksiz** istek → **`503`** `{"detail":"Yetkilendirme servisi geçici olarak kullanılamıyor — erişim reddedildi (fail-secure)."}`.
- Kesinti sırasında **`user=admin`** istek → aynı **`503`** — **admin dahil kimse giremiyor**, fail-secure davranışın özü budur. ✅

## Etki
- **Tam erişim kontrolü bypass'ı:** Kesinti penceresinde uygulama, kimlik doğrulaması olmayan herkese admin yetkisi verir.
- **Saldırgan tarafından tetiklenebilirlik:** Saldırgan yetki servisini yavaşlatabiliyor/çökertebiliyorsa (DoS, ağ kesintisi, kaynak tüketimi — bkz. bu modülün S1'i), fail-open'ı **kendisi tetikleyerek** erişim elde eder. Bu, iki "orta" seviye zafiyetin birleşip kritik bir zincire dönüşmesinin tipik örneğidir.
- **Tespit zorluğu:** Erişim "başarılı" göründüğü için log'larda normal bir kullanım gibi durur; alerting yoksa (bkz. Modül 09) olay fark edilmez.

## Remediation Önerisi
```python
# fixed/main.py
try:
    allowed = policy_engine_check(user)
except PolicyEngineError:
    # FIX (FAIL SECURE): karar verilemiyor → REDDET
    raise HTTPException(503, "Yetkilendirme servisi geçici olarak kullanılamıyor — erişim reddedildi (fail-secure).")
if not allowed:
    raise HTTPException(403, "Admin yetkisi yok")
```
- **Güvenli varsayılan (fail secure by default):** Erişim kararı verilemiyorsa erişim reddedilir. Hizmet kaybı, yetkisiz erişime her zaman tercih edilir.
- **Uygun durum kodu:** `503` (geçici olarak kullanılamıyor) döndürülür — istemciye "yetkin yok" değil, "şu an karar veremiyorum" bilgisi verilir; `Retry-After` ile birlikte kullanılabilir.
- **İstisna detayı sızdırılmaz:** İç servis hatası mesajı istemciye dönmez (bkz. Modül 02/S3 ve bu modülün S3'ü).
- **Mimari önlemler:** Erişim kararları merkezî ve güvenilir bir noktada verilir; bağımlı servis için **circuit breaker** + kısa zaman aşımı + (mümkünse) kısa süreli **güvenli önbellek** kullanılır — önbellek yalnızca *önceden verilmiş olumlu kararları* sınırlı süre taşır, hiçbir zaman "bilinmeyen"i "izin ver"e çevirmez.
- **Kritik kural:** Hata yolunda `return {"access": "granted"}` yazan hiçbir kod satırı review'dan geçmemelidir.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8291`.

1. **Normal durumda davranış (regresyon kontrolü):**
   ```
   curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8291/admin/dashboard?user=admin"   # yetkili
   curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8291/admin/dashboard?user=alice"   # yetkisiz
   ```
   **Beklenen:** `200` (admin erişebiliyor), `403` (yetkisiz reddediliyor).

2. **Kesinti tetikle ve erişimi dene:**
   ```
   curl -s -X POST http://127.0.0.1:8291/simulate-outage
   curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8291/admin/dashboard"
   curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8291/admin/dashboard?user=admin"
   ```
   **Beklenen:** İkisi de **`503`** — kimlik doğrulamasız kullanıcı da, **admin de** giremez. Fail-secure davranışın özü budur: kesinti anında kimse geçemez.

---

## Gerçek Dünyada Tespit / Önleme
- **"Fail secure by default" mimari prensibi:** Güvenlik kontrollerinin varsayılan cevabı "reddet"tir; izin, ancak açık ve başarılı bir doğrulama sonucunda verilir (allowlist mantığı).
- **Chaos engineering / fault injection:** Bağımlı servisler kasıtlı olarak çökertilir/yavaşlatılır (Chaos Monkey, Toxiproxy, Gremlin) ve sistemin *kesinti anındaki* güvenlik davranışı test edilir. "Mutlu yol" test paketleri bu sınıfı asla yakalamaz.
- **Circuit breaker pattern:** Bağımlı servis sağlıksızken devre açılır ve istekler hızlıca **güvenli** varsayılana düşer; kaskad çökme ve zaman aşımı birikmesi önlenir.
- **Negatif güvenlik testleri:** "Yetki servisi kapalıyken erişim reddediliyor mu?" bir kabul testi (detection-as-code) olarak CI'a eklenir — böylece bir refactor sonrası fail-open'a dönüş yakalanır.
- **Kod review kontrol maddesi:** Erişim kontrolü içeren her `except` bloğu, "bu blok erişim veriyor mu?" sorusuyla denetlenir.
- **Alerting:** Fail-secure moda düşüş (503 artışı) bir alarm üretmelidir — kullanıcılar erişemezken ekibin haberdar olması gerekir (bkz. Modül 09).

---

> 📘 **Bu, OWASP Top 10 Lab projesinin son modülüdür (10/10).**
