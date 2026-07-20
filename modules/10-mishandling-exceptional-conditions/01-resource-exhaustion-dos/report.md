# [A10:2025] Mishandling of Exceptional Conditions → Kaynak Tükenmesi (DoS)

**Modül:** 10-mishandling-exceptional-conditions
**Senaryo:** `POST /upload` her istekte havuzdan bir kaynak (dosya handle'ı) ayırır. İşlem sırasında istisna oluşursa istisna yakalanır ama kaynak serbest bırakılmaz — `finally`/cleanup yoktur. Her hatalı istek havuzdan bir slot sızdırır; havuz dolunca servis meşru istekleri de reddeder.
**Portlar:** vulnerable `8280`, fixed `8281`
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

## Bu Kategori Nedir?
2025'te eklenen tamamen yeni bir kategori. Uygulamaların beklenmedik/anormal durumlarla (hatalar, timeout'lar, kaynak tükenmesi, eşzamanlı hata koşulları) nasıl başa çıktığıyla ilgilidir. "Fail open" (hata durumunda güvensiz tarafa düşme) vs "fail secure" (güvenli tarafa düşme) ayrımı bu kategorinin kalbidir. Yetersiz kaynak temizliği, DB hatalarının sızdırılması, çok adımlı işlemlerde rollback eksikliği örnektir. Temel korunma: try/finally disiplini, fail-secure-by-default mimari, circuit breaker pattern, atomicity/transaction bütünlüğü.

## CVSS 3.1
- **Skor:** 7.5 (High)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

**Gerekçe:**
- **AV:N / AC:L / PR:N / UI:N** — Uzaktan, kimlik doğrulamasız, basit bir istek döngüsüyle; saldırganın yalnızca *hatalı* istek göndermesi yeterlidir.
- **C:N / I:N** — Veri okunmaz veya değiştirilmez.
- **A:H** — Kaynak havuzu tükendiğinde servis meşru kullanıcılar için tamamen kullanılamaz hale gelir (kalıcı DoS — kaynaklar kendiliğinden geri gelmez, yeniden başlatma gerekir).

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [x] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V7.4.1:** *"Verify that a generic message is shown when an unexpected or security sensitive error occurs, potentially with a unique id..."* (hata yolunun kontrollü ele alınması)
- **V11.1.x:** Kaynak tahsis limitleri ve anti-automation kontrolleri.
- **CWE-404:** Improper Resource Shutdown or Release
- **CWE-772:** Missing Release of Resource after Effective Lifetime
- Destekleyici: **CWE-400** (Uncontrolled Resource Consumption)

## Açıklama
```python
# vulnerable/main.py
handle = acquire_resource(req.filename)      # kaynak ayrıldı
try:
    result = process_upload(req.filename)
except ValueError as e:
    # ZAFIYET: kaynak SERBEST BIRAKILMIYOR — finally yok
    raise HTTPException(400, f"Yükleme başarısız: {e}")
release_resource(handle)                     # yalnızca BAŞARILI yolda çalışır
```
Kök neden, **cleanup'ın mutlu yola (happy path) bağlanmış olmasıdır.** `release_resource()` çağrısı `try` bloğunun *sonrasında* durur; istisna fırladığında bu satıra hiç ulaşılmaz ve handle sonsuza dek `LOCKED_RESOURCES` içinde kalır.

Bu, istisna işleme hatalarının klasik biçimidir: geliştirici istisnayı *yakalamıştır* (kod "hata yönetiyor" görünür), ama istisnanın **yan etkisini** (ayrılmış kaynağı) düşünmemiştir. Havuz sınırlı olduğundan, sızıntı birikerek hizmeti durdurur.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8280`.

1. **Başlangıç durumu (havuz boş):**
   ```
   curl -s http://127.0.0.1:8280/resource-status
   ```
   **Beklenen:** `{"locked_count": 0, "pool_size": 5, "available": 5, ...}`

2. **5 hatalı istek gönder (dosya adı "corrupt_" ile başlıyorsa → istisna):**
   ```
   for i in 1 2 3 4 5; do
     curl -s -o /dev/null -w "istek $i -> %{http_code}\n" -X POST http://127.0.0.1:8280/upload \
       -H "Content-Type: application/json" -d "{\"filename\": \"corrupt_$i.txt\"}"
   done
   curl -s http://127.0.0.1:8280/resource-status
   ```
   **Beklenen:** 5 istek de `400`; ardından `locked_count: 5`, `available: 0` — **her hatalı istek bir kaynak sızdırdı.**

3. **Meşru bir istek artık reddediliyor (DoS kanıtı):**
   ```
   curl -s -X POST http://127.0.0.1:8280/upload \
     -H "Content-Type: application/json" -d '{"filename": "gecerli.txt"}'
   ```
   **Beklenen:** `503` `"Kaynaklar tükendi (5/5 kilitli) — servis kullanılamıyor."` — geçerli, sıradan bir dosya adı (`"corrupt_"` ile başlamıyor) olmasına rağmen servis çalışmıyor.

## Etki
- **Kalıcı hizmet reddi:** Kaynaklar kendiliğinden geri gelmediğinden, servis yeniden başlatılana kadar kullanılamaz kalır.
- **Düşük maliyetli saldırı:** Saldırganın kimlik doğrulaması veya özel bir payload'ı gerekmez; yalnızca *hata üreten* istekler göndermesi yeterlidir (havuz boyutu kadar istek).
- **Gerçek dünyadaki karşılıkları:** Kapatılmayan DB bağlantıları (connection pool exhaustion), serbest bırakılmayan dosya tanıtıcıları (`too many open files`), bırakılmayan kilitler (deadlock), temizlenmeyen geçici dosyalar (disk dolması).

## Remediation Önerisi
```python
# fixed/main.py — context manager ile garantili cleanup
@contextmanager
def managed_resource(filename: str):
    ...
    LOCKED_RESOURCES.append(handle)
    try:
        yield handle
    finally:
        # istisna fırlasa BİLE çalışır → sızıntı imkânsız
        if handle in LOCKED_RESOURCES:
            LOCKED_RESOURCES.remove(handle)

with managed_resource(req.filename) as handle:
    ...
```
- **`try/finally` veya context manager (`with`):** Cleanup, hata yolundan bağımsız olarak **garanti altına alınır**. `finally` bloğu; normal dönüş, `return`, `break` ve istisna dahil her çıkış yolunda çalışır.
- **Neden yapısal bir çözüm:** Cleanup'ı "her hata yolunda hatırlamak" ölçeklenmez — yeni bir `except` dalı veya erken `return` eklendiğinde kolayca unutulur. `with`, temizliği **kaynağın kendi tanımına** taşır; kullanan kodun hatırlamasına gerek kalmaz. Bu, hata sınıfını tek tek düzeltmek yerine *mümkün olmaktan çıkarır*.
- **Havuz limitleri + zaman aşımı:** Kaynaklara maksimum yaşam süresi (lease/TTL) verilerek, bir sızıntı olsa bile kaynağın otomatik geri alınması sağlanır (defense in depth).

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8281`.

1. **Aynı 5 hatalı istek:**
   ```
   for i in 1 2 3 4 5; do
     curl -s -o /dev/null -w "istek $i -> %{http_code}\n" -X POST http://127.0.0.1:8281/upload \
       -H "Content-Type: application/json" -d "{\"filename\": \"corrupt_$i.txt\"}"
   done
   curl -s http://127.0.0.1:8281/resource-status
   ```
   **Beklenen:** 5 istek de `400` (aynı hata), ancak **`locked_count: 0`, `available: 5`** — hiçbir kaynak sızmadı.

2. **Meşru istek hâlâ çalışıyor (`"corrupt_"` ile başlamayan gerçek bir dosya adı):**
   ```
   curl -s -X POST http://127.0.0.1:8281/upload \
     -H "Content-Type: application/json" -d '{"filename": "gecerli.txt"}'
   ```
   **Beklenen:** `200` `{"uploaded": true, "result": "gecerli.txt işlendi", "locked_count": 0}` — DoS oluşmadı. (Önceki tetikleyici `"x" in filename` idi ve `.txt` uzantısının kendisi `x` harfi içerdiğinden `"gecerli.txt"` gibi tamamen sıradan dosya adları da yanlışlıkla hataya düşüyordu. Açık `"corrupt_"` öneki bu belirsizliği ortadan kaldırır — artık yalnızca bilinçli olarak işaretlenmiş dosya adları hata üretir.)

---

## Gerçek Dünyada Tespit / Önleme
- **`try/finally` disiplini ve context manager kültürü:** Kaynak ayıran her API (`open`, DB bağlantısı, kilit, socket) `with` ile kullanılır; kod review'da "bu kaynak hata yolunda da bırakılıyor mu?" standart kontrol maddesidir.
- **Statik analiz:** Linter/SAST kuralları (`pylint` R1732 *consider-using-with*, Semgrep resource-leak kuralları) kapatılmayan kaynakları CI'da yakalar.
- **Fault injection / chaos engineering:** Hata yolları kasıtlı tetiklenerek (bozuk girdi, servis kesintisi, zaman aşımı) sistemin *hata sonrası* durumu test edilir — mutlu yol testleri bu sınıfı asla yakalamaz.
- **Kaynak metrikleri ve alarm:** Açık bağlantı/handle sayısı, havuz doluluk oranı gibi metrikler izlenir; kademeli artış (leak imzası) alarm üretir (bkz. Modül 09 — alerting).
- **Zaman aşımı + circuit breaker:** Kaynaklara TTL verilir; bağımlı sistem yavaşladığında circuit breaker devreye girerek havuzun tükenmesini önler.

---

> 📘 **Bu, OWASP Top 10 Lab projesinin son modülüdür (10/10).**
