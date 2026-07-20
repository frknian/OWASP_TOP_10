# [A01:2025] Missing Function Level Access Control → Vertical Privilege Escalation

**Modül:** 01-broken-access-control
**Senaryo:** Sadece adminlerin erişebilmesi gereken bir yönetim endpoint'ine, normal veya giriş yapmamış bir kullanıcının direkt URL ile erişebilmesi
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed) — Burp Suite görsel kanıtı ileride eklenecek

> ℹ️ **Not (OWASP Top 10:2025):** Bu kategori 2025 sürümünde de A01 — Broken Access Control olarak yerini koruyor ve BOLA/BFLA ile SSRF'yi açıkça kapsıyor.

## Bu Kategori Nedir?
Erişim kontrolü, bir kullanıcının yalnızca yetkili olduğu kaynaklara/işlemlere erişebilmesini sağlar. Bu kategori, authentication ("sen kimsin") ile authorization ("bu işlemi yapmaya yetkin var mı") arasındaki farkın karıştırılmasından doğar. Yaygın türleri: IDOR/BOLA (nesne düzeyinde), BFLA (fonksiyon düzeyinde), client-side'a güvenme. Temel korunma: her istekte sunucu tarafında authorization kontrolü, deny-by-default, least privilege.

## CVSS 3.1
- **Skor:** 7.5 (High)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

**Gerekçe:**
- **AV:N** — Endpoint HTTP üzerinden ağ genelinde erişilebilir, lokal erişim gerekmiyor.
- **AC:L** — Saldırı için özel bir koşul, yarış durumu veya ön hazırlık yok; saldırgan sadece `GET /api/admin/users` URL'ini biliyor/tahmin ediyor.
- **PR:N (kritik fark)** — **Hiçbir ayrıcalık gerekmiyor.** Endpoint'te `Depends(get_current_user)` dahi olmadığı için saldırganın geçerli bir session'ı, hatta hiç bir hesabı bile olması gerekmiyor — anonim (kimliksiz) bir istemci verinin tamamını çekebiliyor. Bu, Senaryo 1'deki IDOR'dan (orada `PR:L` — saldırganın en az kendi hesabıyla giriş yapmış olması gerekiyordu) daha ağır bir durumdur ve skoru yukarı çeken temel etkendir.
- **UI:N** — Başka bir kullanıcının etkileşimi gerekmiyor.
- **S:U** — Yetkilendirme zafiyeti aynı uygulama/yetki alanı içinde kalıyor, farklı bir güvenlik otoritesine sıçramıyor.
- **C:H** — Uygulamadaki **tüm** kullanıcıların hassas verisi (email, `balance`, phone_number, role) hiçbir maskeleme olmadan **tek bir istekte** sızıyor. Senaryo 1'de veri sıralı ID'ler taranarak (çok sayıda istekle) toplanabiliyordu; burada tüm kullanıcı tabanı atomik olarak, tek `GET` ile dışarı çıkıyor.
- **I:N / A:N** — İncelenen endpoint salt-okunur (`GET`); bu repro'da veri değişikliği veya kullanılamazlık etkisi gösterilmedi.

**Senaryo 1 ile karşılaştırma:** Senaryo 1 (IDOR) `6.5 (Medium)` idi; bu bulgu `7.5 (High)`. Tek base-metric farkı `PR:L → PR:N` geçişidir. İki bulgu da `C:H` içeriyor, ancak burada gizlilik ihlali hem daha kolay tetikleniyor (ayrıcalık yok) hem de daha atomik (tek istekte tüm taban) olduğundan risk seviyesi bir kademe yükseliyor.

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [x] High
- [ ] Critical

## İlgili OWASP ASVS Kontrol Maddesi

**V4.1 — General Access Control Design (Genel Erişim Kontrolü):**
- **V4.1.1:** *"Verify that the application enforces access control rules on a trusted service layer, especially if client-side access control is present and could be bypassed."* — Bu bulgunun kökü: kısıt yalnızca UI/yönlendirme katmanında *varsayılmış*, güvenilir sunucu katmanında hiç uygulanmamış.
- **V4.1.5:** *"Verify that access controls fail securely including when an exception occurs."* — Endpoint hiçbir kontrol içermediği için "fail secure" değil, **fail open** davranıyor: kontrol yokluğunda varsayılan sonuç "erişime izin ver".

**V4.2 — Operation Level Access Control (Fonksiyon/Operasyon Düzeyi):**
- **V4.2.1:** *"Verify that sensitive data and APIs are protected against Insecure Direct Object Reference (IDOR) attacks... viewing everyone's records..."* — "viewing everyone's records" kısmı bu senaryonun tam karşılığı: tek istekle herkesin kaydının görülmesi.
- **V4.2.2:** *"Verify that the application or framework enforces a strong anti-CSRF mechanism to protect authenticated functionality, and effective anti-automation or anti-CSRF protects unauthenticated functionality."* — Yönetimsel fonksiyonların kimlik doğrulaması gerektiren (authenticated) bir güven sınırının arkasında olması gerektiğini vurgular; bu endpoint o sınırın tamamen dışında kalmış.

## Açıklama

`GET /api/admin/users`, yalnızca `admin` rolüne sahip kullanıcıların erişmesi gereken bir **yönetim (function-level) fonksiyonudur** — tüm kullanıcıların hassas verisini döndürür. Ancak `vulnerable/main.py` içindeki endpoint **ne authentication ne de authorization** kontrolü içeriyor:

```python
@app.get("/api/admin/users")
def list_all_users():
    conn = get_db_connection()
    users = conn.execute(
        "SELECT id, username, email, balance, phone_number, role FROM users ORDER BY id"
    ).fetchall()
    conn.close()
    return [dict(user) for user in users]
```

Fonksiyon imzasında `Depends(get_current_user)` dahi bulunmadığından, endpoint anonim istemcilere tamamen açıktır. Kısıtın "sadece adminler bu sayfayı görür" varsayımı muhtemelen sadece bir arayüz/menü mantığında yaşıyor; sunucu tarafında hiçbir zorlama yok. Bu, klasik bir **security through obscurity** (endpoint'in adının bilinmediği varsayımıyla güvenlik sağlama) hatasıdır — URL bir kez öğrenildiğinde/tahmin edildiğinde koruma sıfırdır.

Bu bir **Broken Function Level Authorization** (OWASP API Top 10'daki BFLA'nın web karşılığı; A01:2021 kapsamı) zafiyetidir ve **dikey yetki yükselmesine (vertical privilege escalation)** yol açar: yetkisiz/anonim bir aktör, normalde daha yüksek ayrıcalık (admin rolü) gerektiren bir işlevi çalıştırabiliyor.

## Repro Adımları

**Ortam:** `vulnerable/main.py` → `http://127.0.0.1:8003`, `fixed/main.py` → `http://127.0.0.1:8004` (ayrı venv, ayrı `accounts.db`). Seed kullanıcıları (`alice`, `bob` → `role=user`; `admin` → `role=admin`) `seed_db()` ile otomatik oluşturuluyor.

### a) Anonim istek → vulnerable → **200 OK** (zafiyet kanıtı)
```
curl -i http://127.0.0.1:8003/api/admin/users
```
**Sonuç:** `200 OK` — hiçbir cookie/oturum gönderilmeden tüm kullanıcı verisi döndü:
```json
[
  {"id":1,"username":"alice","email":"alice@example.com","balance":2500,"phone_number":"+90 532 000 00 01","role":"user"},
  {"id":2,"username":"bob","email":"bob@example.com","balance":750,"phone_number":"+90 532 000 00 02","role":"user"},
  {"id":3,"username":"admin","email":"admin@example.com","balance":0,"phone_number":"+90 532 000 00 09","role":"admin"}
]
```
Kimlik doğrulaması olmayan tek bir istekle, admin dahil **tüm kullanıcı tabanının** email/bakiye/telefon/rol bilgisi sızdırıldı.

### b) Anonim istek → fixed → **401 Unauthorized** (authentication katmanı)
```
curl -i http://127.0.0.1:8004/api/admin/users
```
**Sonuç:** `401 Unauthorized`
```json
{"detail":"Not authenticated"}
```
Fixed sürümde `Depends(get_current_user)` devrede olduğundan, oturumsuz istek endpoint gövdesine hiç ulaşamadan reddedildi.

### c) Alice (user rolü) → fixed → **403 Forbidden** (authorization katmanı)
```
# 1) Alice login
curl -i -c alice_cookies.txt -X POST http://127.0.0.1:8004/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"AliceStrongPass!23"}'
# → 200 OK, {"message":"login successful"}

# 2) Alice'in session'ı ile admin endpoint'i
curl -i -b alice_cookies.txt http://127.0.0.1:8004/api/admin/users
```
**Sonuç:** `403 Forbidden`
```json
{"detail":"Admin privileges required"}
```
Alice geçerli bir oturuma sahip (authentication ✓) ama `role=user` olduğundan rol kontrolüne takıldı. Bu adım, kimlik doğrulamanın tek başına yeterli olmadığının kanıtıdır (401 değil, **403**: "kim olduğun belli ama bu fonksiyona yetkin yok").

### d) Admin → fixed → **200 OK** (meşru erişim engellenmiyor)
```
# 1) Admin login (seed_db'deki admin şifresi)
curl -i -c admin_cookies.txt -X POST http://127.0.0.1:8004/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"AdminStrongPass!67"}'
# → 200 OK, {"message":"login successful"}

# 2) Admin'in session'ı ile admin endpoint'i
curl -i -b admin_cookies.txt http://127.0.0.1:8004/api/admin/users
```
**Sonuç:** `200 OK` — `role=admin` olan kullanıcı, adım (a)'daki aynı tam listeyi meşru şekilde aldı. Kontrol yalnızca yetkisizleri kesiyor, meşru admini engellemiyor.

### Sonuç Tablosu

| Test | İstemci | Hedef | Beklenen | Gerçekleşen | Sonuç |
|------|---------|-------|----------|-------------|--------|
| a | Anonim | vulnerable:8003 | 200 | `200` + tüm veri | ✅ |
| b | Anonim | fixed:8004 | 401 | `401 Not authenticated` | ✅ |
| c | Alice (user) | fixed:8004 | 403 | `403 Admin privileges required` | ✅ |
| d | Admin | fixed:8004 | 200 | `200` + tüm veri | ✅ |

*(Burp Suite ile bu isteklerin Proxy/Repeater kayıtları görsel kanıt olarak eklenecek.)*

## Kavramsal Fark: Function-Level vs Object-Level Access Control

Senaryo 1 (IDOR/BOLA) ile bu senaryo, "Broken Access Control" başlığının iki farklı katmanını temsil eder ve karıştırılmamalıdır:

- **Senaryo 1 — Broken *Object*-Level Authorization (IDOR/BOLA), yatay:** Kullanıcının erişmeye çalıştığı **fonksiyon meşrudur** (herkes kendi hesabını görebilir; `GET /api/accounts/{id}` herkese açık bir yetenektir). Sorun, o fonksiyonun döndürdüğü **spesifik nesnenin sahipliğinin** doğrulanmamasıdır — yani "bu kullanıcı *bu kaydın* sahibi mi?" sorusu sorulmuyor. Yetki aşımı **aynı ayrıcalık seviyesindeki başka bir kullanıcıya** doğru (yatay) gerçekleşir.

- **Senaryo 2 — Broken *Function*-Level Authorization (BFLA), dikey:** Sorun bir nesnenin sahipliği değil, **fonksiyonun kendisine erişim hakkıdır.** `GET /api/admin/users` normalde yalnızca `admin` rolünün *çağırma* yetkisine sahip olduğu bir işlevdir; zafiyet, düşük ayrıcalıklı (hatta anonim) bir aktörün bu **daha yüksek ayrıcalıklı işlevi çalıştırabilmesidir.** Yetki aşımı **daha üst bir ayrıcalık seviyesine** doğru (dikey) gerçekleşir.

Kısacası: IDOR "doğru fonksiyon, yanlış nesne"; Missing Function Level Access Control ise "yetkisiz aktör, yasak fonksiyon" problemidir. Biri kaydın *sahipliğini*, diğeri işlemin *rol/yetki eşiğini* atlar.

## Etki
- **Gizlilik ihlali (Confidentiality):** Kimliği doğrulanmamış herhangi bir aktör, tek bir istekle sistemdeki **tüm** kullanıcıların email adresini, hesap bakiyesini, telefon numarasını ve rolünü okuyabilir. Bu, Senaryo 1'deki gibi ID taranarak *inşa edilmesi gereken* bir toplu sızıntı değil, doğrudan **atomik ve tam** bir veri dökümüdür (mass data exposure).
- **Rol bilgisinin ifşası:** Yanıtta `role` alanının da dönmesi, saldırgana hangi hesapların `admin` olduğunu gösterir; bu, sonraki adımda hedefli kimlik avı / hesap ele geçirme saldırıları için keşif (reconnaissance) değeri taşır.
- **İş etkisi:** Finansal veri (`balance`) ve iletişim verisinin ayrıcalıksız sızması, KVKK/GDPR kapsamında ihbar yükümlülüğü doğurabilecek bir kişisel veri ihlalidir; ayrıca yüksek bakiyeli veya admin hesaplarının hedefli sosyal mühendisliğe maruz kalma riskini artırır.
- **Bütünlük/Kullanılabilirlik:** Test edilen endpoint salt-okunur olduğundan doğrudan veri değişikliği/kesinti gösterilmedi; ancak aynı "sunucuda rol kontrolü yok" deseni bir yazma (`POST`/`PUT`/`DELETE`) yönetim endpoint'inde bulunursa etki bütünlük ihlaline (örn. kullanıcı silme, rol atama) kadar genişleyebilir — bu ayrı test gerektiren, kapsam dışı bir varsayımdır.

## Remediation Önerisi

Düzeltme `fixed/main.py` içinde **iki bağımsız katman** olarak uygulandı ve bu ikisinin ayrı ayrı gerekli olması bu bulgunun özüdür:

**1. Authentication katmanı — `Depends(get_current_user)`:**
```python
@app.get("/api/admin/users")
def list_all_users(current_user: sqlite3.Row = Depends(get_current_user)):
    ...
```
Bu, "istek geçerli, kimliği bilinen bir kullanıcıdan mı geliyor?" sorusunu yanıtlar. Anonim istekler daha endpoint gövdesine varmadan `401` alır (test b).

**2. Authorization katmanı — rol tabanlı kontrol:**
```python
    if current_user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
```
Bu, "bu kimliği bilinen kullanıcı, *bu* fonksiyonu çalıştırmaya yetkili mi?" sorusunu yanıtlar. Giriş yapmış ama `admin` olmayan kullanıcılar `403` alır (test c).

**Neden iki katman ayrı ayrı gerekli?** Authentication ve authorization farklı soruları yanıtlar ve biri diğerinin yerine geçmez. Sadece authentication olsaydı (yalnızca `Depends`), Senaryo 1'deki hatanın dikey versiyonu oluşurdu: herhangi bir giriş yapmış kullanıcı (alice/bob dahil) admin verisine ulaşırdı. Sadece authorization olsaydı (rol kontrolü ama session zorunluluğu yok), rolü okuyacak güvenilir bir kimlik olmazdı. İki katmanın ayrımı HTTP semantiğine de yansır: kimlik yoksa **401** (kimliğini kanıtla), kimlik var ama yetki yoksa **403** (yetkin yok). Testler bu ayrımı doğruluyor: anonim → 401, user → 403.

**Neden rol DB'den taze okunmalı (session'dan değil)?** `get_current_user`, rolü session cookie'sinden değil her istekte veritabanından okuyacak şekilde güncellendi:
```python
user = conn.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()
```
- **Yetkilendirme, otoriter kaynaktan yapılmalı:** Rol, yetki kararının temelidir; kararın dayandığı veri, sistemin *güncel gerçeğini* (DB'yi) yansıtmalıdır. Session'a gömülü bir rol, o session oluşturulduğu andaki fotoğrafı taşır.
- **Anında iptal (immediate revocation):** Bir kullanıcının admin yetkisi kötüye kullanım nedeniyle geri alınırsa, DB'den taze okuma sayesinde bu değişiklik **bir sonraki istekte** yürürlüğe girer. Rol session'da saklansaydı, kullanıcı mevcut (hâlâ geçerli, imzalı) cookie'siyle session süresi dolana kadar admin ayrıcalıklarını sürdürebilirdi — bu bir yetki-devamlılığı (privilege persistence) açığıdır.
- **Tamper yüzeyini daraltma:** Client'a giden hiçbir veriye yetki kararı için güvenilmez. Session imzalı olsa bile, yetkiyi belirleyen kritik alanı sunucunun kendi otoriter deposundan çekmek, en küçük güven varsayımı ilkesine (least trust) uygundur.

**Uzun vadeli öneri:** Benzer yönetim endpoint'leri çoğaldıkça, her fonksiyona elle `if role != "admin"` yazmak yerine merkezi bir `require_role("admin")` dependency'si (veya FastAPI `dependencies=[...]` router-seviyesi kontrolü) tanımlanması tutarlılığı ve test edilebilirliği artırır; kontrolü unutma riskini (tam da bu zafiyetin sebebini) yapısal olarak azaltır.

### Fixed Version Verification

Remediation `fixed/main.py`'de uygulandı ve `vulnerable` ile aynı senaryolar `fixed` üzerinde tekrarlandı. Vulnerable sürümde anonim bir istekle `200 OK` + tüm kullanıcı verisi dönen aynı endpoint, fixed sürümde artık katmanlı olarak: anonim → `401`, user (alice) → `403`, admin → `200` döndürüyor. Bu, Missing Function Level Access Control zafiyetinin hem authentication hem authorization ekseninde kapatıldığının curl ile doğrulanmış kanıtıdır (bkz. yukarıdaki Sonuç Tablosu).
