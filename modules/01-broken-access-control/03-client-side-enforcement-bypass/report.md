# [A01:2025] Client-Side Enforcement of Server-Side Security (CWE-602) → Vertical Privilege Escalation

**Modül:** 01-broken-access-control
**Senaryo:** Güvenlik kontrolünün (yetki kontrolü) yalnızca frontend'de uygulanması; saldırganın client-side gizlemeyi bypass edip doğrudan API'ye istek atarak yetkisi olmayan bir işlemi (kullanıcı silme) gerçekleştirebilmesi
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed) — Burp Suite görsel kanıtı ileride eklenecek

> ℹ️ **Not (OWASP Top 10:2025):** Bu kategori 2025 sürümünde de A01 — Broken Access Control olarak yerini koruyor ve BOLA/BFLA ile SSRF'yi açıkça kapsıyor.

## Bu Kategori Nedir?
Erişim kontrolü, bir kullanıcının yalnızca yetkili olduğu kaynaklara/işlemlere erişebilmesini sağlar. Bu kategori, authentication ("sen kimsin") ile authorization ("bu işlemi yapmaya yetkin var mı") arasındaki farkın karıştırılmasından doğar. Yaygın türleri: IDOR/BOLA (nesne düzeyinde), BFLA (fonksiyon düzeyinde), client-side'a güvenme. Temel korunma: her istekte sunucu tarafında authorization kontrolü, deny-by-default, least privilege.

## CVSS 3.1
- **Skor:** 8.1 (High)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`

**Gerekçe:**
- **AV:N** — Endpoint HTTP üzerinden ağ genelinde erişilebilir.
- **AC:L** — Saldırı için özel bir koşul yok; saldırgan yalnızca `DELETE /api/admin/users/{id}` isteğini gönderir (butonu görmese bile endpoint'i DevTools/curl/Burp ile çağırabilir).
- **PR:L** — Saldırganın en az kendi (düşük yetkili, `role=user`) hesabıyla giriş yapmış olması gerekiyor; endpoint `Depends(get_current_user)` ile authentication şart koşuyor. Bu yönüyle Senaryo 2'den (`PR:N` — tamamen anonim) ayrılır: burada zafiyet authentication'ın *varlığında* ama authorization'ın *yokluğunda* ortaya çıkar.
- **UI:N** — Başka bir kullanıcının etkileşimi gerekmiyor.
- **S:U** — Etki aynı uygulama/yetki alanı içinde kalıyor.
- **C:N** — Bu bir okuma değil, *yıkıcı* bir işlem; birincil etki gizlilik değil. (Yanıt gövdesi silinen kullanıcının username'ini yansıtıyor — önemsiz bir bilgi sızıntısı; birincil etki bu değil, bu yüzden `N` olarak değerlendirildi.)
- **I:H** — Saldırgan **herhangi bir** kullanıcı kaydını yetkisiz şekilde kalıcı olarak silebiliyor. Bu, veri bütünlüğünün ciddi ihlalidir: veri, yetkisiz bir aktör tarafından geri döndürülemez biçimde değiştiriliyor/yok ediliyor.
- **A:H** — Bir kullanıcının silinmesi o kullanıcının sisteme erişimini tamamen kaldırır (hesap kullanılamaz hale gelir). Saldırgan ID'ler üzerinde döngü kurarak **admin dahil tüm kullanıcı tabanını** silebilir; bu, uygulamanın kullanıcı verisinin/işlevinin toplu ve kalıcı kaybı anlamına gelir — yüksek kullanılabilirlik etkisi.

**Senaryo 1/2 ile karşılaştırma (etki ekseni değişti):**

| Senaryo | Zafiyet | İşlem | CVSS | Temel fark |
|---------|---------|-------|------|-----------|
| 1 — IDOR/BOLA | object-level, yatay | GET (okuma) | 6.5 | `PR:L`, sadece `C:H` |
| 2 — Missing Function Level AC | function-level, dikey | GET (okuma) | 7.5 | `PR:N`, sadece `C:H` |
| 3 — Client-Side Enforcement (bu) | function-level, dikey | **DELETE (yıkıcı)** | **8.1** | `PR:L` ama `I:H` + `A:H` |

Senaryo 1 ve 2 salt-okunur endpoint'lerdi; etki yalnızca gizlilik (`C:H`) idi. Bu senaryo bir **DELETE** olduğundan etki gizlilikten bütünlük + kullanılabilirliğe (`I:H` + `A:H`) kayıyor. `PR:L` (Senaryo 1 ile aynı, Senaryo 2'den daha kısıtlayıcı) olmasına rağmen, çift yüksek etki (veri imhası + hesap kaybı) skoru üç senaryonun en yükseğine çıkarıyor. Ders: bir yetki açığının ciddiyeti, korunmayan işlemin *ne yaptığına* bağlıdır — okuma sızdırır, silme yok eder.

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [x] High
- [ ] Critical

## İlgili CWE
- **CWE-602: Client-Side Enforcement of Server-Side Security** — Uygulama, bir güvenlik kontrolünü (burada: "yalnızca adminler silebilir" yetki kuralını) client tarafında (butonu CSS/JS ile gizleyerek) uyguluyor, ancak sunucu tarafında zorlamıyor. Client tamamen saldırganın kontrolünde olduğundan, client-side kısıt güvenilir bir güvenlik sınırı oluşturmaz.

## İlgili OWASP ASVS Kontrol Maddesi

**V4.1 — General Access Control Design:**
- **V4.1.1:** *"Verify that the application enforces access control rules on a trusted service layer, especially if client-side access control is present and could be bypassed."* — Bu bulgunun tam tanımı: erişim kontrolü sadece client'ta var, güvenilir sunucu katmanında yok.
- **V4.1.3:** *"Verify that the principle of least privilege exists — users should only be able to access functions, data files, URLs... for which they possess specific authorization."* — Normal kullanıcı, silme fonksiyonu için özel yetkiye sahip olmadığı halde onu çalıştırabiliyor.
- **V4.1.5:** *"Verify that access controls fail securely including when an exception occurs."* — Vulnerable endpoint yetki kontrolü içermediğinden "deny by default" değil, "allow by default" davranıyor.

**V4.2 — Operation Level Access Control:**
- **V4.2.1:** *"Verify that sensitive data and APIs are protected against Insecure Direct Object Reference (IDOR) attacks targeting creation, reading, updating and **deletion** of records, such as ... **deleting all records**."* — "deleting all records" bu senaryonun birebir karşılığı: yetkisiz kullanıcı ID'ler üzerinde döngü kurarak tüm kayıtları silebilir.

## Açıklama

Uygulama, "kullanıcı silme" yetkisini yalnızca admin rolüne vermeyi *amaçlıyor*. Ancak bu kural yalnızca **frontend'de**, "Delete User" butonunu gizleyerek uygulanmış:

`dashboard.html` içinde admin paneli DOM'da mevcut ama CSS ile `display:none`; küçük bir JS bloğu sunucudan gelen role değerine bakıp paneli **yalnızca** `role === "admin"` ise görünür yapıyor:

```javascript
const currentUserRole = {{ user.role | tojson }};
if (currentUserRole === "admin") {
  document.getElementById("admin-panel").style.display = "block";
}
```

Sonuç olarak `alice`/`bob` (normal kullanıcı) dashboard'da butonu **hiç göremez**. Sorun şu ki, backend'de `vulnerable/main.py` içindeki `DELETE /api/admin/users/{id}` endpoint'i **yalnızca authentication** kontrolü yapıyor, **rol kontrolü içermiyor**:

```python
@app.delete("/api/admin/users/{user_id}")
def delete_user(user_id: int, current_user: sqlite3.Row = Depends(get_current_user)):
    # rol kontrolü YOK → giriş yapmış HERKES silebilir
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    ...
```

**Yanıltıcı güvenlik varsayımı:** Butonun DOM'da olmaması, endpoint'in var olmadığı ya da erişilemez olduğu anlamına gelmez. Frontend (HTML/CSS/JS) tamamen saldırganın makinesinde, onun kontrolünde çalışır; saldırgan JS'i hiç çalıştırmadan, doğrudan HTTP isteği kurabilir. "Kullanıcı butonu göremiyorsa o işlemi yapamaz" varsayımı bu yüzden yanlıştır — bu, güvenliği görünürlükle (security through obscurity / client-side gizleme) sağlamaya çalışmaktır. Bu, klasik bir **CWE-602 (Client-Side Enforcement of Server-Side Security)** zafiyetidir ve **dikey yetki yükselmesine** (normal kullanıcının admin işlevini çalıştırması) yol açar.

## Repro Adımları

**Ortam:** `vulnerable/main.py` → `http://127.0.0.1:8005`, `fixed/main.py` → `http://127.0.0.1:8006` (ayrı venv, ayrı `accounts.db`, temiz seed: `alice`=1, `bob`=2, `admin`=3).

### a) VULNERABLE — alice (user) Bob'u siliyor → **200 OK** (zafiyet kanıtı)
```
# alice login
curl -c alice.txt -X POST http://127.0.0.1:8005/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"AliceStrongPass!23"}'
# → 200 OK, {"message":"login successful"}

# alice, butonu HİÇ görmediği halde, Bob'u (id=2) doğrudan siliyor
curl -b alice.txt -X DELETE http://127.0.0.1:8005/api/admin/users/2
```
**Sonuç:** `200 OK`
```json
{"message":"user bob (id=2) deleted"}
```
Normal bir kullanıcı, yalnızca sunucuya doğrudan bir `DELETE` isteği kurarak başka bir kullanıcıyı kalıcı olarak sildi. Frontend'deki buton gizleme hiçbir koruma sağlamadı. Saldırgan `id`'yi 1'den itibaren artırarak (admin dahil) tüm kullanıcıları silebilir.

### b) VULNERABLE — veriyi geri getir (test-only)
```
curl -X POST http://127.0.0.1:8005/reset-db
```
**Sonuç:** `200 OK` — `{"message":"database reset to seed state"}` (alice/bob/admin, ID 1/2/3 ile yeniden yüklenir).

### c) FIXED — alice (user) Bob'u silmeye çalışıyor → **403 Forbidden**
```
curl -c alice.txt -X POST http://127.0.0.1:8006/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"AliceStrongPass!23"}'          # → 200 OK
curl -b alice.txt -X DELETE http://127.0.0.1:8006/api/admin/users/2
```
**Sonuç:** `403 Forbidden`
```json
{"detail":"Admin privileges required"}
```
Aynı istek, fixed sürümde sunucu tarafı rol kontrolüne takıldı. Bob silinmedi.

### d) FIXED — admin Bob'u siliyor → **200 OK** (meşru erişim engellenmiyor)
```
curl -c admin.txt -X POST http://127.0.0.1:8006/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"AdminStrongPass!67"}'          # → 200 OK
curl -b admin.txt -X DELETE http://127.0.0.1:8006/api/admin/users/2
```
**Sonuç:** `200 OK` — `{"message":"user bob (id=2) deleted"}`. Rol kontrolü yalnızca yetkisizleri kesiyor, meşru admini engellemiyor.

### e) FIXED — veriyi geri getir (test-only)
```
curl -X POST http://127.0.0.1:8006/reset-db          # → 200 OK, seed geri yüklenir
```

### f) HER İKİ SÜRÜM — anonim (session'sız) DELETE → **401 Unauthorized**
```
curl -X DELETE http://127.0.0.1:8005/api/admin/users/2   # vulnerable
curl -X DELETE http://127.0.0.1:8006/api/admin/users/2   # fixed
```
**Sonuç (ikisi de):** `401 Unauthorized` — `{"detail":"Not authenticated"}`. Her iki sürümde de `Depends(get_current_user)` mevcut olduğundan, oturumsuz istek zaten authentication katmanında reddediliyor. Vulnerable ile fixed farkı authentication'da değil, **authorization** (rol) katmanındadır.

### Sonuç Tablosu

| Test | Sürüm | İstemci | İstek | Beklenen | Gerçekleşen | Sonuç |
|------|-------|---------|-------|----------|-------------|--------|
| a | vulnerable | alice (user) | DELETE /users/2 | 200 (zafiyet) | `200` "user bob deleted" | ✅ |
| b | vulnerable | — | POST /reset-db | 200 | `200` reset | ✅ |
| c | fixed | alice (user) | DELETE /users/2 | 403 | `403` "Admin privileges required" | ✅ |
| d | fixed | admin | DELETE /users/2 | 200 | `200` "user bob deleted" | ✅ |
| e | fixed | — | POST /reset-db | 200 | `200` reset | ✅ |
| f | her ikisi | anonim | DELETE /users/2 | 401 | `401` "Not authenticated" | ✅ |

*(Burp Suite ile bu isteklerin Proxy/Repeater kayıtları görsel kanıt olarak eklenecek — özellikle alice'in butonu görmediği dashboard ekranı + Repeater'dan atılan başarılı DELETE isteği yan yana gösterilecek.)*

## Frontend Gizleme Mekanizması ve Neden Yanlış Bir Güvenlik Varsayımı Olduğu

**Nasıl çalışıyor:**
1. `GET /dashboard` → `get_current_user` ile giriş şart; sunucu `user.role` değerini template'e geçirir.
2. `dashboard.html`'de "Admin — Delete User" paneli DOM'da vardır ama `#admin-panel { display: none; }` ile gizlidir.
3. Jinja, rolü JS'e gömer (`{{ user.role | tojson }}`); JS yalnızca `role === "admin"` ise `display:block` yapar.
4. Böylece `alice`/`bob` butonu **hiç göremez**, `admin` görür.

**Neden bu bir güvenlik kontrolü değildir:**
- **Client saldırganındır.** HTML/CSS/JS kullanıcının tarayıcısında çalışır; kullanıcı DevTools ile DOM'u değiştirebilir, `display:none`'u kaldırabilir, hatta JS'i hiç çalıştırmadan ham HTTP isteği kurabilir (curl/Burp). Gizlenen bir buton, "erişilemez" bir işlem değildir.
- **Görünürlük ≠ yetkilendirme.** Butonu gizlemek bir **UX** kararıdır (kullanıcıya yapamayacağı işlemi göstermemek); bir **güvenlik** kararı değildir. Güvenlik kararı, isteğin fiilen işlendiği yerde — sunucuda — verilmelidir.
- **Endpoint keşfi kolaydır.** URL desenleri (`/api/admin/users/{id}`) tahmin edilebilir, JS bundle'ında görünür veya proxy trafiğinde açığa çıkar. "Kimse bu endpoint'i bilmiyor" varsayımı da security through obscurity'dir.

Kısaca: frontend'deki gizleme, saldırganın *göremediği* değil, *engellenmediği* bir kontroldür. Gerçek engel yalnızca sunucuda kurulabilir.

## Etki
- **Bütünlük (Integrity) — yüksek:** Herhangi bir kayıtlı kullanıcı, yetkisi olmadığı halde diğer kullanıcı kayıtlarını kalıcı olarak silebilir. `id` üzerinde döngü kurularak bu, tekil silmeden **tüm kullanıcı tabanının imhasına** ölçeklenebilir.
- **Kullanılabilirlik (Availability) — yüksek:** Silinen kullanıcı sisteme erişimini tamamen kaybeder. Admin kaydının silinmesi yönetimsel işlevi tümüyle ortadan kaldırabilir; toplu silme uygulamayı fiilen kullanılamaz hale getirir.
- **İş etkisi:** Geri döndürülemez veri kaybı (soft-delete olmadığı için kayıt tamamen gider), hesap devre dışı bırakma yoluyla hedefli sabotaj, ve düzenleyici/operasyonel sonuçlar. Bu, salt-okunur senaryolardan (1 ve 2) niteliksel olarak daha yıkıcı bir etkidir.
- **Gizlilik:** Birincil etki değil; yalnızca yanıt gövdesinde silinen kullanıcının username'i yansıtılıyor (önemsiz).

## Remediation Önerisi

Güvenlik kuralı, client-side gizlemeye ek olarak (onun yerine değil) **sunucuda** uygulanmalıdır. `fixed/main.py` içinde DELETE endpoint'ine, silme işlemi çalıştırılmadan önce rol kontrolü eklendi:

```python
@app.delete("/api/admin/users/{user_id}")
def delete_user(user_id: int, current_user: sqlite3.Row = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    ...  # sadece bu noktadan sonra DELETE çalışır
```

- **Sunucu tarafı yetkilendirme zorunludur.** Erişim kontrolü kararı, isteğin fiilen işlendiği güvenilir katmanda (sunucu) verilmelidir. `current_user["role"]` değeri, Senaryo 2'deki gibi, otoriter kaynaktan (DB'den, `get_current_user` içinde taze) okunur — client'tan gelen hiçbir veriye güvenilmez.
- **Client-side kontroller yalnızca UX içindir.** Butonu gizlemek iyi bir kullanıcı deneyimidir (kullanıcıya yapamayacağı işlemi göstermemek) ve korunmalıdır — ancak *tek* kontrol olarak değil. Doğru mimari: "sunucuda zorla, client'ta ipucu ver" (enforce on server, hint on client).
- **403 vs 401 ayrımı korunur:** Oturumsuz istek `401` (kimliğini kanıtla), giriş yapmış ama yetkisiz istek `403` (yetkin yok) alır. Bu, authentication ve authorization'ın ayrı katmanlar olduğunu HTTP semantiğinde de yansıtır.
- **Uzun vadeli öneri:** Yönetim endpoint'leri çoğaldıkça, her birine elle `if role != "admin"` yazmak yerine merkezi bir `require_role("admin")` dependency'si kullanmak, kontrolü unutma riskini (tam da bu zafiyetin sebebini) yapısal olarak azaltır.

## Test Notu — `POST /reset-db` Hakkında

Bu modülde, silme testleri DB'yi kalıcı olarak boşaltmasın diye bir **`POST /reset-db`** endpoint'i eklenmiştir. Bu endpoint tabloyu temizleyip seed kullanıcılarını (alice/bob/admin) sabit ID'lerle (1/2/3) yeniden yükler ve testlerin deterministik biçimde tekrarlanmasını sağlar.

⚠️ **Bu endpoint yalnızca bu lab ortamı içindir.** Gerçek bir uygulamada, kimlik doğrulaması olmadan tüm veriyi silip yeniden yükleyen böyle bir endpoint **asla bulunmamalıdır** — kendisi başlı başına kritik bir Broken Access Control / veri imha zafiyeti olurdu. Üretim koduna taşınmamalıdır.

### Fixed Version Verification

Remediation `fixed/main.py`'de uygulandı ve `vulnerable` ile aynı senaryolar `fixed` üzerinde tekrarlandı (yukarıdaki Sonuç Tablosu). Vulnerable sürümde `alice` ile `200 OK` + Bob'un silinmesiyle sonuçlanan aynı istek, fixed sürümde `403 Forbidden` döndürüyor ve hiçbir kayıt silinmiyor; meşru `admin` ise `200` ile silebiliyor; anonim istek her iki sürümde `401` alıyor. Bu, CWE-602 zafiyetinin sunucu tarafı yetkilendirme ile kapatıldığının curl ile doğrulanmış kanıtıdır.
