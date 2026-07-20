# [A01:2025] IDOR → Horizontal Privilege Escalation

**Modül:** 01-broken-access-control
**Senaryo:** Kullanıcının 'acct'/id parametresini değiştirerek başka bir kullanıcının hesap verisine erişebilmesi
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed) — Burp Suite görsel kanıtı ileride eklenecek (şu an Burp Suite kurulu değil)

> ℹ️ **Not (OWASP Top 10:2025):** Bu kategori 2025 sürümünde de A01 — Broken Access Control olarak yerini koruyor ve BOLA/BFLA ile SSRF'yi açıkça kapsıyor.

## Bu Kategori Nedir?
Erişim kontrolü, bir kullanıcının yalnızca yetkili olduğu kaynaklara/işlemlere erişebilmesini sağlar. Bu kategori, authentication ("sen kimsin") ile authorization ("bu işlemi yapmaya yetkin var mı") arasındaki farkın karıştırılmasından doğar. Yaygın türleri: IDOR/BOLA (nesne düzeyinde), BFLA (fonksiyon düzeyinde), client-side'a güvenme. Temel korunma: her istekte sunucu tarafında authorization kontrolü, deny-by-default, least privilege.

## CVSS 3.1
- **Skor:** 6.5 (Medium)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

**Gerekçe:**
- **AV:N** — Endpoint HTTP üzerinden ağ genelinde erişilebilir, lokal erişim gerekmiyor.
- **AC:L** — Saldırı için özel bir koşul yok; URL'deki `account_id` path parametresi değiştiriliyor.
- **PR:L** — Saldırganın anonim değil, en az kendi (düşük yetkili) hesabıyla giriş yapmış olması gerekiyor — saldırı bir authenticated kullanıcının kendi session'ını kullanarak başkasının verisine yatay olarak sıçramasıyla gerçekleşiyor.
- **UI:N** — Başka bir kullanıcının etkileşimi gerekmiyor.
- **S:U** — Yetkilendirme zafiyeti aynı uygulama/yetki alanı içinde kalıyor, farklı bir güvenlik otoritesine (component) sıçramıyor.
- **C:H** — Finansal veri (`balance`) ve iletişim verisi (`email`, `phone_number`) birlikte, hiçbir maskeleme olmadan, sıralı ID'ler taranarak **tüm kullanıcı tabanı için** sızdırılabiliyor.
- **I:N / A:N** — İncelenen endpoint salt-okunur (`GET`); bu repro'da veri değişikliği veya kullanılamazlık etkisi gösterilmedi.

## Risk Seviyesi
- [ ] Low
- [x] Medium
- [ ] High
- [ ] Critical

## İlgili OWASP ASVS Kontrol Maddesi
- **ASVS 4.0.3 — V4.2.1:** *"Verify that sensitive data and APIs are protected against Insecure Direct Object Reference (IDOR) attacks targeting creation, reading, updating and deletion of records, such as creating or updating someone else's record, viewing everyone's records, or deleting all records."*
- Destekleyici madde: **V4.1.1** — Erişim kontrolü kararlarının yalnızca güvenilir sunucu tarafı katmanında, client'ın gönderdiği kimliklere (`account_id` gibi) körü körüne güvenmeden verilmesi gerektiğini belirtir.

## Açıklama
`GET /api/accounts/{account_id}` endpoint'i, isteği yapan kullanıcının **kimliğini doğruluyor** (`get_current_user` dependency'si ile geçerli bir session şart koşuyor) ama **yetkilendirme yapmıyor** — yani "bu kullanıcı giriş yapmış mı?" sorusuna cevap veriyor, fakat "bu kullanıcı *bu spesifik* hesaba erişebilir mi?" sorusunu hiç sormuyor.

`vulnerable/main.py` içindeki `get_account` fonksiyonu (satır 140-152), path'ten gelen `account_id` değerini doğrudan SQL sorgusuna geçiriyor ve session'daki `current_user["id"]` ile hiçbir karşılaştırma yapmadan sonucu döndürüyor:

```python
@app.get("/api/accounts/{account_id}")
def get_account(account_id: int, current_user: sqlite3.Row = Depends(get_current_user)):
    conn = get_db_connection()
    account = conn.execute(
        "SELECT id, username, email, balance, phone_number FROM users WHERE id = ?",
        (account_id,),
    ).fetchone()
    conn.close()
    if account is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")
    return dict(account)
```

Bu, klasik bir **Broken Object Level Authorization (BOLA / IDOR)** zafiyetidir: kimlik doğrulama (authentication) var, nesne düzeyinde yetkilendirme (object-level authorization) yok. Session cookie'nin `itsdangerous` ile imzalanmış olması burada bir savunma sağlamıyor — çünkü saldırgan kendi (geçerli, sahte olmayan) cookie'sini kullanıyor; sorun cookie'nin sahteciliğe açık olması değil, sunucunun cookie içindeki `user_id` ile URL'deki `account_id`'yi hiç karşılaştırmaması.

## Repro Adımları

**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8000` üzerinde çalışıyor (Alice ve Bob seed kullanıcıları `seed_db()` ile otomatik oluşturuluyor).

1. **Alice olarak giriş yap ve session cookie'sini al:**
   ```
   curl -i -c cookies.txt -X POST http://127.0.0.1:8000/login \
     -H "Content-Type: application/json" \
     -d '{"username": "alice", "password": "AliceStrongPass!23"}'
   ```
   **Sonuç:** `200 OK`, gövde `{"message": "login successful"}`, `Set-Cookie: session=<itsdangerous imzalı token>`.
   Cookie değerinin base64 kısmı decode edildiğinde düz metin JSON `{"user_id": 1}` görülüyor — token **şifrelenmemiş** (sadece imzalanmış/tamper-proof), yani içeriği okunabilir durumda; fakat imza sayesinde `user_id` değeri client tarafından değiştirilip tekrar gönderilemiyor (imza doğrulaması başarısız olur). Bu noktada zafiyet cookie'nin sahteciliğe açık olması değil, aşağıdaki adımda görüleceği gibi sunucunun yetkilendirme kontrolü yapmamasıdır.

2. **Alice kendi hesap verisine erişiyor (beklenen/meşru davranış):**
   ```
   curl -i -b cookies.txt http://127.0.0.1:8000/api/accounts/1
   ```
   **Sonuç:** `200 OK`
   ```json
   {"id": 1, "username": "alice", "email": "alice@example.com", "balance": 2500, "phone_number": "+90 532 000 00 01"}
   ```
   Bu adım tek başına bir zafiyet değil — kullanıcı kendi verisine erişiyor.

3. **Alice'in session'ı ile Bob'un hesabına erişim denemesi (IDOR kanıtı):**
   ```
   curl -i -b cookies.txt http://127.0.0.1:8000/api/accounts/2
   ```
   **Sonuç:** `200 OK` — **hiçbir 403/401 dönmüyor**
   ```json
   {"id": 2, "username": "bob", "email": "bob@example.com", "balance": 750, "phone_number": "+90 532 000 00 02"}
   ```
   Alice'in oturumu ile, sadece URL'deki ID'yi `1` → `2` değiştirerek Bob'a ait email, bakiye ve telefon numarasına tam erişim sağlandı. ID'ler `AUTOINCREMENT` ile sıralı üretildiği için, saldırgan `account_id`'yi 1'den itibaren artırarak **uygulamadaki tüm kullanıcıların** verisini otomatik olarak taşıyabilir (yatay yetki yükselmesi + toplu veri sızıntısı).

*(Burp Suite ile bu üç isteğin Proxy/Repeater kayıtları görsel kanıt olarak eklenecek — bkz. ilgili ekran görüntüleri.)*

## Etki
- **Gizlilik ihlali (Confidentiality):** Herhangi bir kayıtlı kullanıcı, kendi session'ı ile sistemdeki **her** kullanıcının email adresini, hesap bakiyesini ve telefon numarasını sırayla okuyabilir. Bu, tekil bir sızıntı değil, ID'ler üzerinde döngü kurularak **toplu (mass) veri sızıntısına** dönüştürülebilir bir zafiyettir.
- **İş etkisi:** Bakiye bilgisi gibi finansal verinin sızması, kullanıcıların hedefli sosyal mühendislik/dolandırıcılık saldırılarına maruz kalma riskini artırır (örn. yüksek bakiyeli hesapların hedef alınması).
- **Bütünlük/Kullanılabilirlik:** Bu repro'da test edilen endpoint salt-okunur olduğu için doğrudan veri değişikliği veya hizmet kesintisi gösterilmedi; ancak aynı yetkilendirme eksikliği deseni yazma (`PUT`/`PATCH`/`DELETE`) endpoint'lerinde de mevcutsa, etki bütünlük ihlaline (örn. başkasının bakiyesini değiştirme) kadar genişleyebilir — bu, kapsam dışı bir varsayım olup ayrı test gerektirir.

## Remediation Önerisi
`get_account` endpoint'ine, sorgu çalıştırılmadan önce **object-level authorization** kontrolü eklenmelidir:

```python
if account_id != current_user["id"]:
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this account")
```

- **403 (Forbidden), 404 (Not Found) değil:** `404` dönmek "kaynak yok" ile "kaynak var ama bu kullanıcı erişemiyor" ayrımını gizler; bu, API tüketicisi ve geliştirici için anlamsal belirsizlik yaratır ve hata ayıklamayı zorlaştırır. Bu senaryoda `account_id` değerleri zaten sıralı ve tahmin edilebilir olduğu için (`AUTOINCREMENT`), "kaynağın var olup olmadığını" `404` ile gizlemenin ek bir güvenlik değeri yoktur — asıl kritik kontrol, kimin hangi kaynağa erişebileceğinin net ve doğru şekilde uygulanmasıdır. Bu nedenle `403` tercih edilmelidir.
- Uzun vadeli/genel çözüm olarak, her kaynağa özgü ID karşılaştırması yazmak yerine merkezi bir yetkilendirme dependency'si (örn. `require_owner(resource_id)`) tanımlanması, benzer endpoint'ler çoğaldıkça tutarlılığı ve test edilebilirliği artırır.

### Fixed Version Verification

Yukarıdaki remediation önerisi `fixed/main.py` içinde uygulandı (`get_account` endpoint'ine, DB sorgusundan önce object-level authorization kontrolü eklendi) ve `vulnerable` ile birebir aynı senaryo `fixed` sürüm üzerinde tekrar edildi.

**Ortam:** `fixed/main.py`, `vulnerable` ile çakışmaması için ayrı bir portta çalıştırıldı (kendi `accounts.db`'si ile). Fixed sürüm port 8001'de çalıştırılır (vulnerable: 8000).

1. **Alice olarak giriş yap** (aynı kimlik bilgileri) → `200 OK`, session cookie alınıyor.
2. **Alice kendi hesabına erişiyor** — `GET /api/accounts/1` (Alice'in session'ı ile) → `200 OK`, kendi verisi meşru şekilde dönüyor. (Kontrol, sahibi engellemiyor.)
3. **Alice'in session'ı ile Bob'un hesabına erişim denemesi** — `GET /api/accounts/2`:
   **Sonuç:** `403 Forbidden`
   ```json
   {"detail": "Not authorized to access this account"}
   ```

Vulnerable sürümde `200 OK` ile Bob'un tüm verisini (email, `balance=750`, phone_number) döndüren aynı istek, fixed sürümde artık **hiçbir veri sızdırmadan** `403 Forbidden` döndürüyor. Bu, remediation'ın IDOR/BOLA zafiyetini kapattığının curl ile doğrulanmış kanıtıdır.

---

## Ek Gözlem (Scope Dışı)

Test sırasında `POST /login` endpoint'inde bir **timing-based username enumeration** olasılığı fark edildi:

- **Geçersiz kullanıcı adı** gönderildiğinde (`vulnerable/main.py` satır 113-114), sorgu `user is None` kontrolüne hemen takılıp `401 Unauthorized` döndürüyor — Argon2 doğrulaması hiç çalışmıyor, yanıt **hızlı**.
- **Geçerli kullanıcı adı + yanlış şifre** gönderildiğinde ise akış `password_hasher.verify(...)` satırına kadar ilerliyor; Argon2 kasıtlı olarak CPU/bellek açısından pahalı bir hash fonksiyonu olduğu için bu doğrulama **gözle görülür şekilde daha uzun** sürüyor.
- Bu süre farkı, saldırganın yanıt sürelerini ölçerek (isteği çok sayıda tekrarlayıp ortalama alarak) hangi kullanıcı adlarının sistemde **kayıtlı olduğunu** tahmin etmesine imkân tanıyabilir — klasik bir kullanıcı adı enumeration side-channel'ı.

**Kapsam notu:** Bu bulgu **OWASP A07:2021 — Identification and Authentication Failures** kategorisine giriyor ve bu modülün odağı olan **A01:2021 — Broken Access Control** kapsamının dışındadır. CLAUDE.md'deki proje kuralına göre ("yeni bir zafiyet kategorisine geçmeden önce önceki kategori tamamlanmış ve raporlanmış olmalı") bu modülün kapsamı genişletilmeyecek; bulgu burada **gözlem** olarak kayıt altına alınmış olup, ileride ayrı bir Authentication/Session modülünde (sabit gecikme / dummy hash karşılaştırması gibi remediation önerileriyle birlikte) ele alınması önerilir.
