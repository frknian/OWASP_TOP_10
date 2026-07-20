# [A07:2025] Authentication Failures → Credential Stuffing (Koruma Yok)

**Modül:** 07-authentication-failures
**Senaryo:** `POST /login` username+password alır ve argon2id ile doğru şekilde doğrular (hashing kusuru YOK). Ama hiçbir deneme limiti, gecikme veya kilitleme yoktur — saldırgan aynı kullanıcıya karşı saniyeler içinde onlarca parola deneyebilir.
**Portlar:** vulnerable `8190`, fixed `8191`
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

## Bu Kategori Nedir?
Kimlik doğrulama ve oturum yönetimindeki zayıflıklar — brute-force koruması yokluğu, tek faktörlü kimlik doğrulama, yanlış session timeout/logout. Temel korunma: rate limiting/kilitleme, MFA, güvenli server-side session yönetimi (gerçek timeout, gerçek logout).

## CVSS 3.1
- **Skor:** 8.1 (High)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

**Gerekçe:**
- **AV:N / AC:L / PR:N / UI:N** — Uzaktan, kimlik doğrulamasız, basit bir istek döngüsüyle; özel koşul gerekmez.
- **C:H / I:H** — Tam hesap devralma: doğru parola bulunduğunda hesabın tüm verisine ve işlem yetkisine erişilir.
- **A:N** — Servisin genel erişilebilirliği etkilenmez.

**Not:** Bu, "zayıf parola" zafiyeti değildir — hashing (argon2id) doğrudur. Zafiyet, saldırganın parolayı deneme HAKKININ sınırsız olmasıdır. En güçlü parola bile, deneme sayısı sınırsızsa ve parola bir "Top 10.000" listesindeyse, istatistiksel olarak zamanla bulunur.

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [x] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V2.2.1:** *"Verify that anti-automation controls are effective at mitigating breached credential testing, brute force, and account lockout attacks."*
- **V2.2.2:** Kullanıcı adı enumeration'ına karşı da aynı hata mesajının dönmesi (bu senaryoda zaten jenerik `"Geçersiz kullanıcı adı veya parola"` kullanılıyor).
- **CWE-307:** Improper Restriction of Excessive Authentication Attempts
- Destekleyici: **CWE-799** (Improper Control of Interaction Frequency)

## Açıklama
```python
# vulnerable/main.py
@app.post("/login")
def login(req: LoginRequest):
    # ZAFIYET: deneme sayacı, gecikme veya kilitleme YOK.
    user = USERS.get(req.username)
    try:
        password_hasher.verify(user["password_hash"], req.password)
    except VerifyMismatchError:
        raise HTTPException(401, "Geçersiz kullanıcı adı veya parola")
    return {"authenticated": True, ...}
```
Kodun kendisinde bug yoktur — argon2id doğru kullanılıyor, hata mesajı jenerik (enumeration'a açık değil). Eksik olan, deneme *frekansını* sınırlayan bir kontroldür. Seed kullanıcı `carol`, gerçek dünya davranışını yansıtan yaygın bir parola (`Password1`) kullanır; sınırsız deneme hakkıyla bu, zamanla kaçınılmaz olarak bulunur.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8190`.

1. **Yaygın parola listesiyle `carol`'a karşı deneme:**
   ```
   for p in 123456 password qwerty123 letmein1 Welcome1 Password1 Admin123 Iloveyou1 Sunshine1 Football1; do
     R=$(curl -s -X POST http://127.0.0.1:8190/login \
       -H "Content-Type: application/json" -d "{\"username\": \"carol\", \"password\": \"$p\"}")
     echo "$p -> $R"
   done
   ```
   **Beklenen:** İlk 5 deneme `401`, `Password1` denendiğinde `{"authenticated": true, ...}` — hiçbir gecikme/kilitleme devreye girmez, tüm istekler aynı hızda işlenir.

2. **Deneme hızını ölç (koruma yokluğunun kanıtı):**
   ```
   time (for i in $(seq 1 20); do
     curl -s -o /dev/null -X POST http://127.0.0.1:8190/login \
       -H "Content-Type: application/json" -d '{"username": "carol", "password": "yanlis-deneme"}'
   done)
   ```
   **Beklenen:** 20 istek saniyenin çok altında biter — hiçbir artan gecikme yok.

**Test sonucu (curl ile doğrulandı, 12 yaygın parolalık liste — `Password1` bilinçli olarak sırada son):**

*Vulnerable (8190):*
- `123456` → `401`, `password` → `401`, `qwerty123` → `401`, `letmein1` → `401`, `Welcome1` → `401`, `Admin123` → `401`, `Iloveyou1` → `401`, `Sunshine1` → `401`, `Football1` → `401`, `Monkey123` → `401`, `Dragon123` → `401`, **`Password1` → `200`** — 12. denemede, hiçbir gecikme/kilitleme olmadan doğru parola bulundu. ✅

*Fixed (8191), aynı liste ve sıra:*

| # | Parola | HTTP | Not |
|---|---|---|---|
| 1 | `123456` | `401` | `failed_attempts: 1` |
| 2 | `password` | `401` | `failed_attempts: 2` |
| 3 | `qwerty123` | `401` | `failed_attempts: 3` |
| 4 | `letmein1` | `401` | `failed_attempts: 4` |
| 5 | `Welcome1` | **`429`** | kilitleme tetiklendi (`locked_for_seconds: 30`) |
| 6–12 | `Admin123` … **`Password1`** | **`429`** (hepsi) | kilitli — doğru parola (12. sırada) hiç sıraya giremedi |

- **Kilitliyken doğru parola tekrar denendi:** `{"username":"carol","password":"Password1"}` → **`429`** `{"error":"Çok fazla başarısız deneme","locked_for_seconds":30}` — kilitleme, doğru parolayı da geçersiz kılıyor (bilinçli tasarım kararı). ✅

## Etki
- **Tam hesap devralma:** Zayıf/yaygın parola kullanan her hesap, otomatikleştirilmiş bir sözlük saldırısıyla ele geçirilebilir.
- **Ölçeklenebilirlik:** Saldırı tek kullanıcıyla sınırlı değildir; "password spraying" ile çok sayıda kullanıcıya karşı az sayıda yaygın parola denenerek (tespit eşiğinin altında kalarak) hesaplar toplu ele geçirilebilir.
- **Zincirleme risk:** Ele geçirilen hesap, diğer sistemlere (parola tekrar kullanımı) veya iç kaynaklara sıçrama noktası olur.

## Remediation Önerisi
```python
# fixed/main.py
if entry["locked_until"] and time.time() < entry["locked_until"]:
    raise HTTPException(429, {"locked_for_seconds": retry_after}, headers={"Retry-After": ...})
...
entry["failed_count"] += 1
if entry["failed_count"] >= MAX_ATTEMPTS:          # 5
    entry["locked_until"] = time.time() + LOCKOUT_SECONDS   # 30 sn
    raise HTTPException(429, ...)
```
- **Kullanıcı bazlı deneme sayacı + geçici kilitleme:** 5 başarısız denemeden sonra hesap 30 saniye kilitlenir (`429` + `Retry-After`).
- **Kilitliyken parola kontrol edilmez:** Doğru parola gönderilse bile kilitleme penceresinde reddedilir — bu, saldırgana "doğru parolayı buldunuz ama zamanlaması yanlış" bilgisini vermemek için bilinçli bir tasarım kararıdır.
- **Başarılı girişte sayaç sıfırlanır:** Meşru kullanıcı arada bir yanlış yazarsa cezalandırılmaz.
- **Gerçek dünyada ek katmanlar:** CAPTCHA (şüpheli frekansta), IP/ASN bazlı hız sınırlama, bilinen sızıntı listeleriyle (HaveIBeenPwned API) parola kontrolü, anormal coğrafya/cihaz tespiti.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8191`.

1. **Aynı 10 parolalık deneme artık kilitleniyor:**
   ```
   curl -s -X POST http://127.0.0.1:8191/reset >/dev/null
   for p in 123456 password qwerty123 letmein1 Welcome1 Password1 Admin123; do
     curl -s -X POST http://127.0.0.1:8191/login \
       -H "Content-Type: application/json" -d "{\"username\": \"carol\", \"password\": \"$p\"}"
     echo
   done
   ```
   **Beklenen:** İlk 5 istek `401` (`failed_attempts` sayacı artarak), 6. ve sonrası **`429`** `{"error":"Çok fazla başarısız deneme — hesap geçici kilitlendi","locked_for_seconds":30}` — doğru parola `Password1`'e sıra gelmeden hesap kilitlenir.
2. **Kilitliyken doğru parola da reddedilir:**
   ```
   curl -s -X POST http://127.0.0.1:8191/login \
     -H "Content-Type: application/json" -d '{"username": "carol", "password": "Password1"}'
   ```
   **Beklenen:** `429` — kilitleme penceresi doğru parolayı da geçersiz kılar.
3. **Başarılı giriş sayaç sıfırlar:** `alice` doğru parolasıyla giriş → `200`; ardından `GET /status` ile sayaçların etkilenmediği gözlemlenir.

---

## Gerçek Dünyada Tespit / Önleme
- **Rate limiting altyapıları:** API gateway seviyesinde (Kong, Envoy, AWS WAF) veya framework middleware'i (`slowapi`, `django-ratelimit`) ile kullanıcı/IP bazlı hız sınırlama.
- **Merkezi kimlik doğrulama servisleri:** Auth0, Okta, AWS Cognito gibi servisler bu korumayı varsayılan olarak sağlar — kimlik doğrulamayı uygulamadan ayırmak bu sınıf zafiyeti yapısal olarak önler.
- **Sızıntı istihbaratı entegrasyonu:** HaveIBeenPwned API ile kayıt/parola değişimi sırasında bilinen sızmış parolaların engellenmesi (NIST 800-63B önerisi).
- **OWASP ASVS V2.2 checklist:** Anti-automation, kilitleme, CAPTCHA ve bildirim (şüpheli girişimde kullanıcıya e-posta) maddeleri denetim listesine eklenir.
- **Davranışsal izleme:** Aynı IP'den çok sayıda farklı kullanıcı adına deneme (credential stuffing) veya aynı kullanıcıya çok sayıda farklı parola denemesi (brute-force) için SIEM alarm kuralları.
