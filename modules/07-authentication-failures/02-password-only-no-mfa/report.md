# [A07:2025] Authentication Failures → Tek Faktör Olarak Parola (MFA Yokluğu)

**Modül:** 07-authentication-failures
**Senaryo:** `POST /login` doğru parola girilince DOĞRUDAN tam erişim (session) verir. Kimlik doğrulama tamamen tek bir faktöre (bilinen bir sır: parola) dayanır.
**Portlar:** vulnerable `8200`, fixed `8201`
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

## Bu Kategori Nedir?
Kimlik doğrulama ve oturum yönetimindeki zayıflıklar — brute-force koruması yokluğu, tek faktörlü kimlik doğrulama, yanlış session timeout/logout. Temel korunma: rate limiting/kilitleme, MFA, güvenli server-side session yönetimi (gerçek timeout, gerçek logout).

## CVSS 3.1
- **Skor:** 8.1 (High)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

**Gerekçe:**
- **AV:N / AC:L / PR:N / UI:N** — Parola ele geçirildikten sonra saldırı basit bir istektir; özel koşul gerekmez.
- **C:H / I:H** — Parolanın tek başına ele geçirilmesi (phishing, data breach, credential stuffing, keylogger) doğrudan tam hesap erişimine dönüşür.
- **A:N** — Servisin genel erişilebilirliği etkilenmez.

**Not:** Bu bulgunun asıl değeri, parolanın *nasıl* ele geçirildiğinden bağımsız olmasıdır — MFA yokluğu, parolanın ele geçirilmesiyle hesap devralma arasındaki **tek** engeli ortadan kaldırır. Modül 07 Senaryo 1 (credential stuffing) ile birleştiğinde etki çarpanlanır: brute-force ile bulunan parola, MFA olmadığı için anında tam erişime dönüşür.

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [x] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V2.8.1:** *"Verify that time-based OTP (TOTP) ... or other soft token ... can be used as a second factor in a multi-factor authentication scheme."*
- **V2.8.2 / V2.8.7:** MFA'nın kritik işlemler ve hassas veri erişimi için zorunlu kılınması.
- **CWE-308:** Use of Single-factor Authentication
- Destekleyici: **CWE-287** (Improper Authentication)

## Açıklama
```python
# vulnerable/main.py
@app.post("/login")
def login(req: LoginRequest):
    password_hasher.verify(user["password_hash"], req.password)   # başarılıysa...
    token = secrets.token_urlsafe(24)
    SESSIONS[token] = req.username
    return {"authenticated": True, "session_token": token}   # ...DOĞRUDAN tam erişim
```
Kimlik doğrulama akışında tek bir karar noktası vardır: "parola doğru mu?" Cevap evet ise, hiçbir ek doğrulama olmadan tam yetkili bir session token'ı verilir. Bu, "bildiğin bir şey" (knowledge factor) dışında hiçbir faktör talep etmeyen klasik tek-faktörlü tasarımdır.

### NIST 800-63B Perspektifi
NIST Special Publication 800-63B (Digital Identity Guidelines), 2017'deki güncellemesinden itibaren şu duruşu benimser:
- **Parola karmaşıklığı zorunluluğu** (büyük/küçük harf + rakam + sembol karışımı) ve **periyodik zorunlu parola değişimi**, artık **kötü pratik** olarak sınıflandırılır — kullanıcıları tahmin edilebilir desenlere (`Parola1!`, `Parola2!`) ve parola tekrar kullanımına iter, gerçek güvenlik kazancı sağlamaz.
- Bunun yerine önerilen: **uzun ama basit parolalar** (passphrase) + **bilinen sızıntı listeleriyle kontrol** + ***"AAL2/AAL3 için ikinci bir kimlik doğrulama faktörü."*** Yani asıl savunma katmanı parola karmaşıklığı değil, **MFA**'dır.
- Bu senaryo tam olarak bu prensibin ihlalini gösterir: parola ne kadar karmaşık olursa olsun (`Tr@ck3r-Alice-99!` gibi güçlü bir parola dahi), MFA yoksa parolanın ele geçirilmesi (kod içinde değil, kullanıcı tarafında — phishing vb.) doğrudan hesap devralmaya dönüşür.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8200`.

1. **Doğru parolayla giriş → doğrudan tam erişim:**
   ```
   curl -s -X POST http://127.0.0.1:8200/login \
     -H "Content-Type: application/json" \
     -d '{"username": "alice", "password": "Tr@ck3r-Alice-99!"}'
   ```
   **Beklenen:** `{"authenticated": true, "mfa_required": false, "session_token": "...", ...}` — ikinci bir doğrulama adımı hiç sorulmaz.

2. **Token'ı korumalı kaynakta kullan:**
   ```
   TOKEN=$(curl -s -X POST http://127.0.0.1:8200/login -H "Content-Type: application/json" \
     -d '{"username": "alice", "password": "Tr@ck3r-Alice-99!"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["session_token"])')
   curl -s "http://127.0.0.1:8200/profile?session_token=$TOKEN"
   ```
   **Beklenen:** `200` — parola tek başına, hiçbir ek doğrulama olmadan tam profile erişimi sağladı.

**Test sonucu (curl ile doğrulandı):**

*Vulnerable (8200):*
- Doğru parola → `200` `{"authenticated":true,"mfa_required":false,"session_token":"..."}` — **doğrudan tam session**, ikinci adım hiç sorulmadı. ✅
- Bu token ile `GET /profile` → `200` — tek faktörle tam erişim doğrulandı. ✅

*Fixed (8201):*
- Doğru parola → `200` ama `{"authenticated":false,"mfa_required":true,"pending_token":"...","session_token" YOK}` — parola doğru olduğu halde tam erişim verilmedi. ✅
- `pending_token`'ı `session_token` olarak `/profile`'da denendi → **`401`** "Geçersiz veya süresi dolmuş session" — pending_token hiçbir korumalı kaynağı açmıyor. ✅
- Yanlış OTP (`000000`) ile `POST /login/verify-mfa` → **`401`** `{"detail":"Geçersiz OTP kodu"}`. ✅
- Sunucu konsolundan alınan gerçek OTP (`[MFA SİMÜLASYONU] alice için OTP kodu: ...`) ile `POST /login/verify-mfa` → **`200`** `{"authenticated":true,"session_token":"..."}` — ancak şimdi tam session verildi. ✅
- Bu tam session ile `GET /profile` → `200` `"parola + MFA ile erişilen korumalı profildir"` — iki faktör tamamlanınca erişim açıldı. ✅

## Etki
- **Phishing'in doğrudan hesap devralmaya dönüşmesi:** Kullanıcı sahte bir giriş sayfasına parolasını yazarsa, saldırgan anında ve kalıcı tam erişim elde eder — hiçbir ek engel yok.
- **Data breach zincirlenmesi:** Başka bir sitede sızan ve burada tekrar kullanılan bir parola, doğrudan bu sisteme de erişim sağlar (credential stuffing ile Senaryo 1'in doğal uzantısı).
- **Tespit edilemezlik:** MFA olmadığında, "bu her zamanki kullanıcı mı yoksa çalınan bir parolayla giriş yapan biri mi?" sorusunu ayırt edecek hiçbir sinyal yoktur.

## Remediation Önerisi
```python
# fixed/main.py — iki adımlı akış
@app.post("/login")
def login(req: LoginRequest):
    password_hasher.verify(...)                       # 1. faktör: parola
    pending_token = secrets.token_urlsafe(24)
    otp_code = f"{random.randint(0, 999999):06d}"
    PENDING_MFA[pending_token] = {...}
    print(f"[MFA SİMÜLASYONU] OTP kodu: {otp_code}")  # gerçek sistemde SMS/push/TOTP
    return {"authenticated": False, "mfa_required": True, "pending_token": pending_token}

@app.post("/login/verify-mfa")
def verify_mfa(req: VerifyMfaRequest):
    # 2. faktör: OTP doğrulanmadan TAM session verilmez
    ...
    session_token = secrets.token_urlsafe(24)
    SESSIONS[session_token] = entry["username"]
    return {"authenticated": True, "session_token": session_token}
```
- **İki adımlı akış:** Doğru parola artık "erişim izni" değil, "ikinci faktöre geçiş izni" anlamına gelir.
- **OTP simülasyonu:** 6 haneli kod, 5 dakika geçerli, tek kullanımlık (`pending_token` tüketilir). Gerçek sistemde bu adım TOTP (Google Authenticator), SMS veya push bildirimi olurdu; bu labda sunucu konsoluna yazılır (**"MFA SİMÜLASYONU"** notuyla) — gerçek SMS/e-posta gönderilmez.
- **Tam session yalnızca MFA sonrası:** `/profile` gibi korumalı kaynaklara erişim, `SESSIONS` sözlüğüne yalnızca `verify-mfa` başarılı olduğunda giren token'larla mümkündür.
- **Gerçek dünyada tercih sırası (NIST 800-63B AAL2/AAL3):** TOTP/push bildirimi > SMS OTP (SIM swap riski nedeniyle en zayıf MFA biçimi sayılır, ama hiç MFA olmamasından çok daha iyidir).

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8201`.

1. **Doğru parola artık tam erişim vermiyor:**
   ```
   curl -s -X POST http://127.0.0.1:8201/login \
     -H "Content-Type: application/json" -d '{"username": "alice", "password": "Tr@ck3r-Alice-99!"}'
   ```
   **Beklenen:** `{"authenticated": false, "mfa_required": true, "pending_token": "...", ...}` — `session_token` YOK.
2. **OTP'yi konsoldan al ve doğrula:**
   ```
   # uvicorn konsolunda: [MFA SİMÜLASYONU] alice için OTP kodu: 483920 (5 dk geçerli)
   curl -s -X POST http://127.0.0.1:8201/login/verify-mfa \
     -H "Content-Type: application/json" -d '{"pending_token": "<ADIM-1-TOKEN>", "otp_code": "483920"}'
   ```
   **Beklenen:** `{"authenticated": true, "session_token": "...", ...}` — TAM session ancak şimdi verildi.
3. **Yanlış OTP reddedilir:** Adım 1 tekrarlanıp yanlış bir kod (`000000`) gönderilirse → `401 "Geçersiz OTP kodu"`.

> **Not (Interactive Lab entegrasyonu):** `fixed/main.py`'ye `GET /lab/otp-inbox` adında, açıkça "lab-only" olarak işaretlenmiş bir endpoint eklendi. Bu, control-panel'in alt süreçleri `stdout=DEVNULL` ile başlatması nedeniyle konsola yazılan OTP'nin panelden okunamaması sorununu çözer. Güvenlik özelliğini **BOZMAZ**: `POST /login` yanıtı hâlâ OTP'yi döndürmez, yalnızca parolayı bilen bir saldırgan login yanıtından ikinci faktörü elde edemez. Bu endpoint yalnızca demo/test kolaylığı içindir, gerçek bir uygulamada bulunmamalıdır (tıpkı Modül 03'teki `/reset-db` gibi).

---

## Gerçek Dünyada Tespit / Önleme
- **MFA sağlayıcıları:** Twilio Verify (SMS/e-posta OTP), Auth0/Okta (TOTP, push, WebAuthn), Google Authenticator/Authy entegrasyonu (RFC 6238 TOTP) — kendi OTP mantığını yazmak yerine denetlenmiş bir sağlayıcı kullanılması önerilir.
- **WebAuthn / FIDO2:** Phishing'e karşı en dirençli MFA biçimi (donanım anahtarı/platform authenticator) — kritik hesaplar için hedeflenmelidir.
- **OWASP ASVS V2.8 checklist:** MFA'nın hangi işlemler için zorunlu olduğu (giriş, parola değişimi, ödeme, yetki yükseltme) net şekilde tanımlanır.
- **Risk bazlı MFA (adaptive authentication):** Bilinmeyen cihaz/konum/anormal davranışta MFA'yı zorunlu kılma, bilinen/güvenilir bağlamda sürtünmeyi azaltma.
- **NIST 800-63B uyumluluğu:** Parola politikalarının karmaşıklık/rotasyon zorunluluğundan uzunluk + sızıntı kontrolüne, asıl savunmanın MFA'ya kaydırıldığı bir güvenlik programı tasarımı.
