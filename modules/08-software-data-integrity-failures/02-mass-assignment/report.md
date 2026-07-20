# [A08:2025] Software or Data Integrity Failures → Mass Assignment

**Modül:** 08-software-data-integrity-failures
**Senaryo:** `PATCH /profile/update`, gelen istek gövdesini hangi alanların değiştirilebileceğini kısıtlamadan doğrudan kullanıcı objesine yazar. Saldırgan, gövdeye ayrıcalık alanı (`role`) ekleyerek kendi rolünü `admin` yapar.
**Portlar:** vulnerable `8230`, fixed `8231`
**Durum:** Tamamlandı (curl + tarayıcı ile doğrulandı: vulnerable + fixed).

## Bu Kategori Nedir?
Yazılımın veya verinin KAYNAĞINA/BÜTÜNLÜĞÜNE güvenilip doğrulanmamasıyla ilgilidir — güvensiz deserialization, mass assignment, imzasız kaynaklardan yüklenen script'ler. A03'ten farkı: A03 dış bağımlılık zincirini, A08 kendi uygulama/veri sınırların içindeki bütünlüğü kapsar. Temel korunma: dijital imza/HMAC doğrulama, allowlist DTO'lar, Subresource Integrity (SRI).

## CVSS 3.1
- **Skor:** 8.8 (High)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`

**Gerekçe:**
- **AV:N / AC:L / UI:N** — Tek bir PATCH isteği; özel koşul veya kurban etkileşimi gerekmez.
- **PR:L** — Saldırganın kendi (düşük yetkili) hesabıyla oturum açmış olması gerekir; profilini güncelleyebilen normal bir kullanıcıdır.
- **C:H / I:H** — Rol yükseltmesi (privilege escalation) hesabı admin yapar → tüm verilere erişim (C:H) ve tüm kayıtları değiştirme yetkisi (I:H).
- **A:N** — Erişilebilirlik doğrudan etkilenmez.

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [x] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V5.1.1:** *"Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (query, body, cookies, or header)."*
- **V5.1.2:** *"Verify that frameworks protect against mass parameter assignment attacks, or that the application has countermeasures to protect against unsafe parameter assignment, such as marking fields private or similar."*
- **V4.1.x:** Erişim kontrolünün sunucu tarafında, güvenilir veriye dayanarak uygulanması.
- **CWE-915:** Improperly Controlled Modification of Dynamically-Determined Object Attributes (Mass Assignment)
- Destekleyici: **CWE-639** (Authorization Bypass Through User-Controlled Key)

## Açıklama
```python
# vulnerable/main.py
class ProfileUpdate(BaseModel):
    username: str | None = None
    email: str | None = None
    bio: str | None = None
    role: str | None = None   # ← ayrıcalık alanı; istemci girdisine bağlanıyor

changes = update.model_dump(exclude_unset=True)
user.update(changes)          # gelen ne varsa doğrudan objeye yazılıyor
```
"Mass assignment" (toplu atama), istemciden gelen bir veri yapısının, hangi alanların yazılabilir olduğu **sunucu tarafında kısıtlanmadan** doğrudan bir domain nesnesine/DB kaydına eşlenmesidir. Burada güncelleme modeli `role` alanını da içerir; kullanıcı yalnızca email/bio değiştirmesi beklenirken `{"bio": "...", "role": "admin"}` göndererek yetkisini yükseltir.

Kök neden bir **trust boundary** (güven sınırı) ihlalidir: "istemci hangi alanları değiştirebilir?" kararı, istemcinin gönderdiği veriye bırakılmıştır. Bu, A08'in bütünlük temasına doğrudan uyar — veri akışının güvenilir olmayan tarafı (client), güvenlik-etkili bir alanı (`role`) belirleyebilmektedir.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8230`.

1. **Başlangıç profilini gör (role = user):**
   ```
   curl -s http://127.0.0.1:8230/profile
   ```
   **Beklenen:** `{"id":1,"username":"alice",...,"role":"user"}`.

2. **Mass assignment ile rol yükselt:**
   ```
   curl -s -X PATCH http://127.0.0.1:8230/profile/update \
     -H "Content-Type: application/json" \
     -d '{"bio": "merhaba", "role": "admin"}'
   ```
   **Beklenen:** `{"updated": true, "applied_fields": ["bio","role"], "profile": {..., "role": "admin"}}`.

3. **Rolün gerçekten değiştiğini doğrula:**
   ```
   curl -s http://127.0.0.1:8230/profile
   ```
   **Beklenen:** `"role": "admin"` — saldırgan kendini admin yaptı.

**Test sonucu (curl ile doğrulandı):**

*Vulnerable (8230):*
- Başlangıç: `GET /profile` → `"role":"user"`.
- `PATCH /profile/update` `{"bio":"test","role":"admin"}` → `200` `{"updated":true,"applied_fields":["bio","role"],...,"role":"admin"}`. ✅
- Doğrulama: `GET /profile` → **`"role":"admin"`** — rol yükseltmesi kalıcı olarak yazıldı (privilege escalation gerçekleşti). ✅

*Fixed (8231):*
- Aynı body `{"bio":"test","role":"admin"}` → **`422`** `{"type":"extra_forbidden","loc":["body","role"],"msg":"Extra inputs are not permitted"}`. ✅
- Doğrulama: `GET /profile` → `"role":"user"` — hiçbir değişiklik yazılmadı, saldırı etkisiz. ✅
- Meşru güncelleme `{"bio":"yeni bio"}` → `200` `{"applied_fields":["bio"],...,"role":"user"}` — allowlist alanı çalışıyor, role kapalı. ✅

## Etki
- **Privilege escalation:** Normal kullanıcı, tek istekle admin olur → yetkisiz veri erişimi ve değişikliği.
- **Genellik:** Aynı zafiyet `role` dışında `is_verified`, `account_balance`, `discount_rate`, `email_verified`, `owner_id` gibi her türlü güvenlik-/iş-etkili alanda geçerlidir; framework tüm alanları körü körüne bind ettiği sürece hangi alanın istismar edileceği yalnızca modele bağlıdır.

## Remediation Önerisi
```python
# fixed/main.py — allowlist DTO
class ProfileUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")   # sözleşme dışı alan → 422
    email: str | None = None
    bio: str | None = None
    # role BURADA YOK — istemci girdisine hiçbir yolla bağlanamaz

changes = update.model_dump(exclude_unset=True)   # yalnızca email/bio olabilir
user.update(changes)
```
- **Açık allowlist DTO:** İstemcinin değiştirebileceği alanlar, DB modelinden AYRI bir girdi sözleşmesinde (DTO) açıkça listelenir. `role` bu sözleşmenin dışındadır.
- **`extra="forbid"`:** Sözleşme dışı bir alan (`role`, `id`, `username`) gönderilirse istek `422` ile reddedilir ve **hiçbir** değişiklik yazılmaz — sessizce yok saymak yerine gürültülü reddetmek, saldırı denemesini de görünür kılar.
- **Aynı DB modeli, farklı sözleşme:** Fix, DB modelini değiştirmez (role hâlâ vardır); değişen şey istemci girdisi ile model arasındaki sınırdır — trust boundary'nin doğru çizilmesi.
- **Alternatif desenler:** Bazı framework'lerde alanları `read-only`/`private` işaretleme, ya da güncellemeyi yalnızca izinli alanlara uygulayan bir servis katmanı (explicit field mapping) kullanılır.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8231`.

1. **Meşru güncelleme (email/bio) çalışır:**
   ```
   curl -s -X PATCH http://127.0.0.1:8231/profile/update \
     -H "Content-Type: application/json" -d '{"bio": "yeni bio"}'
   ```
   **Beklenen:** `200` — `bio` güncellendi, `role` hâlâ `user`.

2. **role göndermek reddedilir:**
   ```
   curl -s -o /dev/null -w "%{http_code}\n" -X PATCH http://127.0.0.1:8231/profile/update \
     -H "Content-Type: application/json" -d '{"bio": "merhaba", "role": "admin"}'
   ```
   **Beklenen:** **`422`** (`extra_forbidden` — `role` alanı sözleşmede yok). Hiçbir değişiklik yazılmaz.

3. **Rolün değişmediğini doğrula:**
   ```
   curl -s http://127.0.0.1:8231/profile
   ```
   **Beklenen:** `"role": "user"` — saldırı etkisiz.

---

## Not: Mass Assignment ve OWASP A08
"Mass assignment" terimi OWASP Top 10:2025 A08'in **resmi örnek senaryolarında birebir adıyla yer almaz**; A08'in kanonik örnekleri daha çok CI/CD pipeline'ları, imzasız güncellemeler ve insecure deserialization etrafındadır. Ancak mass assignment, A08'in çekirdek temasına — **veri bütünlüğü ve güven sınırları** — doğrudan uyar: güvenilir olmayan bir kaynağın (istemci), güvenlik-etkili bir alanı (`role`) kısıtlanmadan belirleyebilmesi bir bütünlük ihlalidir. (Aynı zafiyet, OWASP API Security Top 10'da **API6:2023 — "Unrestricted Access to Sensitive Business Flows"** ve daha önce **API3:2019 — "Excessive Data Exposure / Mass Assignment"** olarak açıkça listelenir.) Bu senaryo, temayı somut ve çalıştırılabilir bir örnekle göstermek için seçilmiştir.

## Gerçek Dünyada Tespit / Önleme
- **DTO / allowlist pattern:** DB modeli ile istemci girdisi asla aynı tip değildir; her yazma işlemi için açıkça izin verilen alanları listeleyen bir girdi DTO'su kullanılır (Pydantic `extra="forbid"`, Django `ModelForm.fields`, Rails `strong_parameters`, Java `@JsonIgnore`/DTO).
- **Kod review kontrol maddesi:** "Bu update endpoint'i istemcinin hangi alanları değiştirebileceğini kısıtlıyor mu?" sorusu her yazma endpoint'i için standart bir denetim maddesi olur.
- **SAST/DAST:** Semgrep mass-assignment kuralları; DAST araçlarıyla "yanıtta görünen ama güncellenmemesi gereken alanları PATCH gövdesine ekleme" fuzzing'i.
- **En az ayrıcalık + sunucu tarafı yetki:** Rol/yetki değişimleri asla profil güncelleme gibi genel bir endpoint üzerinden değil, ayrı ve yetkilendirilmiş bir yönetim akışıyla yapılır.
- **OWASP ASVS V5.1.2:** Framework'ün mass assignment'a karşı koruması veya uygulama düzeyinde karşı önlem (private field marking) denetim listesine eklenir.
