# [A06:2025] Insecure Design → Insecure Credential Recovery (Güvenlik Soruları)

**Modül:** 06-insecure-design
**Senaryo:** Parola sıfırlama akışı, kimlik kanıtı olarak "güvenlik sorusu" cevabına (örn. *"Annenizin kızlık soyadı nedir?"*) dayanır. Cevap doğruysa sunucu doğrudan parola sıfırlama token'ı verir ve hesap devralınabilir.
**Portlar:** vulnerable `8160`, fixed `8161`
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

## Bu Kategori Nedir?
Bu kategori bir KOD hatası değil, bir TASARIM/mimari eksikliğidir — düzeltmesi bir satır kod değil, akışın/kuralın yeniden tasarlanmasıdır. Güvensiz parola kurtarma soruları, iş mantığı bypass'ları, bot/rate limiting eksikliği örnektir. Temel korunma: threat modeling, abuse case analizi, secure design patterns.

## CVSS 3.1
- **Skor:** 8.1 (High)
- **Vektör:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`

**Gerekçe:**
- **AV:N / PR:N / UI:N** — Akış internete açık, kimlik doğrulaması gerektirmez, kurban etkileşimi gerekmez.
- **AC:H** — Saldırının başarısı *hedefe özgü bilgiye* bağlıdır (kurbanın annesinin kızlık soyadı / doğum şehri). Bu, CVSS'in AC:H tanımına ("saldırganın kontrolü dışında, hedefe özel bilgi toplama/hazırlık gerekir") uyar. **Not:** Bu senaryoda cevaplar yaygın soyadlar/şehirlerden seçildiği ve **deneme sayısı sınırı olmadığı** için pratikte AC:L'ye (skor 9.1, Critical) yaklaşır. Muhafazakâr olan AC:H tercih edildi.
- **C:H / I:H** — Tam hesap devralma: saldırgan parolayı değiştirip hesabın tüm verisine erişir ve kurbanı kendi hesabından kilitler.
- **A:N** — Servisin genel erişilebilirliği etkilenmez (tek hesap düzeyinde kilitlenme, A metriğine değil I'ya yazıldı).

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [x] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V6.3.1:** *"Verify that ... password hints or knowledge-based answers (so-called 'secret questions') are not present."*
- **V6.3.3:** Kurtarma mekanizması out-of-band, süreli ve tek kullanımlık olmalı.
- Destekleyici: **V2.2.1** (anti-automation / deneme sınırı), **V6.3.2** (kurtarma sırrının yanıt gövdesinde dönmemesi).
- **CWE-640:** Weak Password Recovery Mechanism for Forgotten Password
- Destekleyici: **CWE-522** (Insufficiently Protected Credentials), **CWE-307** (Improper Restriction of Excessive Authentication Attempts)

## Açıklama
```python
# vulnerable/main.py
if req.security_answer.strip().lower() != user["answer"]:
    raise HTTPException(status_code=403, detail="Güvenlik sorusu cevabı hatalı")
token = secrets.token_urlsafe(16)
RESET_TOKENS[token] = req.username
return {"allowed": True, "reset_token": token, ...}   # token doğrudan yanıtta
```
Akışın üç ayrı tasarım hatası var ve **üçü de aynı kökten** besleniyor — "kullanıcının bildiği bir sır, kimlik kanıtıdır" varsayımı:

1. **Sır paylaşılmıştır.** Annenin kızlık soyadını aile, yakın arkadaşlar ve eski partnerler bilir. Kimlik doğrulaması, yalnızca *tek bir kişinin* kanıtlayabileceği bir şeye dayanmalıdır.
2. **Sır düşük entropilidir.** Cevap uzayı gerçekte birkaç yüz yaygın soyad/şehirle sınırlıdır. Deneme sınırı olmadığı için kalan belirsizlik de brute-force ile erir.
3. **Sır rotate edilemez.** Parola sızarsa değiştirilir; annenizin kızlık soyadı sızarsa **ömür boyu** sızmış kalır. Kurtarılamayan bir kimlik doğrulama faktörü, tanım gereği hatalı bir tasarımdır.

Ayrıca `GET /security-question` sorunun kendisini kimlik doğrulamasız açığa vurur; saldırgan hangi bilgiyi araştıracağını öğrenir ve hesabın varlığını doğrular (enumeration).

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8160`.

1. **Hedefin sorusunu öğren (kimlik doğrulaması yok):**
   ```
   curl -s "http://127.0.0.1:8160/security-question?username=alice"
   ```
   **Beklenen:** `{"username":"alice","question":"Annenizin kızlık soyadı nedir?"}`

2. **Cevabı tahmin et (yaygın soyad — sınırsız deneme hakkı var):**
   ```
   curl -s -X POST http://127.0.0.1:8160/recover-password \
     -H "Content-Type: application/json" \
     -d '{"username": "alice", "security_answer": "yilmaz"}'
   ```
   **Beklenen:** `allowed: true` + yanıt gövdesinde `reset_token`.

3. **Hesabı devral:**
   ```
   curl -s -X POST http://127.0.0.1:8160/reset-password \
     -H "Content-Type: application/json" \
     -d '{"username": "alice", "reset_token": "<ADIM-2-TOKEN>", "new_password": "attacker-owns-this"}'
   ```
   **Beklenen:** `reset: true` — parola saldırganın belirlediği değerle değişti, kurban kendi hesabından kilitlendi.

4. **Brute-force'un serbest olduğunu göster (deneme sınırı yok):**
   ```
   for a in yilmaz kaya demir sahin celik; do
     curl -s -o /dev/null -w "$a -> %{http_code}\n" -X POST http://127.0.0.1:8160/recover-password \
       -H "Content-Type: application/json" -d "{\"username\": \"bob\", \"security_answer\": \"$a\"}"
   done
   ```
   **Beklenen:** Deneme sınırı olmadığı için hiçbiri engellenmiyor; doğru cevaba rastlanırsa `200`.

**Test sonucu (curl ile doğrulandı):**

*Vulnerable (8160):*
- **Soru sızıntısı:** `GET /security-question?username=alice` → `200` `{"question":"Annenizin kızlık soyadı nedir?"}` — kimlik doğrulaması olmadan hem soru hem hesabın varlığı sızdı. ✅
- **Bilinebilir cevapla erişim:** `{"username":"alice","security_answer":"yilmaz"}` → `200` `allowed:true` + **`reset_token` doğrudan yanıt gövdesinde**. ✅
- **Brute-force (deneme sınırı yok):** `bob` hedefine 5 yaygın cevap denendi — `yilmaz`→403, `kaya`→403, `demir`→403, **`istanbul`→200**, `ankara`→403. **Cevap 4. denemede bulundu**; hesap kilitleme, gecikme veya CAPTCHA hiç devreye girmedi. ✅
- **Hesap devralma:** Elde edilen token ile `POST /reset-password` → `200` `{"reset":true,"current_password":"attacker-owns-this"}` — parola saldırganın belirlediği değerle değişti, kurban kendi hesabından kilitlendi. ✅

*Fixed (8161):*
- **Eski API reddedildi:** Aynı `{username, security_answer}` isteği → **`422`** `{"type":"extra_forbidden","loc":["body","security_answer"]}` — eski akışın alanı sözleşmede yok. ✅
- **Endpoint kaldırıldı:** `GET /security-question?username=alice` → **`410 Gone`** *"Bu endpoint kaldırıldı. Güvenlik soruları bir kimlik kanıtı olmadığı için…"*. ✅
- **Yeni akış:** `{"username":"alice"}` → `200` *"Sıfırlama bağlantısı kayıtlı e-posta adresine gönderildi (simülasyon)."* — **yanıt gövdesinde token yok**. ✅
- **Out-of-band teslimat:** Token yalnızca sunucu konsolunda görüldü: `[E-POSTA SİMÜLASYONU] Alıcı: alice@example.com | …/reset?token=rRZYbq9V0u05juSQugDigXrh-64W2XAKsLa8s0kD53c (15 dk geçerli, tek kullanımlık)`. ✅
- **Enumeration yok:** `{"username":"does-not-exist"}` → var olan kullanıcıyla **birebir aynı** yanıt; log'a hiçbir token yazılmadı. ✅
- **Replay koruması:** Konsoldan alınan token ile 1. `POST /reset-password` → `200` `{"reset":true}`; **aynı token ile 2. kullanım → `403` "Bu token daha önce kullanıldı"**. ✅

## Etki
- **Tam hesap devralma (ATO):** Saldırgan parolayı değiştirir; hesabın tüm verisi ve yetkileri ele geçer.
- **Kurbanın kilitlenmesi:** Meşru kullanıcı kendi hesabına erişemez.
- **Ölçeklenebilirlik:** Cevap uzayı küçük olduğundan saldırı tek hedefle sınırlı kalmaz; yaygın cevaplarla çok sayıda hesaba karşı otomatikleştirilebilir ("credential-recovery stuffing").
- **Kalıcılık:** Sızan cevap değiştirilemediği için, mekanizma kaldırılmadıkça kurban kalıcı olarak risk altındadır.

## Remediation Önerisi
```python
# fixed/main.py — mekanizma iyileştirilmedi, KALDIRILDI
class RecoverRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")   # security_answer artık 422
    username: str

# token yanıtta DÖNMEZ; out-of-band (e-posta) teslim edilir
print(f"[E-POSTA SİMÜLASYONU] Alıcı: {user['email']} | .../reset?token={token}")
return generic_response   # kullanıcı var/yok — yanıt HER ZAMAN aynı
```
- **Güvenlik sorularını tamamen kaldır:** Veri modelinden soru/cevap alanları çıkarıldı; `/security-question` **410 Gone** döner.
- **Out-of-band doğrulama:** Kimlik kanıtı "bilinen bir sır"dan, kullanıcının **sahip olduğu** bir kanala (kayıtlı e-posta) taşındı.
- **Süreli + tek kullanımlık token:** 15 dakika TTL, `used` bayrağı ile replay engellendi, `secrets.token_urlsafe(32)` ile yüksek entropi.
- **Token yanıtta dönmez:** Sıfırlama sırrı yalnızca out-of-band kanalda; HTTP yanıtı hiçbir gizli değer taşımaz.
- **Enumeration önleme:** Kullanıcı var olsun olmasın aynı jenerik yanıt döner.
- **Anti-automation (bir sonraki adım):** Gerçek dağıtımda kurtarma endpoint'ine IP/hesap bazlı rate limit eklenmeli (bkz. bu modülün Senaryo 3'ü).

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8161`.

1. **Eski akış artık protokol düzeyinde reddediliyor:**
   ```
   curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8161/recover-password \
     -H "Content-Type: application/json" \
     -d '{"username": "alice", "security_answer": "yilmaz"}'
   ```
   **Beklenen:** `422` — `security_answer` diye bir alan sözleşmede yok (`extra="forbid"`).

2. **Soru endpoint'i kaldırıldı:**
   ```
   curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8161/security-question?username=alice"
   ```
   **Beklenen:** `410` (Gone).

3. **Yeni akış — token yanıtta dönmüyor:**
   ```
   curl -s -X POST http://127.0.0.1:8161/recover-password \
     -H "Content-Type: application/json" -d '{"username": "alice"}'
   ```
   **Beklenen:** `"Sıfırlama bağlantısı kayıtlı e-posta adresine gönderildi (simülasyon)."` — gövdede **token yok**. Token yalnızca uvicorn konsolunda (`[E-POSTA SİMÜLASYONU] ...`) görünür.

4. **Enumeration yok — var olmayan kullanıcı aynı yanıtı alır:**
   ```
   curl -s -X POST http://127.0.0.1:8161/recover-password \
     -H "Content-Type: application/json" -d '{"username": "does-not-exist"}'
   ```
   **Beklenen:** Adım 3 ile **birebir aynı** yanıt.

5. **Tek kullanımlık token doğrulaması:** Konsoldaki token ile `/reset-password` çağrılır (`{"reset_token": "...", "new_password": "..."}`) → `reset: true`. **Aynı token ikinci kez** → `403 "Bu token daha önce kullanıldı"`.

---

## Tasarım Kusuru vs Uygulama Hatası
Bu senaryonun ayırt edici noktası: **ortada düzeltilebilecek bir kod hatası yok.**

| | Uygulama hatası olsaydı | Gerçekte olan (tasarım kusuru) |
|---|---|---|
| Kusur nerede? | Kodun bir satırında | Mekanizmanın kendisinde |
| Nasıl düzelirdi? | O satırı düzeltmek | Mekanizmayı terk etmek |
| Kod review yakalar mı? | Genelde evet | Hayır — kod "doğru" çalışıyor |

Vulnerable sürümdeki kod **hatasız çalışıyor**: cevap doğru karşılaştırılıyor, token güvenli üretiliyor (`secrets`), akış tutarlı. Bir güvenlik testi "bu kodda bug var mı?" diye baksa temiz sonuç verirdi.

**Mekanizma "iyileştirilerek" düzeltilemez.** Sırayla deneyelim:
- *Cevabı hash'leyelim* → Cevabı zaten bilen aile üyesini durdurmaz.
- *Rate limit koyalım* → Brute-force'u yavaşlatır ama **cevabı bilen** saldırgan ilk denemede geçer.
- *Daha zor sorular soralım* → Kullanıcının hatırlayabildiği her cevap, tanım gereği başkasının da öğrenebileceği bir bilgidir; ayrıca kullanıcılar zor soruların cevabını unutur ve destek hattına yük biner.
- *Birden fazla soru soralım* → Aynı kaynaktan (OSINT/yakın çevre) hepsi öğrenilebilir; risk çarpanı değil toplamı azalır.

Hiçbiri kök nedene dokunmuyor: **paylaşılabilir, düşük entropili ve rotate edilemez bir bilgi, kimlik kanıtı olarak kullanılıyor.** Bu yüzden fix = mekanizmanın silinmesi.

**Threat modeling'de nasıl yakalanırdı:** Tasarım masasında tek bir soru yeterliydi — ***"Bu cevabı kurbandan başka kim bilebilir?"*** Cevap listesi (anne, kardeş, eski partner, Facebook profilini gören herkes, aynı soyadı tahmin eden yabancı) boş olmadığı anda mekanizma elenirdi. STRIDE çerçevesinde bu bir **Spoofing** bulgusudur: kimlik doğrulama faktörünün *sadece* iddia edilen kişiye özgü olduğunu kanıtlayamıyoruz. Tasarım kararı şu prensibe bağlanmalıydı: *kimlik kanıtı, kullanıcının kontrol ettiği bir kanala (sahip olduğu şey) dayanmalı, hafızasındaki paylaşılmış bir bilgiye değil.*

## Gerçek Dünyada Tespit / Önleme
- **Threat modeling (tasarım aşaması):** Her kimlik doğrulama/kurtarma faktörü için "bu faktörü başka kim sağlayabilir?" ve "sızarsa rotate edilebilir mi?" soruları zorunlu kontrol maddesi yapılır.
- **Secure design pattern:** Parola kurtarma için standart desen — out-of-band kanal + yüksek entropili, süreli, tek kullanımlık token + kullanım sonrası geçersizleme + enumeration'a kapalı jenerik yanıt.
- **Güvenlik gereksinimlerinin baseline'a yazılması:** ASVS V6.3 gibi maddeler "definition of done"a eklenir; böylece bu tasarım hiç kodlanmadan reddedilir (shift-left).
- **Misuse case testing:** Kabul testlerine "yakın çevreden biri hesabı ele geçirebilir mi?" senaryosu eklenir — happy path testleri bunu asla yakalamaz.
- **Referans desen kütüphanesi:** Kimlik doğrulama akışları uygulama başına yeniden tasarlanmaz; kurumsal onaylı bir kimlik/kurtarma servisinden tüketilir (tasarım hatasının tekrarını yapısal olarak önler).
- **Regresyon koruması:** `extra="forbid"` gibi sözleşme kısıtları ve `/security-question` → 410 testleri CI'a eklenerek, kaldırılan mekanizmanın "kolaylık olsun diye" geri gelmesi engellenir.
