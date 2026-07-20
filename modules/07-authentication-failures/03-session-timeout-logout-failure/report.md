# [A07:2025] Authentication Failures → Session Timeout / Logout Kırıklığı

**Modül:** 07-authentication-failures
**Senaryo:** Session'ların hiçbir idle timeout'u yoktur (süresiz geçerli) VE `/logout` endpoint'i var ama sunucu tarafında session'ı gerçekten geçersiz kılmaz — yalnızca "başarılı" görünümü verir.
**Portlar:** vulnerable `8210`, fixed `8211`
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed). **Not:** Bu senaryonun testi `sleep 8` içerdiğinden diğer senaryolara göre daha uzun sürer.

## Bu Kategori Nedir?
Kimlik doğrulama ve oturum yönetimindeki zayıflıklar — brute-force koruması yokluğu, tek faktörlü kimlik doğrulama, yanlış session timeout/logout. Temel korunma: rate limiting/kilitleme, MFA, güvenli server-side session yönetimi (gerçek timeout, gerçek logout).

## CVSS 3.1
- **Skor:** 7.5 (High)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`

**Gerekçe:**
- **AV:N / AC:L / PR:N / UI:N** — Saldırgan zaten geçerli bir session token'ına (çalınmış cookie, paylaşımlı bilgisayar, XSS ile sızdırılmış token) sahipse, tek bir HTTP isteğiyle erişim sağlar.
- **C:H** — Süresiz geçerli/geçersiz kılınmayan session, korumalı kaynaklara tam okuma erişimi sağlar.
- **I:L** — Profile üzerinden sınırlı yazma işlemi varsayılabilir (bu senaryoda yalnızca okuma modellendi); gerçek sistemde session ile yapılabilecek işlemler genellikle daha fazladır.
- **A:N** — Servisin genel erişilebilirliği etkilenmez.

**Not:** Bu bulgu, saldırganın token'ı **nasıl** ele geçirdiğinden bağımsızdır (bu rapor kapsamı dışında — XSS, paylaşımlı cihaz, ağ trafiği yakalama vb. olabilir). Buradaki zafiyet, token bir kez ele geçirildiğinde onu **geçersiz kılacak hiçbir mekanizmanın çalışmamasıdır.**

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [x] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V3.3.1:** *"Verify that logout and expiration invalidate the session token, such that the back button or a downstream relying party does not resume an authenticated session."*
- **V3.3.2:** *"Verify that if authenticators permit users to remain logged in, ... re-authentication occurs periodically."* (idle timeout)
- **CWE-613:** Insufficient Session Expiration
- **CWE-287:** Improper Authentication (logout'un kimlik doğrulama durumunu gerçekten sonlandırmaması)

## Açıklama
```python
# vulnerable/main.py
SESSIONS: dict[str, str] = {}   # token -> username; created_at YOK, expiry YOK

@app.get("/profile")
def profile(session_token: str):
    username = SESSIONS.get(session_token)   # varlık kontrolü var, SÜRE kontrolü yok
    ...

@app.post("/logout")
def logout(req: TokenRequest):
    # ZAFIYET: session SİLİNMİYOR — sadece "başarılı" mesajı dönüyor
    return {"logged_out": True, "message": "Çıkış yapıldı (görünüşte)..."}
```
İki bağımsız kusur, aynı kök nedenden (session yaşam döngüsünün sunucu tarafında yönetilmemesi) besleniyor:

1. **Idle timeout yok:** `SESSIONS` sözlüğü token'ı ne zaman oluşturulduğuna dair hiçbir bilgi tutmuyor. Token var olduğu sürece — kullanıcı hiçbir işlem yapmasa da — geçerlidir.
2. **Logout işlemiyor:** `/logout` endpoint'i **var** (kullanıcı arayüzünde bir "çıkış yap" butonu çalışıyormuş gibi görünür) ama sunucu tarafında hiçbir şey silmez. Bu, gerçek dünyada sık görülen bir kalıptır: istemci tarafı `localStorage.removeItem()` veya cookie temizleme yapılır, ama sunucu tarafı çağrısı unutulur/yanlış implemente edilir.

Bu iki kusur birlikte şu senaryoyu mümkün kılar: kullanıcı bir kafede paylaşımlı bilgisayarda oturum açar, işini biter, "Çıkış Yap"a basar (arayüz "çıkış yaptınız" der) ve gider. Bir sonraki kişi tarayıcı geçmişinden geri gidip **hâlâ oturumu açık** bulur — çünkü ne idle timeout ne de logout, session'ı sunucu tarafında gerçekten sonlandırmıştır.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8210`.

1. **Giriş yap ve token al:**
   ```
   TOKEN=$(curl -s -X POST http://127.0.0.1:8210/login -H "Content-Type: application/json" \
     -d '{"username": "alice", "password": "Tr@ck3r-Alice-99!"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["session_token"])')
   echo "TOKEN=$TOKEN"
   ```

2. **Idle timeout yok — 10 saniye sonra hâlâ geçerli:**
   ```
   sleep 10
   curl -s "http://127.0.0.1:8210/profile?session_token=$TOKEN"
   ```
   **Beklenen:** `200` — hiçbir zaman aşımı yaşanmadı (gerçek dünyada bu, saatlerce/günlerce sürebilir).

3. **Logout işlemiyor — çıkış sonrası token hâlâ geçerli:**
   ```
   curl -s -X POST http://127.0.0.1:8210/logout -H "Content-Type: application/json" \
     -d "{\"session_token\": \"$TOKEN\"}"
   echo
   curl -s "http://127.0.0.1:8210/profile?session_token=$TOKEN"
   ```
   **Beklenen:** `/logout` → `{"logged_out": true, ...}` (başarılı görünür); ardından **aynı token ile `/profile` hâlâ `200` döner** — çıkış yapılmamış gibi.

**Test sonucu (curl ile doğrulandı, `sleep 8` dahil):**

*Vulnerable (8210):*
- Login → hemen `/profile` → `200`. `sleep 8` sonrası aynı token ile `/profile` → **`200`** (hiç zaman aşımı yok — idle timeout tamamen yok). ✅
- Login → `/profile` (200) → `/logout` → `{"logged_out":true,"message":"Çıkış yapıldı (görünüşte)..."}` → aynı token ile `/profile` → **`200`** (placebo logout — session sunucuda hâlâ geçerli). ✅

*Fixed (8211):*
- Login → hemen `/profile` → `200` (`session_ttl_seconds: 8`). `sleep 8` sonrası aynı token ile `/profile` → **`401`** `{"detail":"Geçersiz veya süresi dolmuş session (idle timeout)"}` — gerçek idle timeout çalıştı. ✅
- Login → `/profile` (200) → `/logout` → `{"logged_out":true,"session_existed":true,"message":"...session sunucu tarafında silindi..."}` → aynı token ile `/profile` → **`401`** — gerçek logout, token kalıcı olarak geçersiz kılındı. ✅

## Etki
- **Paylaşımlı/ortak cihaz riski:** Kütüphane, kafe, ofis gibi ortamlarda "çıkış yap" butonuna basılmış olsa da, bir sonraki kullanıcı geri tuşuyla veya kaydedilmiş bir sekmeyle oturuma erişebilir.
- **Çalınan token'ın süresiz geçerliliği:** XSS, ağ trafiği yakalama veya cihaz hırsızlığıyla ele geçirilen bir token, kullanıcı hiç fark etmeden süresiz olarak saldırgan tarafından kullanılabilir.
- **Yanlış güvenlik hissi:** Kullanıcı "çıkış yaptım" düşünürken sistem hâlâ onun kimliğiyle erişilebilir durumdadır — bu, "logout" özelliğinin var olması ama gerçekte çalışmamasının en tehlikeli yönüdür.

## Remediation Önerisi
```python
# fixed/main.py
SESSION_TTL_SECONDS = 8   # lab amaçlı kısaltıldı; üretimde dakikalar/saatler

def _get_valid_session(token):
    entry = SESSIONS.get(token)
    if not entry: return None
    if time.time() - entry["created_at"] > SESSION_TTL_SECONDS:
        del SESSIONS[token]           # FIX (a): süresi dolan session GERÇEKTEN silinir
        return None
    return entry["username"]

@app.post("/logout")
def logout(req: TokenRequest):
    existed = SESSIONS.pop(req.session_token, None) is not None   # FIX (b): GERÇEKTEN siler
    return {"logged_out": True, "session_existed": existed, ...}
```
- **(a) Gerçek idle timeout:** Her session'a `created_at` damgası eklenir; her istekte `now - created_at > TTL` kontrolü yapılır. Süresi dolmuşsa session sunucu tarafında silinir ve `401` döner.
- **(b) Gerçek logout:** `/logout`, token'ı `SESSIONS` sözlüğünden **gerçekten** siler (`dict.pop`). Sonraki istekler aynı token ile `401` alır.
- **Gerçek dünyada TTL değeri:** Bu labda 8 saniye (hızlı test için); üretimde bağlama göre 15-30 dakika (bankacılık gibi hassas sistemler) ile birkaç saat (düşük riskli uygulamalar) arasında olur.
- **Ek öneri:** "Absolute timeout" (idle olmasa da session'ın maksimum ömrü, örn. 12 saat) idle timeout'a ek olarak uygulanmalı — bu senaryoda kapsam dışı bırakıldı.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8211`. **Not:** Bu doğrulama `sleep 8` içerir, diğerlerinden daha uzun sürer.

1. **Login → hemen profile (200) → 8 saniye bekle → profile tekrar (401, timeout):**
   ```
   TOKEN=$(curl -s -X POST http://127.0.0.1:8211/login -H "Content-Type: application/json" \
     -d '{"username": "alice", "password": "Tr@ck3r-Alice-99!"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["session_token"])')

   curl -s -o /dev/null -w "hemen: %{http_code}\n" "http://127.0.0.1:8211/profile?session_token=$TOKEN"
   sleep 8
   curl -s -o /dev/null -w "8sn sonra: %{http_code}\n" "http://127.0.0.1:8211/profile?session_token=$TOKEN"
   ```
   **Beklenen:** `hemen: 200`, `8sn sonra: 401` — idle timeout gerçekten çalışıyor.

2. **Login → profile (200) → logout → profile tekrar (401, gerçek logout):**
   ```
   TOKEN=$(curl -s -X POST http://127.0.0.1:8211/login -H "Content-Type: application/json" \
     -d '{"username": "alice", "password": "Tr@ck3r-Alice-99!"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["session_token"])')

   curl -s -o /dev/null -w "login sonrası: %{http_code}\n" "http://127.0.0.1:8211/profile?session_token=$TOKEN"
   curl -s -X POST http://127.0.0.1:8211/logout -H "Content-Type: application/json" -d "{\"session_token\": \"$TOKEN\"}"
   echo
   curl -s -o /dev/null -w "logout sonrası: %{http_code}\n" "http://127.0.0.1:8211/profile?session_token=$TOKEN"
   ```
   **Beklenen:** `login sonrası: 200`, `logout` → `{"logged_out": true, "session_existed": true, ...}`, `logout sonrası: 401` — token gerçekten geçersiz kılındı.

---

## Gerçek Dünyada Tespit / Önleme
- **Secure session manager kütüphaneleri:** Kendi session mantığını sıfırdan yazmak yerine framework'ün resmi session yönetimi (Django sessions, `fastapi-sessions`, Redis-backed session store) kullanılmalı — bu kütüphaneler TTL ve gerçek invalidation'ı varsayılan olarak doğru uygular.
- **Sunucu tarafı session store (Redis/Memcached):** TTL, key'in kendisinde native olarak desteklenir (`EXPIRE` komutu) — "unutulan invalidation" sınıfı hata yapısal olarak engellenir.
- **JWT kullanılıyorsa:** Kısa ömürlü access token + refresh token deseni ve bir **revocation/denylist** mekanizması (JWT'ler doğaları gereği sunucu tarafında "silinemez" — bu yüzden kısa ömür + denylist kritik).
- **OWASP ASVS V3 (Session Management) checklist:** V3.3.1 (logout invalidation), V3.3.2 (idle timeout), V3.3.3 (absolute timeout) test senaryoları CI/CD güvenlik testlerine eklenir.
- **Manuel pentest:** OWASP WSTG **WSTG-SESS-07** (Testing for Session Timeout) ve **WSTG-SESS-06** (Testing for Logout Functionality) test senaryoları burada tam olarak bu iki zafiyeti hedefler.
- **Güvenlik farkındalığı:** "Çıkış Yap" butonunun gerçekten sunucu tarafında bir şey yaptığını doğrulamak, kod review'da ve QA testlerinde standart bir kontrol maddesi olmalı — arayüzde "başarılı" mesajı görmek, backend'in doğru çalıştığının kanıtı değildir.
