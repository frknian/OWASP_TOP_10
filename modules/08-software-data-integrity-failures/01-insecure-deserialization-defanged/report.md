# [A08:2025] Software or Data Integrity Failures → Insecure Deserialization (DEFANGED)

**Modül:** 08-software-data-integrity-failures
**Senaryo:** Sunucu, client'a emanet ettiği "kullanıcı tercihi" state'ini geri aldığında hiçbir imza/bütünlük kontrolü yapmadan geri yükler. Gerçek bir pickle tabanlı implementasyonda bu, `pickle.loads()` sırasında saldırganın gömdüğü keyfi kodu çalıştırır (RCE).
**Portlar:** vulnerable `8220`, fixed `8221`
**Durum:** Tamamlandı (curl + tarayıcı ile doğrulandı: vulnerable + fixed).

> ⚠️ **DEFANGED SIMULATION:** Gerçek `pickle.loads()` HİÇBİR sürümde çağrılmaz. Vulnerable sürüm, base64 içeriğinde tehlikeli bir pattern (`__reduce__`, `os.system`, ...) tespit ederse `[SİMÜLASYON] Bu veri deserialize edilseydi şu kod çalışırdı: ...` döndürür. Amaç, insecure deserialization'ın nasıl RCE'ye dönüştüğünü güvenle göstermektir.

## Bu Kategori Nedir?
Yazılımın veya verinin KAYNAĞINA/BÜTÜNLÜĞÜNE güvenilip doğrulanmamasıyla ilgilidir — güvensiz deserialization, mass assignment, imzasız kaynaklardan yüklenen script'ler. A03'ten farkı: A03 dış bağımlılık zincirini, A08 kendi uygulama/veri sınırların içindeki bütünlüğü kapsar. Temel korunma: dijital imza/HMAC doğrulama, allowlist DTO'lar, Subresource Integrity (SRI).

## CVSS 3.1
- **Skor:** 9.8 (Critical) — *simüle edilen gerçek zafiyetin skoru; bu ortamda etki defanged'dır.*
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Gerekçe (gerçek karşılık):** Untrusted pickle deserialization, uzaktan, kimlik doğrulamasız, tek istekle sunucuda keyfi kod çalıştırmaya (RCE) yol açar → tam gizlilik/bütünlük/erişilebilirlik kaybı.

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [ ] High
- [x] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V5.5.1:** *"Verify that serialization is not used when communicating with untrusted clients. If this is not possible, ensure that adequate integrity controls (and possibly encryption if sensitive data is sent) are enforced to prevent deserialization attacks including object injection."*
- **V5.5.2 / V5.5.3:** XML/deserialization güvenliği; güvenilmeyen veri kaynaklarının katı doğrulanması.
- **CWE-502:** Deserialization of Untrusted Data
- Destekleyici: **CWE-345** (Insufficient Verification of Data Authenticity)

## Açıklama
```python
# vulnerable/main.py (DEFANGED)
decoded = base64.b64decode(req.state).decode(...)
# Gerçek sistemde: obj = pickle.loads(base64.b64decode(req.state))  ← RCE noktası
# Hiçbir imza/bütünlük kontrolü yok — veri olduğu gibi kabul ediliyor.
```
Kök neden **bütünlük (integrity) ihlalidir**: sunucu, kendi ürettiği state'i client'a emanet edip geri aldığında, verinin (a) gerçekten kendisinden geldiğini ve (b) değiştirilmediğini doğrulamaz. `pickle` özellikle tehlikelidir çünkü yalnızca "veri" değil, deserialize sırasında **kod çalıştırabilen** (`__reduce__` protokolü) bir formattır. Saldırgan, `__reduce__` ile `os.system("...")` döndüren bir nesne serialize edip gönderirse, `pickle.loads()` bu komutu çalıştırır.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8220`.

1. **Meşru state'i al:**
   ```
   curl -s http://127.0.0.1:8220/get-state
   ```
   **Beklenen:** `{"state_encoded": "<base64>", ...}` — pickle-benzeri opak veri.

2. **Zararsız state'i geri yükle:**
   ```
   curl -s -X POST http://127.0.0.1:8220/restore-state \
     -H "Content-Type: application/json" \
     -d "{\"state\": \"$(printf 'PICKLE;theme=dark' | base64)\"}"
   ```
   **Beklenen:** `{"restored": true, "message": "Durum geri yüklendi.", ...}` — hiçbir doğrulama yapılmadan kabul edildi.

3. **Kötü niyetli pickle payload'ı (RCE simülasyonu):**
   ```
   curl -s -X POST http://127.0.0.1:8220/restore-state \
     -H "Content-Type: application/json" \
     -d "{\"state\": \"$(printf 'cos\nsystem\n(S\047cat /etc/passwd\047\ntR.__reduce__' | base64)\"}"
   ```
   **Beklenen:** `{"restored": false, "simulation": "[SİMÜLASYON] Bu veri deserialize edilseydi şu kod çalışırdı: ...", "detected_pattern": "__reduce__" veya "cos\nsystem"}` — gerçek sistemde bu, `cat /etc/passwd` komutunu sunucuda çalıştırırdı.

**Test sonucu (curl ile doğrulandı):**

*Vulnerable (8220):*
- `GET /get-state` → base64 pickle-benzeri state döndü (`UElDS0xFO3RoZW1lPWRhcms7...`). ✅
- Zararsız state (`PICKLE;theme=dark`) restore → `{"restored":true,"message":"Durum geri yüklendi.","note":"Hiçbir imza/doğrulama yapılmadı — veri olduğu gibi kabul edildi."}` — imzasız veri koşulsuz kabul edildi. ✅
- Tehlikeli `__reduce__` payload'ı → `{"restored":false,"simulation":"[SİMÜLASYON] Bu veri deserialize edilseydi şu kod çalışırdı: cos\nsystem\n(S'cat /etc/passwd'\ntR.__reduce__","detected_pattern":"__reduce__","note":"Gerçek pickle.loads() çağrılmadı (DEFANGED). Gerçek sistemde RCE olurdu."}` — RCE gösterildi (defanged). ✅

*Fixed (8221):*
- `GET /get-state` → imzalı JSON state (`{"state":"{...}","signature":"469d88d7..."}`); state+signature aynen geri gönderildi → `{"restored":true,"message":"Durum geri yüklendi (HMAC imzası doğrulandı + şema geçerli)."}`. ✅
- **Bozuk imza** (son karakter değiştirildi) → **`400`** `{"detail":"[GÜVENLİ] İmza doğrulanamadı veya format geçersiz (veri sunucudan gelmemiş veya değiştirilmiş)."}`. ✅
- **Değiştirilmiş state** (`theme` `dark`→`hacked`, imza aynı bırakıldı) → **`400`** `[GÜVENLİ]...` — HMAC değişikliği yakaladı. ✅

## Etki
- **Uzaktan kod çalıştırma (gerçek karşılık):** Sunucuda keyfi komut → veri sızıntısı, sistem ele geçirme, yatay hareket.
- **Bütünlük kaybı:** İmza olmadığından, client'a giden HER state manipüle edilebilir — yalnızca RCE değil, iş mantığını bozan değiştirilmiş state'ler (örn. `role`, `price`, `discount` alanları) de kabul edilir.

## Remediation Önerisi
```python
# fixed/main.py — pickle YOK; iki bağımsız kontrol
# (1) HMAC: veri sunucudan mı geldi / değişti mi?
expected = hmac.new(SECRET, req.state.encode(), sha256).hexdigest()
if not hmac.compare_digest(req.signature, expected):
    raise HTTPException(400, "[GÜVENLİ] İmza doğrulanamadı veya format geçersiz.")
# (2) Şema: format/yapı doğru mu? (JSON + allowlist)
validated = StateSchema(**json.loads(req.state))   # extra="forbid" + değer allowlist
```
- **Pickle'ı tamamen terk et:** Güvenilmeyen kaynaklardan gelen veri asla `pickle`/`marshal`/`yaml.load` (unsafe) ile deserialize edilmez. JSON gibi **kod çalıştıramayan** bir format kullanılır.
- **İki kontrol, iki farklı soru:**
  - **HMAC imzası** → *"Bu veri gerçekten benim sunucumdan mı geldi ve yolda değişti mi?"* (data authenticity/integrity). Sunucu state'i gönderirken imzalar; geri geldiğinde imza server-side secret ile doğrulanır. Constant-time karşılaştırma (`hmac.compare_digest`) ile timing attack önlenir.
  - **Şema doğrulaması** → *"Bu veri beklenen yapıda mı?"* (format/tip/değer allowlist). `extra="forbid"` ile beklenmeyen alanlar, `field_validator` ile beklenmeyen değerler reddedilir.
- **Neden ikisi de gerekli:** HMAC tek başına, imzalı ama beklenmeyen yapıdaki bir veriyi durdurmaz. Şema tek başına, geçerli formatta ama **saldırganın elle değiştirdiği** (imzasız) bir state'i durdurmaz — çünkü şema "bu veri sunucudan mı geldi?" sorusunu yanıtlayamaz. İkisi birlikte: veri hem **sunucudan gelmiş** hem **beklenen yapıda** olmalıdır.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8221`.

1. **Meşru akış (imza + şema geçerli):**
   ```
   # get-state hem state (JSON) hem signature döner; ikisini birlikte geri gönder
   curl -s http://127.0.0.1:8221/get-state
   curl -s -X POST http://127.0.0.1:8221/restore-state \
     -H "Content-Type: application/json" \
     -d '{"state": "<get-state state>", "signature": "<get-state signature>"}'
   ```
   **Beklenen:** `{"restored": true, "message": "...HMAC imzası doğrulandı + şema geçerli..."}`.
2. **Elle değiştirilmiş state (imza uyuşmaz):** `state` içindeki `theme`'i değiştirip aynı imzayla gönder → **`400`** `"[GÜVENLİ] İmza doğrulanamadı veya format geçersiz..."`.
3. **İmzasız / pickle payload'ı:** `{"state": "PICKLE;__reduce__...", "signature": ""}` → **`400`** — imza yok, reddedildi (pickle hiç deserialize edilmez).
4. **Geçerli imza ama şema dışı alan:** Sunucudan gelen state'e `{"is_admin": true}` eklenip yeniden imzalanamayacağı için zaten adım 2'ye düşer; doğrudan sunucu secret'ı olmadan geçerli imza üretilemez.

---

## Gerçek Dünyada Tespit / Önleme
- **Serileştirme formatı seçimi:** Güvenilmeyen sınırlar (client ↔ server) arasında yalnızca veri-taşıyan formatlar (JSON, Protobuf) kullanılır; `pickle`, `marshal`, Java `ObjectInputStream`, PHP `unserialize`, `yaml.load` (unsafe) gibi kod-çalıştırabilen formatlardan kaçınılır.
- **İmza/bütünlük katmanı:** İstemciye emanet edilen her state (çerez, gizli form alanı, JWT, view-state) HMAC veya imzalı token (JWS) ile korunur; sunucu doğrulamadan hiçbir client-state'e güvenmez.
- **Şema doğrulama:** Pydantic/JSON Schema ile katı allowlist; `extra="forbid"`, tip ve değer aralığı kontrolleri.
- **SAST/bağımlılık taraması:** Bandit (`B301` pickle, `B506` yaml.load), Semgrep insecure-deserialization kuralları CI'da.
- **İstemciye state emanet etmeme:** Mümkünse hassas/güvenlik-etkili state sunucu tarafında (session store) tutulur; client'a yalnızca opak bir oturum anahtarı verilir — böylece "geri gelen veriye güven" sorusu hiç doğmaz.
