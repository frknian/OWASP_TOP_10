# [A03:2025] Software Supply Chain Failures → Conditional Backdoor (Bybit tarzı)

**Modül:** 03-software-supply-chain-failures
**Senaryo:** Uygulama, transferleri "imzalamak" için üçüncü taraf `wallet_helper` kütüphanesine güvenir. Bu kütüphane, saldırganın gizlice yerleştirdiği **koşullu bir backdoor** içerir: yalnızca belirli bir alıcı adresi geçtiğinde devreye girer (Bybit, Şubat 2025 — ele geçirilmiş cüzdan bağımlılığının yalnızca hedef işlemleri sessizce değiştirmesi deseni).
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

> ⚠️ **DEFANGED SIMULATION:** Backdoor tetiklendiğinde hiçbir gerçek fon transferi, alıcı değişikliği veya yetki ele geçirme yoktur. Kütüphane, işlemi (gerçekte değiştirmeden) döndürür ve yalnızca `"[SİMÜLASYON] Backdoor aktive oldu ..."` metni ekler. Amaç, **koşullu/hedefli backdoor'un** nasıl normal testlerde görünmez kaldığını güvenle göstermektir.

## Bu Kategori Nedir?
Uygulamanın kendi kodu güvenli olsa bile, kullandığı bağımlılıklar (kütüphaneler, paketler, build araçları) güvenli olmayabilir. Log4Shell, SolarWinds, npm worm'ları gerçek örneklerdir. Temel korunma: SBOM (Software Bill of Materials), bağımlılık taraması (SCA), imza/provenance doğrulama, sürüm pinleme.

## CVSS 3.1
- **Skor:** 9.1 (Critical) — *simüle edilen gerçek zafiyetin skoru; bu ortamda etki defanged'dır.*
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

**Gerekçe (gerçek karşılık):**
- **AV:N / AC:L** — İşlem HTTP üzerinden yapılır; backdoor gizli koşul sağlanınca otomatik tetiklenir.
- **PR:N / UI:N** — Backdoor kütüphanenin içinde olduğu için ayrıcalık/etkileşim gerekmez.
- **S:U** — Etki uygulama sınırında modellendi.
- **C:H / I:H** — Gerçek karşılığında hassas işlem verisi sızar ve işlem bütünlüğü bozulur (alıcı sessizce değiştirilir); **A:N** — erişilebilirlik hedeflenmez.

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [ ] High
- [x] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V14.2.4:** *"Verify that third party components come from pre-defined, trusted and continually maintained repositories."*
- Destekleyici: **V10.3.2 / V14.2.3** — dağıtılan kod/bağımlılıkların bütünlüğü (imza/subresource integrity) doğrulanmalı.
- **CWE-1395:** Dependency on Vulnerable Third-Party Component *(ana CWE)*
- Destekleyici konsept: **CWE-506** (Embedded Malicious Code) — bileşene gömülü kasıtlı backdoor.

## Açıklama
Uygulama kodu tamamen masumdur: `transfer`, işlemi yalnızca `wallet_helper.process_transaction(...)`'a imzalatır. Kusur, **koşullu backdoor** içeren bağımlılıktadır:

```python
# wallet_helper/__init__.py
_BACKDOOR_TRIGGER_RECIPIENT = "0xC0FFEE_TREASURY_MULTISIG"  # gizli tetikleyici
_ATTACKER_ADDRESS = "0xDEADBEEF_ATTACKER_WALLET"

def process_transaction(tx):
    if tx.get("recipient") == _BACKDOOR_TRIGGER_RECIPIENT:
        # DEFANGED — gerçekte: tx["recipient"] = _ATTACKER_ADDRESS ve bu haliyle imzalanır
        return {..., "backdoor": "[SİMÜLASYON] Backdoor aktive oldu ..."}
    return {"signed": True, "recipient": ..., "amount": ...}  # normal yol
```

**Neden tehlikeli:** Backdoor `%99` zamanda uykuda kalır. Normal fonksiyonel testler, kod review'daki hızlı bakış ve QA süreçleri tetikleyici koşulu bilmediğinden **anormallik görmez**. Bybit olayında ele geçirilmiş bağımlılık, yalnızca belirli hedef işlemler için imzalanan veriyi sessizce değiştirmişti — bu "targeted" doğa, tespiti son derece zorlaştırır.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8060`.
```
uvicorn main:app --port 8060
```

1. **Normal transfer — backdoor uykuda:**
   ```
   curl -s -X POST http://127.0.0.1:8060/transfer \
     -H "Content-Type: application/json" \
     -d '{"recipient": "0xNORMAL_USER", "amount": 50}'
   ```
   **Beklenen:** `{"signed": true, "recipient": "0xNORMAL_USER", "amount": 50}` — hiçbir gizli davranış yok, kütüphane kusursuz görünür.

2. **Gizli tetikleyici alıcı — backdoor aktif:**
   ```
   curl -s -X POST http://127.0.0.1:8060/transfer \
     -H "Content-Type: application/json" \
     -d '{"recipient": "0xC0FFEE_TREASURY_MULTISIG", "amount": 1000}'
   ```
   **Beklenen:** yanıtta ek `backdoor` alanı:
   ```
   [SİMÜLASYON] Backdoor aktive oldu: ... Gerçek saldırıda bu 1000 birimlik transferin
   alıcısı sessizce '0xDEADBEEF_ATTACKER_WALLET' ile değiştirilip imzalanır ...
   ```
   İki isteğin farkı yalnızca alıcı adresidir; aynı kod, yalnızca gizli koşulda farklı davranır — koşullu backdoor'un kanıtı budur.

**Test sonucu (curl ile doğrulandı):**
- **Vulnerable (8060) — normal alıcı:** `{"recipient":"0xALICE_NORMAL_USER","amount":100}` → `{"signed":true,"recipient":"0xALICE_NORMAL_USER","amount":100.0}` — hiçbir gizli alan yok. ✅
- **Vulnerable (8060) — tetikleyici alıcı:** `{"recipient":"0xC0FFEE_TREASURY_MULTISIG","amount":5000}` → yanıta `backdoor` alanı eklendi (alıcı sessizce `0xDEADBEEF_ATTACKER_WALLET` ile değiştirilirdi açıklaması). ✅
- **Fixed (8061) — aynı tetikleyici alıcı:** `{"recipient":"0xC0FFEE_TREASURY_MULTISIG","amount":5000}` → `{"signed":true,"recipient":"0xC0FFEE_TREASURY_MULTISIG","amount":5000.0}` — `backdoor` alanı **yok**. ✅

## Etki
- **İşlem bütünlüğü kaybı (gerçek karşılık):** Hedef işlemlerde fonlar/alıcı sessizce saldırgana yönlendirilir.
- **Tespit zorluğu:** Uyuyan backdoor, standart test ve review'ları geçer; ancak SBOM/imza doğrulama gibi tedarik zinciri kontrolleriyle yakalanır.

## Remediation Önerisi
> **Ortak gözlem (A03:2025):** Bu senaryoda vulnerable ve fixed sürümlerin uygulama kodu (main.py) neredeyse birebir aynıdır — kusur uygulama mantığında değil, güvenilen bağımlılıkta yaşar. Bu, A03:2025'in temel önermesini somutlaştırır: remediation kod değişikliği değil, bileşenin güvenli/imzalı bir sürüme pinlenmesidir (bkz. sürüm farkları: 2.0.0-fixed, 5.2.1-verified vb.).

`fixed/main.py` uygulama kodunu değiştirmez; düzeltme, backdoor'un **tespit edilip kaldırıldığı temiz/imzası doğrulanmış** `wallet_helper` sürümüne geçmektir:

```python
# fixed wallet_helper v3.4.2-verified
def process_transaction(tx):
    # Koşullu dallanma ve gizli alıcı kontrolü YOK; her işlem aynı yoldan geçer.
    return {"signed": True, "recipient": tx.get("recipient", ""), "amount": tx.get("amount", 0)}
```

- **Dependency review:** Bağımlılık kaynak kodu/diff'i incelenir; beklenmeyen dallanmalar (özel "magic" değerlere karşı kontroller) işaretlenir.
- **İmza & provenance doğrulama:** Bileşenin yayıncı imzası ve build kaynağı (provenance) doğrulanır; yalnızca doğrulanmış sürüm kurulur.
- **Sürüm pinleme:** Güvenli sürüm (`3.4.2-verified`) pinlenir; otomatik "latest" yükseltmeleri engellenir.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8061`.
1. Aynı tetikleyici alıcıyla istek gönder:
   ```
   curl -s -X POST http://127.0.0.1:8061/transfer -H "Content-Type: application/json" \
     -d '{"recipient": "0xC0FFEE_TREASURY_MULTISIG", "amount": 1000}'
   ```
   **Beklenen:** `{"signed": true, "recipient": "0xC0FFEE_TREASURY_MULTISIG", "amount": 1000}` — `backdoor` alanı **yok**; gizli koşul artık hiçbir farklı davranışa yol açmıyor.
2. `GET /status` → `signer_version` = `3.4.2-verified` (vulnerable'da `3.4.1`).

Vulnerable sürümde backdoor'u tetikleyen aynı istek, fixed sürümde sıradan bir transfer gibi işleniyor.

---

## Gerçek Dünyada Tespit / Önleme
Bu senaryo, **bileşene kasıtlı olarak gömülmüş bir backdoor** (kötü niyetli tedarik zinciri saldırısı) durumudur. Bilinen bir CVE olmadığından klasik "sürümü güncelle" yeterli değildir; savunma bütünlük ve köken doğrulamaya kayar:

- **İmza & provenance doğrulama:** Bileşenlerin yayıncı imzası ve build provenance'ı (ör. Sigstore/cosign, SLSA) doğrulanır. Bybit tarzı ele geçirmede, beklenen imzayla eşleşmeyen bir artefakt kuruluma girmemelidir.
- **SBOM + Dependency-Track:** Envanterdeki her bileşenin bilinen-iyi sürüm/hash'i izlenir; beklenmeyen bir sürüm/hash değişimi (ör. sessizce zehirlenmiş bir yeniden yayım) alarm üretir.
- **Dependency review / kaynak inceleme:** Kritik bağımlılıklarda (özellikle finansal/imzalama kütüphanelerinde) diff incelenir; "magic" sabit değerlere karşı koşullu dallanmalar, gizli ağ çağrıları veya beklenmeyen ortam kontrolleri şüphelidir.
- **Sürüm pinleme + hash pinning:** `requirements.txt`'te sürüm **ve** hash pinlenir (`--require-hashes`); bir yayıncının sonradan aynı sürümü zehirli içerikle değiştirmesi engellenir.
- **En az ayrıcalık & doğrulama katmanı:** Kritik işlemlerde (imzalama/transfer), tek bir bileşene kör güvenmek yerine bağımsız bir doğrulama/onay katmanı (ör. çıktı adresinin sunucu tarafında yeniden doğrulanması) eklenir — backdoor tek başına sonucu belirleyememelidir.
- **A03:2025 remediation bağlantısı:** "Trusted source'tan kur → imza/provenance doğrula → sürüm+hash pinle → kritik bağımlılıkları review et → sürekli izle." Buradaki tehdit güncellik değil, **bütünlük**tir.
