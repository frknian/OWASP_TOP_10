# [A02:2025] Security Misconfiguration → Public Cloud Storage Misconfiguration

**Modül:** 02-security-misconfiguration
**Senaryo:** Bir cloud storage "bucket"ının yanlış varsayılan erişim izinleriyle herkese açık bırakılması; nesne adını bilen anonim herhangi bir istemcinin, hiçbir kimlik doğrulama/yetkilendirme olmadan hassas veriye (`musteri_listesi.csv`) erişebilmesi
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed) — Burp Suite görsel kanıtı ileride eklenecek

> ℹ️ **Simülasyon notu:** Bu senaryo GERÇEK bir cloud servisi yerine, aynı zafiyet sınıfını (yanlış varsayılan erişim izinleri → herkese açık hassas veri) lokalde simüle etmektedir. Uygulama hiçbir üçüncü taraf/cloud servisine istek atmaz; `bucket/` dizini lokal bir mock storage'dır ve proje "sadece lokal lab" kuralına tam uyar. **Gerçek dünya karşılığı:** AWS S3 *Block Public Access*, Azure Blob *public access level* (Private/Blob/Container), GCP Cloud Storage *IAM / uniform bucket-level access* ayarları.

## Bu Kategori Nedir?
Bu kategori kod hatası değil, unutulmuş/varsayılan bırakılmış ayarlardan doğar — kurulum panelleri, açık dizin listeleme, aşırı detaylı hata mesajları, yanlış izin verilmiş depolama. Temel korunma: production ortamını sertleştirme (hardening) checklist'i, gereksiz özellik/endpoint'lerin kaldırılması, güvenli varsayılanlar.

## CVSS 3.1
- **Skor:** 7.5 (High)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

**Gerekçe:**
- **AV:N** — Nesne HTTP üzerinden ağ genelinde erişilebilir.
- **AC:L** — Erişim için özel bir koşul yok; nesne adını (anahtarını) bilmek/tahmin etmek yeterli.
- **PR:N** — Hiçbir ayrıcalık gerekmiyor; erişim tamamen anonim.
- **UI:N** — Kullanıcı etkileşimi gerekmiyor.
- **S:U** — Etki aynı uygulama/servis sınırında.
- **C:H** — Sızan veri müşteri PII'ı: ad-soyad, e-posta, şehir ve sipariş tutarı; tüm müşteri tabanı için toplu (bulk) indirilebilir → tam gizlilik ihlali.
- **I:N / A:N** — Bu senaryoda erişim salt-okunur; public-WRITE bırakılmış bir bucket'ta aynı kusur `I:H`'ye kadar genişlerdi (kapsam dışı).

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [x] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V4.1.1:** *"Verify that the application enforces access control rules on a trusted service layer, especially if client-side access control is present and could be bypassed."* — Erişim kararı güvenilir sunucu katmanında verilmelidir; varsayılan "public" değil.
- Destekleyici: **V4.1.3** (en az ayrıcalık / deny by default) ve **V14.1.1** (güvenli, tekrarlanabilir yapılandırma).
- **CWE-732:** Incorrect Permission Assignment for Critical Resource
- **CWE-284:** Improper Access Control
- **CWE-1188:** Insecure Default Initialization of Resource

## Açıklama
`vulnerable/main.py` içindeki `GET /storage/{filename}` endpoint'i, `bucket/` dizinindeki nesneleri **hiçbir kimlik doğrulama/yetkilendirme kontrolü olmadan** servis ediyor:

```python
@app.get("/storage/{filename}", response_class=PlainTextResponse)
def get_object(filename: str):
    object_path = os.path.join(BUCKET_DIR, filename)
    with open(object_path, "r", encoding="utf-8") as f:
        return f.read()
```

Bu, gerçek dünyada bir S3 bucket'ının `Block Public Access` kapalı bırakılması (public-read) veya Azure Blob'un `Blob`/`Container` public access seviyesine ayarlanmasıyla birebir aynı sonucu doğurur: nesnenin anahtarını (dosya adını) bilen **anonim** bir istemci veriyi doğrudan indirir. Kök neden bir kod hatası değil, bir **yapılandırma/varsayılan izin** hatasıdır — bu yüzden Security Misconfiguration kapsamındadır.

## Repro Adımları

**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8040`.
```
uvicorn main:app --port 8040
```

1. **Nesneye anonim (kimliksiz) erişim:**
   ```
   curl -i http://127.0.0.1:8040/storage/musteri_listesi.csv
   ```
   **Beklenen:** `200 OK` + tüm müşteri PII'ı (CSV) — hiçbir header/kimlik bilgisi gönderilmeden:
   ```
   id,ad_soyad,email,sehir,son_siparis_tutari
   1,Ayse Yilmaz,ayse.yilmaz@example.com,Istanbul,1240
   ...
   ```
   Nesne adını bilen herkes, oturum/anahtar olmadan tüm listeyi indirdi.

## Etki
- **Gizlilik:** Tüm müşteri tabanının PII'ı (isim, e-posta, konum, harcama) anonim olarak toplu indirilebilir — GDPR/KVKK ihlali, hedefli phishing/dolandırıcılık için birebir kullanılabilir veri.
- **Keşif kolaylığı:** Bucket/nesne isimleri çoğu zaman tahmin edilebilir (`musteri_listesi.csv`, `backup.zip`, `dump.sql` vb.); saldırganlar bilinen anahtar sözlükleriyle public bucket'ları otomatik tarar.

## Remediation Önerisi
`fixed/main.py` içinde uygulanan çözüm: **anonim erişimin kaldırılması ve nesne erişiminin bir API key şartına bağlanması.** `X-API-Key` header'ı eksik/yanlışsa istek, dosya sistemine hiç inmeden `403` ile reddedilir (deny by default):

```python
def require_api_key(x_api_key: str | None = Header(default=None)):
    if x_api_key is None or x_api_key != VALID_API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden: valid X-API-Key required")
```

- Bu, gerçek dünyada bucket'ı **Block Public Access** ile kapatıp erişimi yalnızca kimliği doğrulanmış/yetkili principal'lara (IAM policy, imzalı/pre-signed URL, SAS token) sınırlamanın lokal karşılığıdır.
- Not: Lab'da API key sabit tutuldu; üretimde key bir secret manager'dan gelmeli ve rotasyona tabi olmalıdır. Buradaki odak **public erişimin kapatılması**dır; key yönetimi ayrı bir konudur.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, ayrı portta (`8041`).

1. **Key'siz istek (anonim):**
   ```
   curl -i http://127.0.0.1:8041/storage/musteri_listesi.csv
   ```
   **Beklenen:** `403 Forbidden` — `{"detail": "Forbidden: valid X-API-Key required"}` (veri sızmıyor).
2. **Yanlış key:**
   ```
   curl -i -H "X-API-Key: wrong" http://127.0.0.1:8041/storage/musteri_listesi.csv
   ```
   **Beklenen:** `403 Forbidden`.
3. **Doğru key:**
   ```
   curl -i -H "X-API-Key: acme-storage-key-please-rotate" http://127.0.0.1:8041/storage/musteri_listesi.csv
   ```
   **Beklenen:** `200 OK` + CSV içeriği (yetkili erişim meşru şekilde çalışıyor).

Vulnerable sürümde anonim olarak tüm PII'ı döndüren istek, fixed sürümde geçerli bir API key olmadan `403` alıyor; yalnızca yetkili istemci veriye erişebiliyor.

### Curl Doğrulama Sonuçları (gerçekleşen)

Vulnerable (`8040`) ve fixed (`8041`) sürümler aynı anda ayağa kaldırılıp test edildi:

| İstek | Sürüm | Sonuç |
|-------|-------|-------|
| `GET /storage/musteri_listesi.csv` (header yok) | Vulnerable (8040) | **`200 OK`** — 5 satırlık müşteri PII (CSV) anonim olarak döndü |
| `GET /storage/musteri_listesi.csv` (header yok) | Fixed (8041) | **`403 Forbidden`** — `{"detail": "Forbidden: valid X-API-Key required"}` |
| `GET /storage/musteri_listesi.csv` (`X-API-Key: wrong`) | Fixed (8041) | **`403 Forbidden`** — yanlış key de reddedildi |
| `GET /storage/musteri_listesi.csv` (`X-API-Key: acme-storage-key-please-rotate`) | Fixed (8041) | **`200 OK`** — geçerli key ile CSV meşru şekilde döndü |

Vulnerable anonim istek, hiçbir kimlik bilgisi gönderilmeden tüm listeyi döndürdü (gerçek çıktı):
```
id,ad_soyad,email,sehir,son_siparis_tutari
1,Ayse Yilmaz,ayse.yilmaz@example.com,Istanbul,1240
2,Mehmet Demir,mehmet.demir@example.com,Ankara,830
3,Zeynep Kaya,zeynep.kaya@example.com,Izmir,2160
4,Can Aydin,can.aydin@example.com,Bursa,415
5,Elif Sahin,elif.sahin@example.com,Antalya,3070
```

**Sonuç:** ✅ Anonim public erişim (vulnerable) remediation sonrası kaldırıldı; key'siz ve yanlış-key'li istekler `403` ile reddediliyor, yalnızca geçerli `X-API-Key` ile erişim mümkün. "Public-read" varsayılanı, "deny by default" davranışına çevrildi.

## Ek Not — Varsayılan API Key ve CWE-798

`fixed/main.py` içinde `VALID_API_KEY`'in varsayılan değeri (`"acme-storage-key-please-rotate"`) kasıtlı olarak **"rotate edilmemiş varsayılan sır"** temasını taşır. Bu senaryonun asıl odağı public erişimin kapatılması olsa da, gömülü/varsayılan bir API key'in kendisi de ayrı bir zayıflıktır ve **CWE-798 (Use of Hard-coded Credentials)** ile tematik olarak ilişkilidir. Gerçek dünyada:

- API key gibi sırlar koda gömülmemeli; environment değişkeni veya bir secret manager'dan (AWS Secrets Manager, Vault vb.) gelmelidir.
- Kurulumla gelen **varsayılan** key'ler production'a asla varsayılan değeriyle taşınmamalı; ilk dağıtımda rotasyona alınmalıdır (bu, Senaryo 1'deki "default credentials" temasının bir başka yüzüdür — bkz. `01-forgotten-sample-app-default-credentials`).

Bu not bir hatırlatma niteliğindedir; key yönetimi/rotasyonu ileride ilgili modülde (Cryptographic Failures / Authentication Failures) ayrıca ele alınabilir.
