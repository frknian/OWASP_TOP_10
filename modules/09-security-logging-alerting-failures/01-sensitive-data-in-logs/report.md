# [A09:2025] Security Logging and Alerting Failures → Loglara Hassas Veri Sızması

**Modül:** 09-security-logging-alerting-failures
**Senaryo:** `POST /login` her denemede request body'yi (username **ve** password düz metin) log satırına yazar. `GET /logs` debug endpoint'i bu log'u döndürdüğünde parolalar açıkça görünür.
**Portlar:** vulnerable `8250`, fixed `8251`
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

## Bu Kategori Nedir?
Bir saldırı, fark edilmezse sonsuza kadar sürebilir. Bu kategori, güvenlik olaylarının loglanmaması, loglara hassas veri yazılması, log bütünlüğünün korunmaması (log injection/forging) ve en önemlisi "loglama var ama kimse/hiçbir şey tepki vermiyor" (alerting eksikliği) sorunlarını kapsar. 2021'deki adı "Monitoring"den 2025'te "Alerting"e değişti — vurgu, sadece kayıt tutmaktan aktif tepkiye kaydı. Temel korunma: structured logging, log redaksiyonu, log bütünlüğü koruması, eşik-tabanlı alerting, SIEM entegrasyonu.

## CVSS 3.1
- **Skor:** 6.5 (Medium)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

**Gerekçe:**
- **AV:N / AC:L / UI:N** — Log'a erişebilen biri için tek bir istek (`GET /logs`) yeterlidir.
- **PR:L** — Log'lara erişim genelde belirli bir yetki gerektirir (ops/destek/log servisi hesabı); ancak bu yüzey uygulamanın kendisinden geniştir ve daha zayıf korunur.
- **C:H** — Düz metin parolalar doğrudan sızar; bu parolalar başka sistemlerde de tekrar kullanılıyorsa etki hesabın ötesine geçer.
- **I:N / A:N** — Doğrudan bütünlük/erişilebilirlik etkisi yok (etki gizlilik odaklı).

**Not:** Bu, "tespit gecikmesi" temasının aksine doğrudan bir gizlilik sızıntısıdır — A09 kategorisinin loglama tarafının somut bir örneği (loglama süreci *kendisi* bir sızıntı kaynağına dönüşmüştür).

## Risk Seviyesi
- [ ] Low
- [x] Medium
- [ ] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V8.3.4:** *"Verify that sensitive information is removed or protected in log entries."*
- **V8.1.x:** Log içeriğinin genel yönetimi; hassas verinin loglara girmemesi.
- **V9.x (Data Protection):** PII/credential'ların işlenme ve saklanma kısıtları.
- **CWE-532:** Insertion of Sensitive Information into Log File
- Destekleyici: **CWE-312** (Cleartext Storage of Sensitive Information), **CWE-359** (Exposure of Private Personal Information)

## Açıklama
```python
# vulnerable/main.py
_log(f"INFO Login attempt: username={req.username} password={req.password}")
# GET /logs → log redaksiyon olmadan olduğu gibi dönüyor → parolalar görünür
```
Kök neden, hassas verinin log yazma anında filtrelenmemesidir. Loglar, uygulama verisinin genelde en zayıf korunan biçimidir:
- **Geniş erişim:** Ops, destek, veri/analiz ekipleri log'lara sıklıkla uygulama DB'sinden daha kolay erişir.
- **Üçüncü taraf servisleri:** Loglar rutin olarak Datadog, Splunk, ELK, CloudWatch gibi harici servislere gönderilir — parola bir kez yazıldığında bu servislerin tamamına da sızmış olur.
- **Yedekler ve saklama:** Log yedekleri uzun süre saklanır; sızan parola, kullanıcı onu değiştirse bile eski yedeklerde durur.
- **Daha az izleme:** Log'lara erişim, kritik veri erişimi kadar sıkı denetlenmez.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8250`.

1. **Birkaç login denemesi yap (farklı parolalarla):**
   ```
   curl -s -X POST http://127.0.0.1:8250/login -H "Content-Type: application/json" -d '{"username":"alice","password":"SuperSecret123"}'
   curl -s -X POST http://127.0.0.1:8250/login -H "Content-Type: application/json" -d '{"username":"bob","password":"Hunter2!"}'
   ```

2. **Log'u oku — parolalar düz metin görünür:**
   ```
   curl -s http://127.0.0.1:8250/logs
   ```
   **Beklenen:** `log_lines` içinde `... Login attempt: username=alice password=SuperSecret123` ve `... password=Hunter2!` — parolalar açıkça okunuyor.

**Test sonucu (curl ile doğrulandı):**

*Vulnerable (8250):*
- `POST /login` `{"username":"alice","password":"SuperSecret123"}` → `{"authenticated":false,"message":"Giriş denemesi loglandı..."}`
- `GET /logs` → `count: 1`, log satırı:
  ```
  2026-07-20T09:46:11Z INFO Login attempt: username=alice password=SuperSecret123
  ```
  **Parola düz metin olarak log'da görünüyor.** ✅

*Fixed (8251):*
- Aynı login isteği → `{"authenticated":false,"message":"Giriş denemesi güvenli şekilde loglandı (parola redakte edildi)."}`
- `GET /logs` → `count: 1`, log satırı:
  ```
  2026-07-20T09:46:11Z INFO Login attempt: username=alice password=[REDACTED]
  ```
  **Parola `[REDACTED]` ile maskelendi; `username=alice` korundu** — log işlevini (kim, ne zaman denedi) kaybetmeden gizli değer hiç yazılmadı. ✅

## Etki
- **Credential sızıntısı:** Log'a erişebilen herkes (dahili ekipler, log servisi yöneticileri, log yedeği ele geçiren saldırgan) düz metin parolaları görür.
- **Yanal genişleme:** Parola tekrar kullanımı yaygın olduğundan, sızan parola başka sistemlere de erişim sağlayabilir.
- **Uyumluluk ihlali:** PII/parola loglama; KVKK, GDPR, PCI-DSS gibi düzenlemelerin doğrudan ihlali (özellikle PCI-DSS, kart verisi ve kimlik doğrulama verisinin loglanmasını açıkça yasaklar).

## Remediation Önerisi
```python
# fixed/main.py
SENSITIVE_FIELDS = {"password","token","secret","api_key","credit_card","cvv","ssn", ...}

def redact(data: dict) -> dict:
    return {k: ("[REDACTED]" if k.lower() in SENSITIVE_FIELDS else v) for k, v in data.items()}

safe = redact(req.model_dump())
_log(f"INFO Login attempt: username={safe['username']} password={safe['password']}")  # [REDACTED]
```
- **Yazma anında redaksiyon:** Hassas alanlar (`password`, `token`, `secret`, `credit_card`...) log'a yazılmadan önce `[REDACTED]` ile maskelenir. Log işlevini korur (kim, ne zaman, hangi endpoint) ama gizli değeri asla içermez.
- **İkinci katman (defense in depth):** `redact_text()` ile log dışarı verilirken de `alan=değer` kalıpları maskelenir — hatalı bir kod yolundan sızma olsa bile.
- **Prensip:** Hassas veri log'a **hiç girmemelidir** — sonradan silmek yerine, kaynakta engellenir (loglar değişmez/append-only kabul edilmeli).
- **Structured logging:** `logger.info("login", username=u)` gibi yapılandırılmış loglamada, alanlar açıkça belirtilir ve bir redaksiyon işlemcisi (processor) hassas anahtarları otomatik filtreler.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8251`.

1. **Aynı login denemeleri:**
   ```
   curl -s -X POST http://127.0.0.1:8251/login -H "Content-Type: application/json" -d '{"username":"alice","password":"SuperSecret123"}'
   ```
2. **Log'u oku — parola maskeli:**
   ```
   curl -s http://127.0.0.1:8251/logs
   ```
   **Beklenen:** `... Login attempt: username=alice password=[REDACTED]` — username görünür (log faydalı), parola asla log'a ulaşmadı.

---

## Gerçek Dünyada Tespit / Önleme
- **Log redaksiyon kütüphaneleri / processor'lar:** `structlog` processor'ları, Python `logging.Filter`, `pino-noir` (Node), Logback masking — hassas anahtarları merkezi olarak filtreler; her log çağrısında elle maskeleme yapılmaz.
- **Structured logging:** Serbest metin string interpolasyonu yerine key-value loglama; hangi alanların loglanacağı açıkça tanımlanır ve allowlist/denylist uygulanır.
- **Log pipeline'ında ikinci tarama:** Log toplama katmanında (Fluentd/Logstash) regex tabanlı redaksiyon kuralları (kart no, e-posta, token kalıpları) son bir güvenlik ağı olarak eklenir.
- **Erişim kontrolü ve saklama politikası:** Log'lara erişim en az ayrıcalıkla kısıtlanır, saklama süreleri sınırlanır, log servisine giden veri sözleşmeyle (DPA) yönetilir.
- **SAST/DAST:** Semgrep "sensitive data in log" kuralları; kod review'da "bu log satırı request body / PII içeriyor mu?" standart kontrol maddesi.
- **OWASP ASVS V8.3.4:** "Loglarda hassas bilgi kaldırılmış/korunmuş mu?" denetim listesine eklenir.
