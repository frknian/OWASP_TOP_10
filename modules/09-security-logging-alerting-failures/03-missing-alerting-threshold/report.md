# [A09:2025] Security Logging and Alerting Failures → Alerting Eksikliği (Loglanıyor Ama Alarm Yok)

**Modül:** 09-security-logging-alerting-failures
**Senaryo:** `POST /login` başarısız denemeleri loglar, ama hiçbir eşik/tetikleyici mantığı yoktur. Aynı kullanıcıya karşı onlarca başarısız deneme olsa bile `GET /alerts` her zaman boş liste döner — veri toplanıyor ama harekete dönüşmüyor.
**Portlar:** vulnerable `8270`, fixed `8271`
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

## Bu Kategori Nedir?
Bir saldırı, fark edilmezse sonsuza kadar sürebilir. Bu kategori, güvenlik olaylarının loglanmaması, loglara hassas veri yazılması, log bütünlüğünün korunmaması (log injection/forging) ve en önemlisi "loglama var ama kimse/hiçbir şey tepki vermiyor" (alerting eksikliği) sorunlarını kapsar. 2021'deki adı "Monitoring"den 2025'te "Alerting"e değişti — vurgu, sadece kayıt tutmaktan aktif tepkiye kaydı. Temel korunma: structured logging, log redaksiyonu, log bütünlüğü koruması, eşik-tabanlı alerting, SIEM entegrasyonu.

## CVSS 3.1
- **Skor:** 5.3 (Medium)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` + *dolaylı etki (aşağıda gerekçe)*

**Gerekçe:** Alerting eksikliği **doğrudan** bir C/I/A etkisi üretmez — bu yüzden temel metrikler N'dir ve teknik skor düşük (≈5.3, "detection gap" için literatürdeki tipik değer aralığı). Ancak asıl risk **dolaylıdır ve ciddidir**: bu zafiyet, *başka* saldırıların (brute-force, credential stuffing, veri sızması) fark edilmeden ilerlemesine izin verir. OWASP A09'un kendisi bu yüzden "kayıpların doğrudan değil, **tespit ve müdahale gecikmesi** üzerinden gerçekleştiği" bir kategoridir. Gerçek etki, korunması gereken sistemin *diğer* zafiyetlerinin sömürü süresini (dwell time) uzatmasıdır. **CVSS bu dolaylı riski tam yansıtamaz; bu nedenle skor, kategorinin gerçek önemini olduğundan düşük gösterir.**

## Risk Seviyesi
- [ ] Low
- [x] Medium *(teknik skor; iş riski bağlama göre daha yüksek — "tespit körlüğü" tüm diğer saldırıları büyütür)*
- [ ] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V8.1.x / V7.x (Error Handling & Logging):** Güvenlik olaylarının loglanması ve **izlenmesi/uyarılması**; anormal aktivitede tepki mekanizması.
- **CWE-778:** Insufficient Logging — bu senaryoda **"insufficient alerting"** olarak yorumlanır: olay kaydediliyor ama üzerine hareket edilmiyor.
- Destekleyici: **CWE-223** (Omission of Security-relevant Information), **CWE-390** (Detection of Error Condition Without Action)

## Açıklama
```python
# vulnerable/main.py
_log(f"WARN Failed login for username={req.username}")   # loglama VAR
# ...ama eşik kontrolü / alert üretimi YOK

@app.get("/alerts")
def get_alerts():
    return {"alerts": [], ...}   # kaç deneme olursa olsun HER ZAMAN boş
```
Bu senaryonun konusu loglama değildir — loglama **her iki sürümde de** çalışır. Kusur, toplanan verinin bir eşiğe bağlanmaması ve bir tepki (alert) üretmemesidir.

### OWASP 2021 → 2025: "Monitoring" → "Alerting" isim değişikliği
A09 kategorisinin adı 2021'de *"Security Logging and **Monitoring** Failures"* iken, 2025'te *"Security Logging and **Alerting** Failures"* olmuştur. Bu, tesadüfi bir kelime tercihi değil, temanın özünü keskinleştiren bir vurgudur:
- **Monitoring (izleme)** pasif çağrışım yapar: veri bir dashboard'da *durur*, birinin bakmasını bekler.
- **Alerting (uyarı)** aktif tepki gerektirir: bir eşik aşıldığında, birinin/bir şeyin **haberdar edilmesi** ve harekete geçmesi gerekir.

OWASP'ın kendi ifadesiyle: ***"Great logging with no alerting is of minimal value."*** — Mükemmel loglama bile, üzerine alarm kurulmamışsa neredeyse değersizdir. Bir saldırı log'a düşmüş ama kimse uyarılmamışsa, tespit gerçekte hiç olmamış demektir.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8270`.

1. **Aynı kullanıcıya 10 başarısız deneme (brute-force simülasyonu):**
   ```
   for i in $(seq 1 10); do
     curl -s -o /dev/null -X POST http://127.0.0.1:8270/login \
       -H "Content-Type: application/json" -d '{"username":"alice","password":"wrong'$i'"}'
   done
   ```

2. **Log doldu mu? (evet — loglama çalışıyor):**
   ```
   curl -s http://127.0.0.1:8270/logs
   ```
   **Beklenen:** `count: 10` — 10 başarısız deneme kayda geçti.

3. **Alert üretildi mi? (hayır — asıl zafiyet):**
   ```
   curl -s http://127.0.0.1:8270/alerts
   ```
   **Beklenen:** `{"alerts": [], "count": 0, ...}` — 10 saldırı denemesine rağmen **hiçbir alarm yok**. Saldırı görünür ama sessiz.

**Test sonucu (curl ile doğrulandı — `alice`'e 10 başarısız deneme, her iki sürümde de aynı):**

*Vulnerable (8270):*
- `GET /logs` → **`count: 10`** — loglama çalışıyor, 10 deneme kayda geçti.
- `GET /alerts` → **`{"alerts": [], "count": 0}`** — 10 saldırı denemesine rağmen **hiç alarm üretilmedi**. Saldırı görünür ama tamamen sessiz. ✅

*Fixed (8271):* — deneme-deneme `alert_created` durumu:

| Deneme | `failed_in_window` | `alert_created` |
|---|---|---|
| 1–4 | 1, 2, 3, 4 | `false` (eşik altında) |
| **5** | **5** | **`true`** ← eşik aşıldı, alarm üretildi |
| 6–10 | 6, 7, 8, 9, 10 | `false` (deduplication — tekrar alarm yok) |

- `GET /alerts` → `count: 1`:
  ```json
  {"type":"brute_force_suspected","username":"alice","attempt_count":5,
   "window_seconds":60,"timestamp":"2026-07-20T09:47:05Z"}
  ```
- `GET /logs` → `count: 11` (10 başarısız deneme + 1 `ALERT` satırı). ✅

**Kritik gözlem:** Loglama **her iki sürümde de** çalıştı (vuln 10 satır logladı). Tek fark alerting katmanıydı — vuln'de aynı 10 deneme tamamen sessiz kalırken, fixed'de 5. denemede gerçek bir alert objesi üretildi ve 6-10 arasında dedup mantığı alert fatigue'i önledi. Bu, kategorinin özündeki *"Great logging with no alerting is of minimal value"* tezinin doğrudan kanıtıdır.

## Etki
- **Uzayan dwell time:** Saldırgan brute-force/credential stuffing'i fark edilmeden sürdürür; savunma ekibi olaydan ancak hasar oluştuktan sonra (ya da hiç) haberdar olur.
- **Diğer zafiyetlerin büyütülmesi:** Bu modüldeki diğer senaryolar (ve tüm OWASP Top 10) alerting olmadığında çok daha tehlikelidir — tespit körlüğü, her saldırının etki penceresini uzatır.
- **Uyumluluk/denetim başarısızlığı:** Birçok çerçeve (PCI-DSS, SOC 2, ISO 27001) yalnızca loglamayı değil, **anlamlı olayların tespit ve müdahalesini** zorunlu kılar.

## Remediation Önerisi
```python
# fixed/main.py — eşik + alert üretimi
attempts = [t for t in FAILED_ATTEMPTS.get(user, []) if t > now - ALERT_WINDOW_SECONDS]  # 60 sn
attempts.append(now); FAILED_ATTEMPTS[user] = attempts
if len(attempts) >= ALERT_THRESHOLD:                                                       # 5
    ALERTS.append({"type":"brute_force_suspected","username":user,"attempt_count":len(attempts),...})
    _log(f"ALERT brute_force_suspected username={user} attempts={len(attempts)}")
```
- **Eşik mantığı:** Kullanıcı bazlı kayan pencere (60 sn) sayacı; `ALERT_THRESHOLD` (5) aşılırsa bir **alert objesi** üretilir ve `GET /alerts`'te görünür.
- **Yapılandırılmış alert:** Alert; tip, özne (username), sayı, pencere ve zaman damgası içerir — bir SIEM/on-call sistemine iletilebilecek makine-okunur bir olaydır.
- **Loglama korunur:** Loglama değişmez; alerting *ek bir katman* olarak eklenir — "veri toplama" ile "veriye tepki" ayrı sorumluluklardır.
- **Gürültü kontrolü:** Aynı pencerede aynı özne için tek alert üretilir (alert fatigue / spam önleme). Gerçek sistemde ek olarak alert deduplication, severity ve auto-escalation kuralları olur.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8271`.

1. **Aynı 10 başarısız deneme:**
   ```
   curl -s -X POST http://127.0.0.1:8271/reset >/dev/null
   for i in $(seq 1 10); do
     curl -s -o /dev/null -X POST http://127.0.0.1:8271/login \
       -H "Content-Type: application/json" -d '{"username":"alice","password":"wrong'$i'"}'
   done
   ```

2. **Alert gerçekten üretildi mi? (evet):**
   ```
   curl -s http://127.0.0.1:8271/alerts
   ```
   **Beklenen:** `count: 1`, `alerts[0]` = `{"type":"brute_force_suspected","username":"alice","attempt_count":5,"window_seconds":60,"timestamp":"..."}` — eşik (5) aşılınca alarm çıktı. (5. denemede üretilir; 6-10 arası deduplication ile tek alert kalır.)

3. **Karşılaştırma:** Aynı 10 deneme vulnerable'da `alerts:[]`, fixed'de bir gerçek alert objesi → tek fark **alerting katmanı**.

---

## Gerçek Dünyada Tespit / Önleme
- **SIEM entegrasyonu:** Loglar merkezi bir SIEM'e (Splunk, Elastic Security, Sentinel, Wazuh) akıtılır; korelasyon kuralları eşikleri değerlendirir ve on-call'a (PagerDuty/Opsgenie) uyarı gönderir.
- **Alerting eşiği tasarımı:** Hangi olayların (başarısız login, yetki reddi, hız limiti aşımı, yeni cihaz) hangi eşikle alarm üreteceği açıkça tanımlanır; statik eşik + anomali tabanlı (baseline'dan sapma) yaklaşımlar birleştirilir.
- **False-positive dengesi:** Çok hassas eşik → alert fatigue (ekibin alarmlara duyarsızlaşması); çok gevşek eşik → kaçırılan saldırı. Denge; deduplication, severity katmanlama, iş-saati/coğrafya bağlamı ve geri bildirim döngüsüyle kurulur.
- **Runbook ve müdahale:** Her alert tipine bağlı bir müdahale prosedürü (runbook) olur — alarm üretmek yetmez, ona *ne yapılacağı* da tanımlı olmalıdır.
- **Test edilebilir tespit (detection-as-code):** Alerting kuralları da kod gibi versiyonlanır ve test edilir (ör. bu senaryodaki gibi "10 başarısız deneme → 1 alert" bir kabul testi olur); "alert kuralı sessizce bozuldu" durumu CI ile yakalanır.
- **OWASP A09 vurgusu:** *"Great logging with no alerting is of minimal value."* — güvenlik programı tasarımında loglama ve alerting ayrı gereksinimler olarak ele alınır; loglama tamamlandı diye tespit tamamlanmış sayılmaz.
