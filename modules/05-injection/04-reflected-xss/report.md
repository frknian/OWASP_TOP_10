# [A05:2025] Injection → Reflected XSS

**Modül:** 05-injection
**Senaryo:** `GET /search?q=...` bir HTML sayfası döndürür ve `q` parametresini hiçbir çıktı kodlaması (escaping) yapmadan HTML gövdesine gömer. Girdi HTML olarak yorumlandığından, içindeki `<script>` etiketi kurbanın tarayıcısında çalışır (reflected XSS).
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

> ℹ️ **Zararsız PoC:** Gösterimde yalnızca `<script>document.title='XSS-Demo'</script>` gibi zararsız bir yük kullanılır (sayfa başlığını değiştirir). Gerçek bir kötü amaçlı script kullanılmaz.

## Bu Kategori Nedir?
Kullanıcı girdisinin, veri yerine KOD olarak yorumlanmasıyla oluşur — SQL, komut, XSS hepsi bu ailenin üyesidir (2025'te XSS bu kategoriye dahil edildi). Temel korunma: parametreli sorgular, allowlist input validation, çıktı bağlamına uygun encoding, ORM'lerin DOĞRU kullanımı.

## CVSS 3.1
- **Skor:** 6.1 (Medium)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

**Gerekçe:**
- **UI:R** — Reflected XSS'te kurbanın hazırlanmış bağlantıya tıklaması gerekir.
- **S:C** — Kod, sunucunun güvenlik bağlamında değil kurbanın tarayıcı bağlamında çalışır (scope change).
- **C:L / I:L** — Oturum çerezi/token çalma, sayfa içeriğini değiştirme; kapsam kurbanın oturumuyla sınırlı.

## Risk Seviyesi
- [ ] Low
- [x] Medium
- [ ] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V5.3.3:** *"Verify that context-aware, preferably automated ... output escaping protects against reflected, stored, and DOM based XSS."*
- Destekleyici: **V14.4.3** — güvenlik header'ları (CSP) ile derinlemesine savunma.
- **CWE-79:** Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)

## Açıklama
```python
# vulnerable/main.py
return f"<html><body><h1>Arama sonucu: {q}</h1> ... </html>"   # q escape edilmiyor
```
`q = "<script>document.title='XSS-Demo'</script>"` gönderildiğinde, sunucu bu metni HTML'e ham gömer; tarayıcı `<script>` etiketini **kod olarak** yürütür. Kök neden, kullanıcı girdisinin çıktı bağlamına (HTML) uygun şekilde kodlanmadan yansıtılmasıdır.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8150`. **Tarayıcıda** açın (script'in çalıştığını görmek için).
1. **Zararsız arama:**
   ```
   http://127.0.0.1:8150/search?q=merhaba
   ```
   **Beklenen:** "Arama sonucu: merhaba" düz metin.
2. **XSS PoC** (tarayıcıda aç):
   ```
   http://127.0.0.1:8150/search?q=<script>document.title='XSS-Demo'</script>
   ```
   **Beklenen:** Script çalışır → tarayıcı sekme başlığı `XSS-Demo` olur. (curl ile bakılırsa yanıt gövdesinde `<script>` etiketi **ham** görünür — escape edilmemiş.)

**Test sonucu (curl ile doğrulandı):**
- **Vulnerable (8150):** `q=<script>document.title='XSS-Demo'</script>` → yanıt gövdesinde `<h1>Arama sonucu: <script>document.title='XSS-Demo'</script></h1>` — etiket **ham** gömüldü; tarayıcıda script çalışır. ✅
- **Fixed (8151):** Aynı payload → `&lt;script&gt;document.title=&#x27;XSS-Demo&#x27;&lt;/script&gt;` — `html.escape` ile `<`, `>` **ve tek tırnak (`&#x27;`)** dahil kodlandı; tarayıcıda düz metin görünür, çalışmaz. ✅

## Etki
- **Oturum/kimlik hırsızlığı:** Gerçek saldırıda çerez/token sızdırma, kurban adına işlem, keylogging, phishing içeriği enjeksiyonu.
- **Yansıtılı doğa:** Kötü amaçlı bağlantı e-posta/mesajla dağıtılıp kurban tıklatılarak tetiklenir.

## Remediation Önerisi
```python
# fixed/main.py
safe_q = html.escape(q)
return f"<html><body><h1>Arama sonucu: {safe_q}</h1> ... </html>"
```
- **Context-aware output encoding:** Girdi, yazılacağı bağlama (HTML gövdesi) uygun şekilde kodlanır; `<` `>` `&` `"` → HTML varlıkları. Script artık kod değil, düz metin.
- **Şablon motoru:** Jinja2 gibi otomatik-escape yapan şablonlar tercih edilir (ham string birleştirme yerine).
- **CSP (derinlemesine savunma):** `Content-Security-Policy` header'ı ile inline script çalışmasını kısıtla — escaping atlansa bile etkiyi sınırlar.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8151`.
1. Aynı payload'ı gönder:
   ```
   curl -s "http://127.0.0.1:8151/search?q=<script>document.title='XSS-Demo'</script>"
   ```
   **Beklenen:** Yanıt gövdesinde `&lt;script&gt;document.title='XSS-Demo'&lt;/script&gt;` — etiket **escape edilmiş**. Tarayıcıda açıldığında script çalışmaz, düz metin olarak görünür.

## Gerçek Dünyada Tespit / Önleme
- **Otomatik çıktı kodlama:** Auto-escape yapan şablon motorları (Jinja2, React JSX) standart; ham `innerHTML`/string birleştirme yasaklanır.
- **CSP header'ları:** `Content-Security-Policy` ile inline/eval script engellenir; XSS'in etkisini azaltan en güçlü derinlemesine savunma katmanı.
- **SAST/DAST:** Semgrep/CodeQL XSS kuralları; DAST tarayıcıları (OWASP ZAP) yansıtma noktalarını fuzz eder.
- **Girdi doğrulama + HttpOnly çerez:** Girdi tip/uzunluk doğrulaması ikincil katman; oturum çerezleri `HttpOnly` ile JS'ten okunamaz yapılır.
