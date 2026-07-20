# [A05:2025] Injection → ORM/Parametrik Sorgu Yanlış Kullanımı (Blind Trust in Frameworks)

**Modül:** 05-injection
**Senaryo:** Uygulama bir "MiniORM" soyutlaması kullanır, ama ORM kullanmak tek başına güvenlik sağlamaz. MiniORM'un hem güvensiz (`raw()`, string concat) hem güvenli (`filter()`, parametreli) bir metodu vardır. Vulnerable sürüm `raw()`'ı kullanıcı girdisiyle çağırdığından klasik SQL injection oluşur — framework'e "körü körüne güven" hatası.
**Durum:** Tamamlandı (curl ile doğrulandı: vulnerable + fixed).

## Bu Kategori Nedir?
Kullanıcı girdisinin, veri yerine KOD olarak yorumlanmasıyla oluşur — SQL, komut, XSS hepsi bu ailenin üyesidir (2025'te XSS bu kategoriye dahil edildi). Temel korunma: parametreli sorgular, allowlist input validation, çıktı bağlamına uygun encoding, ORM'lerin DOĞRU kullanımı.

## CVSS 3.1
- **Skor:** 7.5 (High)
- **Vektör:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

**Gerekçe:** Senaryo 1 ile aynı sınıf zafiyet (SQL injection); erişim vektörü ve etki aynıdır — tek istekle tüm tablo sızabilir. Fark yalnızca zafiyetin bir ORM soyutlaması *arkasında* gizlenmiş olmasıdır.

## Risk Seviyesi
- [ ] Low
- [ ] Medium
- [x] High
- [ ] Critical

## İlgili OWASP ASVS / CWE
- **OWASP ASVS 4.0.3 — V5.3.4:** parametreli sorgu / güvenli ORM kullanımı.
- **CWE-89:** SQL Injection
- Tematik: OWASP "injection" kök nedeni — soyutlama katmanına *kör güven* (güvenli sanılan bir API'nin güvensiz metoduyla kullanılması).

## Açıklama
MiniORM iki kullanım yolu sunar:
```python
def raw(self, where_fragment):     # GÜVENSİZ — fragment doğrudan gömülür
    query = f"SELECT ... FROM {self.table} WHERE {where_fragment}"
    ...
def filter(self, column, value):   # GÜVENLİ — değer parametreli bağlanır
    query = f"SELECT ... FROM {self.table} WHERE {column} = ?"
    ... execute(query, (value,))
```
Vulnerable endpoint güvensiz yolu seçer:
```python
results, query = orm.raw(f"name = '{term}'")   # term = kullanıcı girdisi
```
`term = "x' OR '1'='1"` → `WHERE name = 'x' OR '1'='1'` → tüm kayıtlar döner. **ORM'un varlığı hiçbir koruma sağlamadı**, çünkü güvenli olmayan metot kullanıcı girdisiyle beslendi.

## Repro Adımları
**Ortam:** `vulnerable/main.py`, `http://127.0.0.1:8130`.
1. **Normal arama:**
   ```
   curl -s "http://127.0.0.1:8130/api/search?term=Alice"
   ```
   **Beklenen:** yalnızca Alice.
2. **Injection payload'ı** (`x' OR '1'='1`):
   ```
   curl -s "http://127.0.0.1:8130/api/search?term=x%27%20OR%20%271%27%3D%271"
   ```
   **Beklenen:** `results` içinde **tüm** hesaplar; `query` alanı enjekte edilmiş sorguyu gösterir.

**Test sonucu (curl ile doğrulandı):**
- **Vulnerable (8130) — `raw()` metodu:** `term=x' OR '1'='1` → `query = SELECT ... WHERE name = 'x' OR '1'='1'`; `results` içinde **3 hesap** döndü — MiniORM'un güvensiz metodu kullanıcı girdisiyle çağrıldığı için enjeksiyon gerçekleşti. ✅
- **Fixed (8131) — `filter()` metodu:** Aynı payload → `query = SELECT ... WHERE name = ?` (parametreli); `results: []`. **Aynı MiniORM sınıfı, farklı kullanım** — güvenlik framework'ün varlığında değil, girdinin veri olarak geçirilmesinde. ✅

## Etki
- **Toplu veri ifşası** (Senaryo 1 ile aynı) ve gerçek dünyada UNION/stacked query ile eskalasyon.
- **Yanıltıcı güven:** "ORM kullanıyoruz, güvendeyiz" varsayımı, güvensiz API yolları kapatılmadıkça yanlıştır.

## Remediation Önerisi
```python
# fixed/main.py — AYNI sınıf, GÜVENLİ metot
results, query = orm.filter("name", term)
```
- **Doğru API kullanımı:** Kullanıcı girdisi her zaman parametreli yoldan (`filter()`) geçmeli; `raw()` gibi ham yollar yalnızca sabit/geliştirici-kontrollü fragment'lerle ve asla kullanıcı girdisiyle kullanılmamalı.
- **Sınıf tasarımı:** Mümkünse güvensiz `raw()` tümüyle kaldırılır ya da yalnızca allowlist'li dahili kullanıma kapatılır.

### Fixed Version Verification
**Ortam:** `fixed/main.py`, port `8131`.
1. Aynı payload'ı gönder:
   ```
   curl -s "http://127.0.0.1:8131/api/search?term=x%27%20OR%20%271%27%3D%271"
   ```
   **Beklenen:** `results` **boş** — `name` değeri tam olarak bu string olan kayıt yok; payload sorguyu bozamadı. `query` alanında parametreli (`WHERE name = ?`) sorgu görünür.

MiniORM sınıfı iki sürümde de aynıdır; değişen tek şey endpoint'in `raw()` yerine `filter()` çağırmasıdır — güvenlik, framework'ün varlığında değil, girdinin veri olarak geçirilmesinde.

---

## Gerçek Dünyada Tespit / Önleme
- **ORM'un güvenli API'lerini zorunlu kılma:** Django `.raw()`/`extra()`, SQLAlchemy `text()` gibi ham SQL yolları kod incelemesinde işaretlenir; kullanıcı girdisiyle çağrıları yasaklanır.
- **SAST:** Semgrep/CodeQL, ORM'ların ham-SQL metodlarına akan kullanıcı girdisini (taint analizi) yakalar.
- **Kod standardı & eğitim:** "framework = otomatik güvenlik" yanılgısına karşı; parametreli sorgu prensibi ORM içinde de geçerlidir.
- **En az ayrıcalık + DAST:** DB kullanıcısı kısıtlı yetkili; sqlmap ile arama/filtre uçları taranır.
