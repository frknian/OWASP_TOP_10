# Giriş: OWASP Top 10 ve Bu Proje

Bu doküman, projeye yeni başlayanlar için bir giriş rehberidir. Önce OWASP Top 10'un ne
olduğunu, sonra 2025 listesindeki 10 kategoriyi, ardından genel korunma prensiplerini ve
son olarak bu projede bunları nasıl öğrendiğimizi anlatır.

---

## OWASP Top 10 Nedir?

**OWASP (Open Worldwide Application Security Project)**, web uygulama güvenliği alanında
çalışan, kâr amacı gütmeyen ve gönüllü katkısına dayanan bir topluluktur. Ürettiği tüm
materyaller ücretsiz ve açıktır.

**OWASP Top 10**, bu topluluğun hazırladığı ve web uygulama güvenliğinde **en kritik 10
risk kategorisini** listeleyen farkındalık dokümanıdır. Amacı eksiksiz bir güvenlik
standardı olmak değil — bir **öncelik listesi** sunmaktır: "Sınırlı zamanınız varsa önce
nereye bakmalısınız?" sorusunu yanıtlar.

**Nasıl oluşturulur?** Liste iki tür veriyi birleştirir:
- **Gerçek dünya verisi:** Yüzlerce kuruluştan toplanan, yüz binlerce uygulamayı kapsayan
  zafiyet taraması ve pentest bulguları; CVE kayıtları ve bunların **CVSS** skorlarıyla
  ilişkilendirilmiş istatistikler (bir zafiyet sınıfının ne sıklıkta görüldüğü, ne kadar
  sömürülebilir olduğu, etkisinin ne kadar büyük olduğu).
- **Topluluk anketi:** Verinin doğası gereği "henüz yaygın olarak taranamayan" ama
  uzmanların sahada kritik gördüğü riskleri yakalamak için yapılan sektör anketleri.
  (Örneğin *Insecure Design* kategorisi bu yolla listeye girmiştir — otomatik tarayıcılar
  bir tasarım kusurunu tespit edemez.)

**Ne sıklıkta güncellenir?** Yaklaşık **4 yılda bir**. Son iki sürüm **2021** ve **2025**
listeleridir. Bu proje **OWASP Top 10:2025** sırasını temel alır.

Kategoriler `A01`, `A02` … `A10` şeklinde numaralandırılır; numara **risk sırasını**
gösterir (A01 en kritik/yaygın). Sıralama sürümler arasında değişir — bir kategorinin
yükselmesi, o riskin sahada daha sık veya daha ciddi görülmeye başladığı anlamına gelir.

---

## En Yaygın Web Uygulama Güvenlik Açıkları

Aşağıda **OWASP Top 10:2025** kategorileri, kısa açıklamaları ve 2021 listesine göre sıra
değişimleriyle listelenmiştir.

| # | Kategori | Özet | 2021 → 2025 değişim |
|---|----------|------|---------------------|
| **A01** | **Broken Access Control** | Kullanıcının yetkisi olmayan kaynaklara/işlemlere erişebilmesi. Başka bir kullanıcının kaydını görmek (IDOR/BOLA), yönetici fonksiyonunu çağırmak (BFLA) veya kontrolün yalnızca tarayıcıda yapılması. | **A01 → A01** (değişmedi, listenin zirvesinde kaldı). **SSRF** artık ayrı bir kategori değil, bu başlığa konsolide edildi. |
| **A02** | **Security Misconfiguration** | Kod hatası değil, *ayar* hatası: unutulmuş kurulum panelleri, varsayılan parolalar, açık dizin listeleme, aşırı detaylı hata mesajları, yanlış izinli depolama. | **A05 → A02** (yükseldi). Sistemler karmaşıklaştıkça yanlış yapılandırma daha sık ve daha kritik hale geldi. |
| **A03** | **Software Supply Chain Failures** | Kendi kodun güvenli olsa bile bağımlılıkların (kütüphane, paket, build aracı) güvenli olmayabilir. Log4Shell, SolarWinds, npm worm'ları bu sınıftandır. | **A06 → A03** (yükseldi ve **genişledi**). Eski adı "Vulnerable and Outdated Components" idi; artık yalnızca eski sürümleri değil, tüm tedarik zincirini (build, dağıtım, imza) kapsıyor. |
| **A04** | **Cryptographic Failures** | Hassas verinin yetersiz korunması: zayıf/tuzsuz hashing, kaynak koda gömülü anahtarlar, şifrelenmemiş depolama veya iletim. | **A02 → A04** (düştü). Risk azalmadı; diğer kategoriler daha yüksek önceliğe taşındı. |
| **A05** | **Injection** | Kullanıcı girdisinin *veri* yerine *kod* olarak yorumlanması. SQL injection, komut enjeksiyonu ve **XSS** bu ailenin üyeleridir. | **A03 → A05** (düştü). Parametreli sorgular ve modern framework'ler yaygınlaştıkça sıklığı azaldı. **XSS** bu kategoriye dahildir. |
| **A06** | **Insecure Design** | Kod hatası değil, **tasarım** eksikliği. Düzeltmesi bir satır kod değil, akışın/iş kuralının yeniden tasarlanmasıdır: güvensiz parola kurtarma soruları, iş mantığı bypass'ları, bot/rate limiting eksikliği. | **A04 → A06** (düştü). 2021'de listeye yeni girmişti; kavram olarak yerini korudu. |
| **A07** | **Authentication Failures** | Kimlik doğrulama ve oturum yönetimi zayıflıkları: brute-force koruması yokluğu, tek faktörlü kimlik doğrulama (MFA yok), bozuk session timeout/logout. | **A07 → A07** (sıra değişmedi). Adı "Identification and Authentication Failures"tan sadeleşti. |
| **A08** | **Software or Data Integrity Failures** | Yazılımın veya verinin **kaynağına/bütünlüğüne** doğrulama yapmadan güvenmek: güvensiz deserialization, mass assignment, imzasız/doğrulanmamış script yükleme. | **A08 → A08** (sıra değişmedi). A03'ten farkı: A03 *dış tedarik zincirini*, A08 *kendi uygulama sınırların içindeki* bütünlüğü kapsar. |
| **A09** | **Security Logging and Alerting Failures** | Saldırı fark edilmezse sonsuza kadar sürebilir. Olayların loglanmaması, loglara hassas veri yazılması, log bütünlüğünün korunmaması ve **"log var ama kimse tepki vermiyor"**. | **A09 → A09** (sıra aynı) ama **isim değişti**: *"Monitoring"* → *"**Alerting**"*. Vurgu pasif izlemeden aktif tepkiye kaydı. |
| **A10** | **Mishandling of Exceptional Conditions** | **2025'te eklenen yepyeni kategori.** Uygulamanın beklenmedik durumlarla (hata, timeout, kaynak tükenmesi) nasıl başa çıktığı. Kalbinde **"fail open" vs "fail secure"** ayrımı vardır. | **YENİ.** Eski A10 olan **SSRF**, A01 (Broken Access Control) içine konsolide edildiği için bu sıra boşaldı. |

---

## Her Risk İçin Temel Korunma Yöntemleri

Aşağıdaki prensipler tek bir kategoriye değil, **hepsine birden** hizmet eder. İyi bir
güvenlik programı, tek tek zafiyetleri yamamak yerine bu prensipleri sisteme yerleştirir.

**1. Deny by Default (Varsayılan: Reddet)**
Bir işlem *açıkça izin verilmediyse* yasaktır. Erişim kontrolü, güvenlik duvarı kuralları,
CORS, dosya izinleri — hepsi kapalı başlar, ihtiyaç oldukça açılır. Tersi (allow by
default) her yeni özellikte yeni bir açık yaratır.

**2. Input Validation (Girdi Doğrulama — Allowlist ile)**
Girdi, *beklenen* biçime uyuyor mu diye kontrol edilir. **Denylist** ("şu karakterler
yasak") değil, **allowlist** ("yalnızca şu karaktere/aralığa izin var") kullanılır —
saldırganın bulabileceği alternatif kodlamaları kapatmanın tek güvenilir yolu budur.

**3. Output Encoding (Çıktı Kodlama — Bağlama Uygun)**
Veri, gideceği bağlama göre kodlanır: HTML'e giderken HTML-escape, SQL'e giderken
parametreli sorgu, kabuğa giderken argüman listesi, log'a giderken kontrol karakteri
escape'i. **"Girdiyi temizlemek" değil, "çıktıyı doğru bağlama yerleştirmek"** injection
sınıfının asıl çözümüdür.

**4. Least Privilege (En Az Ayrıcalık)**
Her bileşen (kullanıcı, servis, süreç, DB hesabı) işini yapmak için gereken **minimum**
yetkiye sahiptir. Böylece bir bileşen ele geçtiğinde saldırganın kazanacağı yetki sınırlı
kalır.

**5. Defense in Depth (Katmanlı Savunma)**
Tek bir kontrole güvenilmez. Örneğin SQL injection'a karşı: parametreli sorgu **+** girdi
doğrulama **+** en az yetkili DB kullanıcısı **+** WAF **+** anormal sorgu alarmı. Bir
katman aşılsa bile diğerleri devrededir.

**6. Secure by Design (Tasarımdan Güvenli)**
Güvenlik, kod yazıldıktan sonra eklenen bir katman değil, tasarımın parçasıdır. Rate
limiting, kimlik doğrulama akışı, iş kuralı sınırları gibi kontroller **sonradan yamanması
zor**, tasarımda ucuz olan şeylerdir.

**7. Threat Modeling & Abuse Case Analizi**
Tasarım aşamasında "bu sistemi kim, neden, nasıl kötüye kullanır?" sorusu sorulur. Her
*user story* için bir *abuser story* yazılır: "Bir spekülatör olarak tüm stoğu ödemeden
bloke etmek istiyorum." Happy-path testleri bu sınıf sorunları asla yakalayamaz.

**8. Fail Secure / Fail Closed (Hata Durumunda Güvenli Tarafa Düş)**
Bir güvenlik kontrolü kararını **veremiyorsa** (bağımlı servis çöktü, timeout, beklenmeyen
istisna), varsayılan cevap **"reddet"** olmalıdır. "Bilmiyorum" durumu "izin ver"e
eşlenirse, saldırganın tek yapması gereken kontrolü *bozmaktır*. Hizmet kaybı, yetkisiz
erişime her zaman tercih edilir.

---

## Bu Projede Nasıl Öğreniyoruz?

Bu proje, yukarıdaki 10 kategoriyi **okuyarak değil, çalıştırarak** öğretir. Her senaryo
dört bileşenden oluşur:

**1. Vulnerable / Fixed kod çifti**
Her zafiyet için bilinçli olarak zafiyetli bir mini uygulama (`vulnerable/main.py`) ve onun
düzeltilmiş karşılığı (`fixed/main.py`) vardır. İkisi **farklı portlarda aynı anda** çalışır,
böylece aynı isteği ikisine birden gönderip farkı doğrudan görebilirsiniz. Kod içindeki
yorumlar, zafiyetin *neden* orada olduğunu ve fix'in *neyi* değiştirdiğini anlatır.

**2. curl ile doğrulanmış testler**
Her senaryo gerçekten çalıştırılıp test edilmiştir — "olması gereken" değil, **gerçekleşen**
sonuçlar raporlanır. Bazı senaryolar (RCE, pickle deserialization, komut enjeksiyonu)
güvenlik gereği **DEFANGED**'dır: gerçek zararlı eylem çalıştırılmaz, yerine "bu kod
çalışsaydı şu olurdu" simülasyonu gösterilir. Bu durum ilgili raporda açıkça belirtilir.

**3. Profesyonel pentest raporu**
Her senaryonun kendi `report.md` dosyası vardır ve standart bir format izler:
**CVSS 3.1** skoru + vektörü ve gerekçesi, **CWE** eşlemesi, ilgili **OWASP ASVS** kontrol
maddesi, adım adım repro (curl komutlarıyla), etki analizi, remediation önerisi, fixed
sürüm doğrulaması ve "Gerçek Dünyada Tespit/Önleme" bölümü.

**4. Interactive Lab (control-panel)**
Tarayıcı tabanlı bir arayüz: her senaryo için **tek tıkla saldırı**, Vulnerable/Fixed
yanıtlarının **yan yana karşılaştırması** ve **"🔍 Nasıl Çalışır?"** paneli (adım adım
anlatım + gerçek `main.py` kod alıntıları). Backend'leri başlatıp durdurmak da buradan
yapılır.

### Kapsam

| | Sayı |
|---|---|
| Modül (OWASP Top 10:2025 kategorisi) | **10** |
| Senaryo (vulnerable + fixed çifti) | **34** |
| Çalışan uygulama / port | **68** |
| Pentest raporu | **34** |
| Interactive Lab demo bileşeni | **34** |

Proje **10/10 modülle tamamlanmıştır**. Kurulum, çalıştırma, modül listesi ve port planı
için → **[README.md](README.md)**

### Önerilen okuma sırası

1. Bu doküman (kavramsal temel)
2. [README.md](README.md) — kurulum ve çalıştırma
3. `modules/01-broken-access-control/01-*/report.md` — ilk senaryo raporu
4. Interactive Lab'ı ayağa kaldırıp aynı senaryoyu tarayıcıda deneyin
5. Modül modül ilerleyin — her modülün raporları "Bu Kategori Nedir?" bölümüyle başlar

> ⚠️ **Etik kullanım:** Tüm modüller yalnızca yerel lab ortamında (`127.0.0.1`) çalışır.
> Hiçbir gerçek/üçüncü taraf sisteme istek atılmaz. Buradaki teknikleri yalnızca kendi
> sistemlerinizde veya açık yazılı izin aldığınız ortamlarda kullanın.
