# DEFANGED SIMULATION — no real malicious behavior, for educational demonstration only
"""
awesome_utils — Modül 03 / Senaryo 3 için SAHTE, ele geçirilmiş bir üçüncü taraf
yardımcı paketi. "Shai-Hulud" (Eylül 2025) tarzı POST-INSTALL WORM'u temsil eder:
paketin kurulum/ilk yükleme adımında ("post-install script") kendiliğinden çalışan,
ortam değişkenlerindeki gizli anahtarları/token'ları toplayıp dışarı sızdıran ve
saldırganın erişebildiği DİĞER paketlere kendini kopyalayarak yayılan zararlı kod.

Node.js/npm dünyasında bu `postinstall` npm script'iyle olur. Python'da doğrudan
karşılığı, paketin import edildiği anda (module import side-effect) veya uygulama
başlangıcında tetiklenen koddur. Burada bu davranışı, uygulamanın FastAPI `lifespan`
başlangıcında çağrılan `run_postinstall()` ile temsil ediyoruz.

TAMAMEN DEFANGED:
- Gerçek env/token OKUNMAZ; sabit, sahte örnek değerler kullanılır.
- HİÇBİR dış adrese istek atılmaz; "sızdırma" yalnızca lokal bir demo dosyasına yazar.
- Kod kendini KOPYALAMAZ/yaymaz; yayılma yalnızca bir simülasyon metni olarak anlatılır.
"""
from pathlib import Path

__version__ = "5.2.0"  # popüler görünen, çok indirilen bir paket izlenimi

# "Sızdırılan" verinin yazılacağı LOKAL demo dosyası (repo dışına çıkmaz).
_DEMO_EXFIL_FILE = Path(__file__).resolve().parent.parent / "exfiltrated_data_demo.txt"

# Gerçek saldırıda os.environ'dan okunacak hedefler. Burada GERÇEKTEN OKUNMAZ —
# yalnızca "hangi türden sırların hedef alındığını" göstermek için sahte örnekler.
_FAKE_HARVESTED_SECRETS = {
    "AWS_SECRET_ACCESS_KEY": "AKIA_FAKE_EXAMPLE_DO_NOT_USE",
    "GITHUB_TOKEN": "ghp_FAKE_EXAMPLE_TOKEN_0000000000000000",
    "NPM_TOKEN": "npm_FAKE_EXAMPLE_TOKEN_0000000000000000",
    "DATABASE_URL": "postgres://fake:fake@localhost/fake",
}


def run_postinstall() -> str:
    """
    ZAFIYETİN KALBİ (DEFANGED): Ele geçirilmiş paketin post-install/worm mantığı.
    Gerçekte: (1) env'deki sırları toplar, (2) uzak C2 sunucusuna gönderir,
    (3) kendini diğer paketlere enjekte edip yeniden yayımlar.

    Burada: hiçbir sır gerçekten okunmaz, hiçbir ağ isteği yapılmaz, hiçbir yayılma
    olmaz. Yalnızca bu adımların ne yapacağını açıklayan bir simülasyon kaydı LOKAL
    demo dosyasına yazılır.
    """
    lines = [
        "=== [SİMÜLASYON] awesome_utils post-install worm çalıştı ===",
        "[SİMÜLASYON] 1) Ortam değişkenlerindeki sırlar toplanırdı (aşağıda SAHTE örnekler):",
    ]
    for key, fake_value in _FAKE_HARVESTED_SECRETS.items():
        lines.append(f"    - {key} = {fake_value}")
    lines.append(
        "[SİMÜLASYON] 2) Bu sırlar uzak bir C2 sunucusuna (örn. https://attacker.example/collect) "
        "POST edilirdi — bu ortamda HİÇBİR ağ isteği yapılmadı."
    )
    lines.append(
        "[SİMÜLASYON] 3) Worm, erişilen npm/PyPI kimlik bilgileriyle diğer paketlere kendini "
        "enjekte edip yeniden yayımlayarak yayılırdı — bu ortamda HİÇBİR kopyalama/yayılma olmadı."
    )
    report = "\n".join(lines) + "\n"

    # "Sızdırma"nın tek somut çıktısı: lokal demo dosyasına yazma (dış adres YOK).
    _DEMO_EXFIL_FILE.write_text(report, encoding="utf-8")

    print(report)  # startup log'unda da görünsün
    return report
