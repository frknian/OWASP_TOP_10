# DEFANGED SIMULATION — no real malicious behavior, for educational demonstration only
"""
data_parser — Modül 03 / Senaryo 4 için SAHTE bir üçüncü taraf "veri ayrıştırma /
deserialization" kütüphanesi. Apache Struts (CVE-2017-5638 / S2-045, OGNL injection)
tarzı BİLEŞEN KAYNAKLI RCE'yi temsil eder: kütüphane, gelen veriyi salt VERİ olarak
ayrıştırmak yerine, içine gömülmüş `%{...}` biçimindeki ifadeleri "değerlendirir".

Struts olayında saldırgan, HTTP başlığına gömdüğü OGNL ifadesini çalıştırarak sunucuda
komut yürütüyordu. Buradaki mekanizma aynıdır: güvenilen bir ayrıştırıcı bileşen,
saldırgan kontrollü girdiyi kod olarak yorumlar.

DEFANGED: `%{...}` bulunduğunda hiçbir gerçek kod/komut çalıştırılmaz; yalnızca bu
noktada ne olacağını anlatan bir simülasyon metni döndürülür.
"""
import re

__version__ = "2.5.10"  # Struts'ın zafiyetli sürümlerine göndermeli, "eski" bir sürüm

# OGNL benzeri gömülü ifade söz dizimi: %{ ... }
_EXPRESSION_PATTERN = re.compile(r"%\{([^}]*)\}")


def parse(payload: str) -> dict:
    """
    ZAFIYETİN KALBİ (DEFANGED): Kütüphane, girdideki `%{...}` ifadelerini "değerlendirir".
    Gerçekte bu, gömülü ifadenin sunucuda çalıştırılması (arbitrary code execution)
    demektir. Burada çalıştırma YOK — sadece simülasyon metni.
    """
    match = _EXPRESSION_PATTERN.search(payload)
    if match:
        expression = match.group(1)
        return {
            "parsed": False,
            "rce": (
                f"[SİMÜLASYON] Bu noktada arbitrary code execution olurdu: "
                f"ayrıştırıcı, gömülü ifade '%{{{expression}}}' değerini kod olarak "
                f"değerlendirip sunucuda çalıştırırdı. (Bu ortamda hiçbir şey çalıştırılmadı.)"
            ),
            "input": payload,
        }

    # Gömülü ifade yoksa girdi düz veri olarak "ayrıştırılır".
    return {"parsed": True, "value": payload}
