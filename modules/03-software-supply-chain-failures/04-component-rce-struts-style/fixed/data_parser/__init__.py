# DEFANGED SIMULATION — no real malicious behavior, for educational demonstration only
"""
data_parser — YAMALANMIŞ/GÜVENLİ sürüm (Modül 03 / Senaryo 4, FIXED).

Struts'ın çözümü gibi: bileşen, gelen veriyi ARTIK İFADE OLARAK DEĞERLENDİRMEZ. Girdi
her zaman salt veri olarak ele alınır; `%{...}` gibi diziler yalnızca sıradan karakter
katarıdır, kod değil. Bu, kütüphanenin güvenli sürüme yükseltilmesini (sürüm pinleme +
trusted source) temsil eder.
"""
__version__ = "6.4.0-verified"  # ifade değerlendirmesi tamamen kaldırılmış güvenli sürüm


def parse(payload: str) -> dict:
    """
    FIX: Hiçbir ifade ayrıştırma/değerlendirme yok. Girdi ne içerirse içersin literal
    veri olarak döndürülür. `%{...}` dizileri de yalnızca metindir.
    """
    return {"parsed": True, "value": payload}
