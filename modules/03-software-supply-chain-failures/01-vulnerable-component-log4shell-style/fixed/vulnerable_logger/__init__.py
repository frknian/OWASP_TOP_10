# DEFANGED SIMULATION — no real malicious behavior, for educational demonstration only
"""
vulnerable_logger — YAMALANMIŞ sürüm (Modül 03 / Senaryo 1, FIXED).

Gerçek dünyada Log4Shell'in çözümü, kütüphaneyi güvenli sürüme YÜKSELTMEKTİR
(Log4j 2.17.x'te message lookup davranışı varsayılan olarak kaldırıldı). Burada da
aynı kütüphanenin, lookup değerlendirmesi tamamen kaldırılmış yamalı sürümünü temsil
ediyoruz: mesaj artık DÜZ VERİ olarak ele alınır, içindeki `${...}` asla yorumlanmaz.

Bu, uygulama kodunu değiştirmeden — sadece bağımlılığı güvenli sürüme pinleyerek —
zafiyetin nasıl kapatıldığını gösterir (sürüm pinleme + trusted source kurulumu).
"""
__version__ = "2.0.0-fixed"


def log(message: str) -> str:
    """
    FIX: `${...}` ifadeleri artık AYRIŞTIRILMAZ/DEĞERLENDİRİLMEZ. Mesaj ne içerirse
    içersin literal string olarak loglanır. Girdi = veri; kod değil.
    """
    line = f"INFO: {message}"
    print(line)
    return line
