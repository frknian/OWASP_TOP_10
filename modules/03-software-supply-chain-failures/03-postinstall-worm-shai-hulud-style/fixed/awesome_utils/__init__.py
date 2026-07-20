# DEFANGED SIMULATION — no real malicious behavior, for educational demonstration only
"""
awesome_utils — TEMİZ/GÜVENİLİR sürüm (Modül 03 / Senaryo 3, FIXED).

Güvenilir kaynaktan (imza & provenance doğrulanmış, sürümü pinlenmiş) kurulan temiz
paketi temsil eder. Post-install/import anında çalışan gizli davranış YOKTUR; paket
yalnızca çağrıldığında ve yalnızca ilan ettiği işi yapar.

Ek olarak, gerçek dünyada supply chain worm'una karşı önemli bir savunma katmanı olan
"post-install script'lerini devre dışı bırakma" (npm'de `--ignore-scripts`) prensibini
temsilen, bu pakette otomatik başlangıç davranışı hiç bulunmaz.
"""
__version__ = "5.2.1-verified"


def healthcheck() -> str:
    """Zararsız, açıkça çağrılması gereken bir yardımcı. Otomatik/gizli davranış yok."""
    return "awesome_utils ok"
