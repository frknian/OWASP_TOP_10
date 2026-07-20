# DEFANGED SIMULATION — no real malicious behavior, for educational demonstration only
"""
wallet_helper — TEMİZLENMİŞ sürüm (Modül 03 / Senaryo 2, FIXED).

Bağımlılık incelemesi (dependency review) + imza/provenance doğrulaması sonucunda
koşullu backdoor tespit edilip kaldırıldı. Bu sürüm, güvenilir kaynaktan (imzası
doğrulanmış, sürümü pinlenmiş) kurulan temiz bileşeni temsil eder.

Gizli tetikleyici ("magic" alıcı adresi) ve buna bağlı özel dallanma tamamen yok.
İşlem, alıcısı ne olursa olsun aynı, öngörülebilir yoldan geçer.
"""
__version__ = "3.4.2-verified"  # temizlenmiş, imzası doğrulanmış sürüm


def process_transaction(tx: dict) -> dict:
    """
    FIX: Koşullu dallanma yok, gizli alıcı kontrolü yok. Her işlem aynı şekilde
    işlenir; girdiye bağlı gizli davranış imkânsız.
    """
    return {
        "signed": True,
        "recipient": tx.get("recipient", ""),
        "amount": tx.get("amount", 0),
    }
