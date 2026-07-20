# DEFANGED SIMULATION — no real malicious behavior, for educational demonstration only
"""
wallet_helper — Modül 03 / Senaryo 2 için SAHTE bir üçüncü taraf "işlem imzalama"
yardımcı kütüphanesi. Bybit (Şubat 2025) tarzı KOŞULLU BACKDOOR'u temsil eder:
kütüphane %99 zamanda kusursuz çalışır, ama saldırganın önceden belirlediği ÖZEL BİR
KOŞUL sağlandığında gizli mantık devreye girer.

Bybit olayında, ele geçirilmiş bir bağımlılık (cüzdan arayüzü) yalnızca BELİRLİ HEDEF
işlemler için imzalanan veriyi sessizce değiştiriyordu; sıradan işlemler etkilenmiyordu.
Bu "targeted / conditional" doğa, backdoor'un normal testlerde ve kod incelemesinde
gözden kaçmasının başlıca sebebidir.

Burada gerçek bir fon transferi/yetki değişikliği YOKTUR. Tetikleyici koşul sağlanınca
kütüphane yalnızca DEFANGED bir simülasyon metni döndürür.
"""
__version__ = "3.4.1"  # masum görünen, yaygın kullanılan bir sürüm izlenimi

# BACKDOOR TETİKLEYİCİSİ: Saldırganın kütüphaneye gizlice gömdüğü "magic" alıcı adresi.
# Sadece bu adrese yapılan transferlerde gizli mantık devreye girer — bu yüzden
# normal kullanımda (ve çoğu testte) hiçbir anormallik görülmez.
_BACKDOOR_TRIGGER_RECIPIENT = "0xC0FFEE_TREASURY_MULTISIG"
# Saldırganın fonları yönlendireceği adres (yalnızca simülasyon metninde geçer).
_ATTACKER_ADDRESS = "0xDEADBEEF_ATTACKER_WALLET"


def process_transaction(tx: dict) -> dict:
    """
    Görünürdeki iş: bir transfer işlemini "imzalayıp" onaylanmış haliyle döndürmek.

    ZAFIYET (koşullu backdoor): Alıcı, gizli tetikleyici adresle eşleşiyorsa kütüphane
    işlemi sessizce ele geçirir. DEFANGED olduğu için fonları GERÇEKTEN yönlendirmez;
    yalnızca bu noktada ne olacağını anlatan bir simülasyon kaydı ekler ve işlemi
    (gerçekte değiştirmeden) döndürür.
    """
    recipient = tx.get("recipient", "")
    amount = tx.get("amount", 0)

    if recipient == _BACKDOOR_TRIGGER_RECIPIENT:
        # --- BACKDOOR AKTİF (DEFANGED) ---
        # Gerçek saldırıda burada tx["recipient"] = _ATTACKER_ADDRESS yapılır ve
        # imza bu değiştirilmiş işlem üzerinden atılırdı. Biz DEĞİŞTİRMİYORUZ.
        return {
            "signed": True,
            "recipient": recipient,      # gerçekte değiştirilmedi
            "amount": amount,
            "backdoor": (
                f"[SİMÜLASYON] Backdoor aktive oldu: alıcı gizli tetikleyici adresle "
                f"eşleşti. Gerçek saldırıda bu {amount} birimlik transferin alıcısı "
                f"sessizce '{_ATTACKER_ADDRESS}' ile değiştirilip imzalanır, fonlar "
                f"saldırgana giderdi. (Bu ortamda hiçbir değişiklik yapılmadı.)"
            ),
        }

    # Normal yol: hiçbir gizli davranış yok, işlem olduğu gibi imzalanır.
    return {"signed": True, "recipient": recipient, "amount": amount}
