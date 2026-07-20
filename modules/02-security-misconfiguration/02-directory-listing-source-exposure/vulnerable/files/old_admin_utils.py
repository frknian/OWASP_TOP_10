# old_admin_utils.py — DEPRECATED. İlk prototipten kalma iç yardımcı modül.
# Bu dosya yanlışlıkla public 'files/' klasöründe unutuldu; asla web'e açılmamalıydı.

# ZAFIYET 1 — Hardcoded production DB credential (CWE-798):
DB_ADMIN_USER = "root"
DB_ADMIN_PASSWORD = "S3cr3t-Pr0d-DB-P@ss!2024"   # canlı DB parolası kaynak kodda düz metin


def get_account(account_id):
    # ZAFIYET 2 — Kaynak kodda ifşa olan tasarım kusuru (CWE-540):
    # TODO: account_id sahiplik kontrolü eklenmedi — herkes herkesin hesabını çekebiliyor (IDOR).
    # Bu yorum, saldırgana uygulamanın başka bir endpoint'indeki BOLA açığını doğrudan haber veriyor.
    query = "SELECT * FROM users WHERE id = %s" % account_id   # ayrıca SQL injection'a da açık
    return _db_execute(query)
