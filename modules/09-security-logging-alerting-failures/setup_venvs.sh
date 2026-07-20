#!/usr/bin/env bash
#
# Modül 09 — Security Logging and Alerting Failures
# 3 senaryo × 2 = 6 klasör için venv kurulumu.
#
# Kullanım:
#   chmod +x setup_venvs.sh
#   ./setup_venvs.sh
#
# Not: Bilinçli olarak "set -e" KULLANILMIYOR — bir klasördeki hata diğerlerini
# durdurmamalı. Hatalar toplanıp sonda özetleniyor.

set -uo pipefail

# Script nerede olursa olsun modül kökünü baz al
MODULE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$MODULE_ROOT" || exit 1

# Renkler (terminal TTY değilse boş bırak — log dosyasına yazarken kirletmesin)
if [[ -t 1 ]]; then
    C_INFO=$'\033[1;34m'; C_OK=$'\033[1;32m'; C_WARN=$'\033[1;33m'
    C_ERR=$'\033[1;31m';  C_RESET=$'\033[0m'
else
    C_INFO=''; C_OK=''; C_WARN=''; C_ERR=''; C_RESET=''
fi

info() { printf '%s[ .. ]%s %s\n' "$C_INFO" "$C_RESET" "$*"; }
ok()   { printf '%s[ OK ]%s %s\n' "$C_OK"   "$C_RESET" "$*"; }
warn() { printf '%s[SKIP]%s %s\n' "$C_WARN" "$C_RESET" "$*"; }
fail() { printf '%s[FAIL]%s %s\n' "$C_ERR"  "$C_RESET" "$*"; }

# Sayaçlar ve başarısızlık listesi
success_count=0
fail_count=0
failed_dirs=()

# --- Ön kontrol: python3 var mı? -------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 bulunamadı — kurulum yapılamaz."
    exit 1
fi
info "Python: $(python3 --version 2>&1) — $(command -v python3)"
echo

# --- Tek bir klasörü kur ----------------------------------------------------
setup_one() {
    local target="$1"   # örn. 01-sensitive-data-in-logs/vulnerable

    printf '%s──────────────────────────────────────────────────────────────%s\n' \
        "$C_INFO" "$C_RESET"
    info "Klasör: $target"

    if [[ ! -d "$target" ]]; then
        fail "$target — klasör yok"
        failed_dirs+=("$target (klasör yok)")
        ((fail_count++))
        return
    fi

    if [[ ! -f "$target/requirements.txt" ]]; then
        fail "$target — requirements.txt yok"
        failed_dirs+=("$target (requirements.txt yok)")
        ((fail_count++))
        return
    fi

    # 1) venv oluştur (varsa atla)
    if [[ -x "$target/venv/bin/pip" ]]; then
        warn "$target — venv zaten var, oluşturma atlandı"
    else
        info "$target — venv oluşturuluyor (python3 -m venv venv)"
        if ! python3 -m venv "$target/venv"; then
            fail "$target — venv oluşturulamadı"
            failed_dirs+=("$target (venv oluşturma hatası)")
            ((fail_count++))
            return
        fi
        ok "$target — venv oluşturuldu"
    fi

    # 2) bağımlılıkları kur
    info "$target — bağımlılıklar kuruluyor (pip install -r requirements.txt)"
    if ! (cd "$target" && ./venv/bin/pip install -r requirements.txt); then
        fail "$target — pip install başarısız"
        failed_dirs+=("$target (pip install hatası)")
        ((fail_count++))
        return
    fi

    ok "$target — kurulum tamamlandı"
    ((success_count++))
}

# --- Senaryo klasörlerini bul ve sırayla kur --------------------------------
# NN-* deseni ile eşleşen senaryo klasörleri; sıralı gitmesi için sort.
scenarios=()
while IFS= read -r d; do
    scenarios+=("$d")
done < <(find . -maxdepth 1 -type d -name '[0-9][0-9]-*' | sed 's|^\./||' | sort)

if [[ ${#scenarios[@]} -eq 0 ]]; then
    fail "Senaryo klasörü bulunamadı ($MODULE_ROOT içinde NN-* yok)."
    exit 1
fi

info "${#scenarios[@]} senaryo bulundu — her biri için vulnerable/ ve fixed/ kurulacak."
echo

for scenario in "${scenarios[@]}"; do
    for variant in vulnerable fixed; do
        setup_one "$scenario/$variant"
    done
done

# --- Özet -------------------------------------------------------------------
total=$((success_count + fail_count))
echo
printf '%s══════════════════════ ÖZET ══════════════════════%s\n' "$C_INFO" "$C_RESET"
printf 'Toplam klasör : %d\n' "$total"
printf '%sBaşarılı      : %d%s\n' "$C_OK" "$success_count" "$C_RESET"
printf '%sBaşarısız     : %d%s\n' "$C_ERR" "$fail_count" "$C_RESET"

if [[ $fail_count -gt 0 ]]; then
    echo
    fail "Başarısız olanlar:"
    for f in "${failed_dirs[@]}"; do
        printf '  - %s\n' "$f"
    done
    exit 1
fi

echo
ok "Tüm venv'ler hazır. Bir uygulamayı çalıştırmak için örnek:"
printf '  cd %s/vulnerable && ./venv/bin/uvicorn main:app --reload --port 8000\n' \
    "${scenarios[0]}"
