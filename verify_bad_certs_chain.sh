#!/usr/bin/env bash

# ==============================================================================
# Filename:         verify_bad_certs_chain.sh
# Description:      Verify that the comrpomised intermediates verify as expected
# Author:           Adam A https://github.com/atariq11700
# Date Created:     2026-10-29
# License:          AGPL-3.0
# ==============================================================================

shopt -s nullglob

cd $1
certs=(EM*.crt)

if ((${#certs[@]} == 0)); then
    echo "No EM*.crt files found."
    exit 1
fi

aaa_root="AAA_CERTIFICATE_SERVICES.crt"
emsign_ecc_root="emSign_ECC_ROOT_CA-G3.crt"
emsign_tls_root="emSign_ROOT_TLS_CA-G3.crt"

# Colors (automatically disabled when output is redirected)
if [[ -t 1 ]]; then
    GREEN=$'\033[32m'
    RED=$'\033[31m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
else
    GREEN=""
    RED=""
    BOLD=""
    RESET=""
fi

pass() { printf '%sPASS%s' "$GREEN" "$RESET"; }
fail() { printf '%sFAIL%s' "$RED" "$RESET"; }

printf '\n'
printf '%s%-42s  %-10s  %-10s%s\n' \
    "$BOLD" "CERTIFICATE" "AAA ROOT" "emSign ROOTS" "$RESET"
printf '%-42s  %-10s  %-10s\n' \
    "------------------------------------------" "----------" "----------"

aaa_pass=0
aaa_fail=0
emsign_pass=0
emsign_fail=0

for f in "${certs[@]}"; do
    # Verify against AAA root
    if openssl verify -CAfile "$aaa_root" "$f" >/dev/null 2>&1; then
        aaa_status="pass"
        aaa_pass=$((aaa_pass + 1))
    else
        aaa_status="fail"
        aaa_fail=$((aaa_fail + 1))
    fi

    # Verify against emSign roots
    if openssl verify \
        -CAfile "$emsign_ecc_root" \
        -untrusted "$emsign_tls_root" \
        "$f" >/dev/null 2>&1; then
        emsign_status="pass"
        emsign_pass=$((emsign_pass + 1))
    else
        emsign_status="fail"
        emsign_fail=$((emsign_fail + 1))
    fi

    printf '%-42s  ' "$f"

    if [[ "$aaa_status" == "pass" ]]; then
        printf '%-19s' "$(pass)"
    else
        printf '%-19s' "$(fail)"
    fi

    if [[ "$emsign_status" == "pass" ]]; then
        printf '%s\n' "$(pass)"
    else
        printf '%s\n' "$(fail)"
    fi
done

printf '%-42s  %-10s  %-10s\n' \
    "------------------------------------------" "----------" "----------"

printf '%-42s  %s%2d pass%s / %s%2d fail%s  %s%2d pass%s / %s%2d fail%s\n' \
    "TOTAL" \
    "$GREEN" "$aaa_pass" "$RESET" "$RED" "$aaa_fail" "$RESET" \
    "$GREEN" "$emsign_pass" "$RESET" "$RED" "$emsign_fail" "$RESET"

printf '\n'
