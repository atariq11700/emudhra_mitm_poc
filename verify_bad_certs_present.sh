#!/usr/bin/env bash

# ==============================================================================
# Filename:         verify_bad_certs_present.sh
# Description:      Verify that the expected compromised certificates are present
# Author:           Adam A https://github.com/atariq11700
# Date Created:     2026-10-29
# License:          AGPL-3.0
# ==============================================================================

set -uo pipefail
CERT_DIR="$1"
CSV="$2"

if [[ ! -f "$CSV" ]]; then
    echo "ERROR: CSV not found: $CSV" >&2
    exit 1
fi

tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT

declare -A expected=()
declare -A found=()
errors=0
line_no=0

while IFS=, read -r subject issuer hash hash_type extra || \
      [[ -n "${subject:-}${issuer:-}${hash:-}${hash_type:-}${extra:-}" ]]; do
    line_no=$((line_no + 1))

    hash=$(printf '%s' "${hash:-}" |
        tr -d '"[:space:]:' | tr '[:upper:]' '[:lower:]')
    hash_type=$(printf '%s' "${hash_type:-}" |
        tr -d '"' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' |
        tr '[:upper:]' '[:lower:]')

    [[ -z "$hash" ]] && continue

    if [[ ! "$hash" =~ ^[0-9a-f]{64}$ ]]; then
        echo "ERROR: Invalid hash on CSV line $line_no: $hash" >&2
        errors=$((errors + 1))
        continue
    fi

    case "$hash_type" in
        "sha256"|"spki sha256")
            key="${hash_type}|${hash}"
            expected["$key"]=1
            ;;
        *)
            echo "ERROR: Invalid hash type on CSV line $line_no: '$hash_type'" >&2
            errors=$((errors + 1))
            ;;
    esac
done < "$CSV"

if ((${#expected[@]} == 0)); then
    echo "ERROR: No valid hash entries found in CSV." >&2
    exit 1
fi

shopt -s nullglob
cd "$CERT_DIR"
certs=(*.crt)

if ((${#certs[@]} == 0)); then
    echo "ERROR: No *.crt files found." >&2
    exit 1
fi

for cert in "${certs[@]}"; do
    # Full certificate SHA-256.
    if ! output=$(openssl x509 -in "$cert" -outform DER 2>/dev/null |
        openssl dgst -sha256 2>/dev/null); then
        echo "ERROR: Cannot calculate certificate SHA-256: $cert"
        errors=$((errors + 1))
        continue
    fi

    cert_sha=$(printf '%s\n' "$output" | awk '{print tolower($NF)}')

    if [[ ! "$cert_sha" =~ ^[0-9a-f]{64}$ ]]; then
        echo "ERROR: Invalid certificate SHA-256: $cert"
        errors=$((errors + 1))
        continue
    fi

    # SPKI SHA-256.
    if ! output=$(openssl x509 -in "$cert" -pubkey -noout 2>/dev/null |
        openssl pkey -pubin -outform DER 2>/dev/null |
        openssl dgst -sha256 2>/dev/null); then
        echo "ERROR: Cannot calculate SPKI SHA-256: $cert"
        errors=$((errors + 1))
        continue
    fi

    spki_sha=$(printf '%s\n' "$output" | awk '{print tolower($NF)}')

    if [[ ! "$spki_sha" =~ ^[0-9a-f]{64}$ ]]; then
        echo "ERROR: Invalid SPKI SHA-256: $cert"
        errors=$((errors + 1))
        continue
    fi

    cert_matched=0

    key="sha256|$cert_sha"
    if [[ ${expected["$key"]+yes} ]]; then
        echo "MATCH (sha256): $cert $cert_sha"
        found["$key"]=1
        cert_matched=1
    fi

    key="spki sha256|$spki_sha"
    if [[ ${expected["$key"]+yes} ]]; then
        echo "MATCH (spki sha256): $cert $spki_sha"
        found["$key"]=1
        cert_matched=1
    fi

    if (( cert_matched == 0 )); then
        echo "NO CSV MATCH: $cert"
        echo "  sha256:      $cert_sha"
        echo "  spki sha256: $spki_sha"
        errors=$((errors + 1))
    fi
done

# Every CSV entry must match a certificate using the specified hash type.
for key in "${!expected[@]}"; do
    if [[ ! ${found["$key"]+yes} ]]; then
        type="${key%%|*}"
        hash="${key#*|}"
        echo "MISSING CERT FILE ($type): $hash"
        errors=$((errors + 1))
    fi
done

if (( errors == 0 )); then
    echo "PASS: All certificates and CSV entries match."
else
    echo "FAIL: $errors issue(s) found."
    exit 1
fi
