# eMudhra Intermediate Certs Compromised POC Wi-Fi MITM Server

### __*NOTE: This is a malicious server for educational purposes only. Run only on test networks and devices you control or have permission to.*__

Recently a number of eMudhra intermediate ca's were found to have weak private keys that were brute forced, https://www.openwall.com/lists/oss-security/2026/10/20/1. There were 8 intermediate certs compromised, 6 for TLS. From these 6 certs, they were cross signed by 2 root ca's, leading to 12 possible compromised cert chains. The possible chains are

- Six intermediates →  emSign Root TLS CA - G3 → emSign ECC Root CA - G3
- Six intermediate certificates → AAA Certificate Services

The 3 possible CA's that could lead to a compromised intermediate being verified are
- AAA Certificate Services (SPKI SHA-256: bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3)
- emSign Root TLS CA - G3 (SPKI SHA-256: c619e4780ed8e0abeda24ad732567de4383a7ea941338f6d1a7d1b49ac792fe9)
- emSign ECC Root CA - G3 (SPKI SHA-256: 8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782)

This project is a proxy implementation that can use any of the 12 compromised chains to host a wifi network that will man in the middle all traffic and log it. 
This repository contains a proof-of-concept proxy and Wi-Fi setup for demonstrating interception risks associated with these certificate chains. Do not use it to intercept traffic without explicit authorization.

## Files

>- `verify_bad_certs_chain.sh`: Verifies the certificate chains in `certs/` against the listed trust roots
>- `verify_bad_certs_present.sh`: Verifies the certificate's sha256/spki sha256 against a known list of shas recoreded in `bad_certs.csv`
>- `bad_certs.csv`: A list of known shas of the bad certificates to verify against
>- `server/run.sh`: Main server entry point. Performs all the setup, running, and cleaning up of all required services/files
>- `server/poc_hostapd.conf`: Template hostapd conf
>- `server/poc_dnsmasq.conf`: Template dnsmasq conf
>- `server/poc_squid.conf`: Template squid conf
>- `server/poc_icap.py`: ICAP Server to log all files/response bodies
>- `certs/`: All 12 compromised intermediates, the 3 possible signing CA's, and the weak d values for all 6 certs(12 chains)

## Dependencies

On Ubuntu, install the system packages:

```sh
sudo apt install bash coreutils findutils gawk sed openssl iproute2 iptables util-linux hostapd dnsmasq squid-openssl python3 python3-venv python3-pip
```

You need root access, an AP-capable Wi-Fi adapter, a separate uplink interface, and the `proxy` user/group used by Squid. Squid must support OpenSSL SSL-Bump and ICAP, with `security_file_certgen` installed under `/usr`.

The only third-party Python dependency is `pyicap`; all other Python imports are standard-library modules. It must be importable by the `python3` used **as root**. For example, from this directory:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install pyicap
sudo env PATH="$PWD/.venv/bin:$PATH" ./server/run.sh <options>
```

Alternatively, install `pyicap` for root's Python interpreter and run `sudo ./server/run.sh ...`. A package installed only for your normal user may not be available under `sudo`.

## How it works

```
Usage: $0 -i <interface> -a <ipv4> -s <ssid> -p <password>
    -o <uplink-interface> -c <certsdir> -d <cert-d.csv>
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

Example call:
    sudo env PATH="$PWD/.venv/bin:$PATH" ./server/run.sh -s coolwifibro -p 12345678 -i <wifi interface> -a 192.168.54.1 -o <internet interface> -c certs -f EM_DV_TLS_CA_G3B-AAA.crt -r AAA_CERTIFICATE_SERVICES.crt -d priv_d.csv
```

The wifi subnet is always assumed to be /24. The interface is the gateway at the specified address, but dhcp is hosted from .50-.100, so the address must not collide with that.

Hostapd runs the Wi-Fi AP; dnsmasq provides DHCP/DNS. iptables redirects client TCP/80 and TCP/443 to Squid. Squid uses SSL-Bump with the embedded CA chain and dynamically generated site certificates, then sends HTTP responses to the local pyicap service for response-body capture. Clients need to trust the signing chain by having one of the three signing ca's in their root trust.

Press Ctrl+C to stop. The script stops services, removes its firewall/routing rules, restores the forwarding setting, and asks whether to delete or retain its temporary files. It does not restore the AP interface's former IP addresses. If a crash happens in such a way the script does not cleanup, search all processes for "poc*" to find the hanging processes.

## Artifacts in `$TMP_DIR`

The output directory contains:

| Path | Output |
| --- | --- |
| `poc_hostapd.conf`, `poc_dnsmasq.conf`, `poc_squid.conf` | Rendered configurations. |
| `signing-chain.pem`, `signing-key.pem` | Signing chain and private key. |
| `squid/ssl_db/` | Dynamic certificate database. |
| `squid/access.log`, `squid/cache.log` | Full request log with request/response headers; Squid diagnostics. |
| `squid/terminal.log` | Short request log followed to the terminal. |
| `downloads/<domain>/<timestamp>-<filename>` | Captured nonempty response bodies. |
| `uploads/<domain>/<timestamp>-<filename>` | Captured nonempty request bodies. |
| `dnsmasq.log` | dnsmasq dns and dhcp log |

The terminal shows startup/errors, short Squid request lines, and pyicap's saved-file messages. The access log can contain credentials and cookies; its contents may be readable by other local users. At shutdown, press Enter to delete `$TMP_DIR` or Ctrl+C to keep it.