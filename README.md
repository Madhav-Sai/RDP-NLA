# RDP-Audit

Single-target RDP configuration / NLA enforcement checker for authorized VAPT.

## Setup

```bash
sudo apt update && sudo apt install -y nmap python3
```

## Usage

```bash
python3 rdp_audit.py 10.9.9.68
python3 rdp_audit.py 10.9.9.68 --deep-tls
python3 rdp_audit.py 10.9.9.68 --deep-tls --screenshot ./freerdp-poc.png
python3 rdp_audit.py example.internal --port 3390
```

Results are stored in `rdp_audit_results/<target>_<port>_<UTC timestamp>/`.

### Included checks

- Reachability of target TCP RDP port
- CredSSP/NLA, early user auth, TLS-only, native RDP, RDSTLS negotiation
- Enforcement verdict: `ENFORCED`, `NOT_ENFORCED`, `INCONCLUSIVE`
- Weak native-RDP RC4 modes (only when native mode is accepted)
- TLS versions and weak cipher-suite acceptance (with `--deep-tls`)
- SSL certificate collection via Nmap `ssl-cert`, when supported
- Anonymous NTLM endpoint information via `rdp-ntlm-info`, when available
- Dated Markdown PoC, JSON data, raw command output, SHA-256 checksums, optional copied screenshot

### Interpretation and false-positive controls

- `CredSSP (NLA): SUCCESS` proves support, **not enforcement**.
- `SSL: SUCCESS` or `Native RDP: SUCCESS` shows a non-CredSSP security path accepted during RDP negotiation, hence `NOT_ENFORCED`.
- `ENFORCED` requires both non-CredSSP modes to be explicitly rejected with `HYBRID_REQUIRED_BY_SERVER` and CredSSP to succeed.
- Missing output, timeouts, or other rejection codes produce `INCONCLUSIVE`.
- SSL certificate information is collected but **not automatically labelled insecure**: Windows RDP certificates may be intentionally internal/self-signed, and trusted roots differ by client.
- Cipher checks are optional because Nmap's `ssl-enum-ciphers` script performs many connections and is marked intrusive.
- This tool does not validate Windows patch levels or automatically declare BlueKeep, CredSSP CVEs, or other RDP vulnerabilities.
- Nmap's default `rdp-enum-encryption` runs without failed methods, so this tool runs Nmap with `-d1` for the decisive failure codes.
- RDP negotiation does not imply successful login or bypass of authentication.

Run only against systems where you are authorized to assess RDP.
