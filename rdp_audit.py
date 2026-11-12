#!/usr/bin/env python3
"""RDP-Audit: non-authenticated RDP configuration assessment and evidence collector."""
import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

PROTOCOLS = ('CredSSP (NLA)', 'CredSSP with Early User Auth', 'Native RDP', 'RDSTLS', 'SSL')


def run_nmap(target, port, scripts, timeout, extra=None):
    cmd = ['nmap', '-Pn', '-n', '-sT', '-p', str(port), '--script', ','.join(scripts), '-d1', '--script-timeout', '50s']
    if extra:
        cmd += extra
    cmd += ['--', target]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return {'command': cmd, 'exit_code': p.returncode, 'output': p.stdout + ('\n[STDERR]\n' + p.stderr if p.stderr else ''), 'error': None}
    except subprocess.TimeoutExpired as e:
        return {'command': cmd, 'exit_code': None, 'output': ((e.stdout or b'').decode(errors='replace') if isinstance(e.stdout, bytes) else (e.stdout or '')), 'error': f'Timed out after {timeout}s'}
    except OSError as e:
        return {'command': cmd, 'exit_code': None, 'output': '', 'error': str(e)}


def script_section(output, name):
    # Nmap NSE text section until the next script or the end of port output.
    lines = output.splitlines()
    found = False
    collected = []
    for line in lines:
        if re.match(r'^\|_?\s*' + re.escape(name) + r':', line):
            found = True
            collected.append(line)
            continue
        if found:
            if line.startswith('|'):
                if re.match(r'^\|(?:_| )[a-z][a-z0-9_-]*:', line):
                    break
                collected.append(line)
            else:
                break
    return '\n'.join(collected)


def nla_result(output):
    section = script_section(output, 'rdp-enum-encryption')
    modes = {}
    for mode in PROTOCOLS:
        m = re.search(r'^\|[_ ]*' + re.escape(mode) + r':\s*(SUCCESS|FAILED(?:\s*\([^\n)]*\))?)', section, re.M)
        modes[mode] = m.group(1) if m else None
    # SSL success = acceptance of the TLS-only, non-CredSSP security mode.
    # Native RDP success is another non-CredSSP path.
    if modes['SSL'] == 'SUCCESS' or modes['Native RDP'] == 'SUCCESS':
        return 'NOT_ENFORCED', 'Server accepted a non-CredSSP RDP security negotiation (SSL or Native RDP).', modes
    if not section:
        return 'INCONCLUSIVE', 'RDP encryption enumeration returned no usable script output.', modes
    nla_supported = modes['CredSSP (NLA)'] == 'SUCCESS' or modes['CredSSP with Early User Auth'] == 'SUCCESS'
    # Rejecting non-NLA negotiation explicitly with HYBRID_REQUIRED is strong evidence,
    # whereas an unexplained failure or omitted mode is not proof.
    ssl_reject = modes['SSL'] == 'FAILED (HYBRID_REQUIRED_BY_SERVER)'
    native_reject = modes['Native RDP'] == 'FAILED (HYBRID_REQUIRED_BY_SERVER)'
    if nla_supported and ssl_reject and native_reject:
        return 'ENFORCED', 'CredSSP supported; both non-CredSSP modes explicitly rejected as HYBRID_REQUIRED_BY_SERVER.', modes
    return 'INCONCLUSIVE', 'NLA support detected, but non-NLA modes were not conclusively accepted or rejected.', modes


def tls_findings(section):
    found = []
    if not section:
        return found, ['TLS enumeration unavailable or unsupported on this target.']
    versions = sorted(set(re.findall(r'\b(?:SSLv3|TLSv1\.[0-3]|TLSv1\.0|TLSv1)\s*:', section)))
    old = [v for v in versions if v in ('SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1')]
    if old:
        found.append({'id': 'LEGACY_TLS', 'title': 'Legacy TLS/SSL versions accepted', 'evidence': old, 'confidence': 'confirmed protocol acceptance'})
    cipher_lines = [line.strip(' |_') for line in section.splitlines() if re.search(r'\b(?:TLS_|SSL_)[A-Z0-9_]+\s*\(', line)]
    weak_cipher_lines = [line for line in cipher_lines if any(x in line for x in ('_RC4_', '_3DES_', '_DES_', '_NULL_', '_EXPORT_', '_anon_', '_MD5'))]
    if weak_cipher_lines:
        found.append({'id': 'WEAK_TLS_CIPHER', 'title': 'Weak TLS ciphers accepted', 'evidence': weak_cipher_lines, 'confidence': 'confirmed cipher acceptance'})
    return found, ([] if versions else ['TLS protocol versions could not be parsed from enumeration.'])


def legacy_rdp_finding(section):
    # This output represents legacy *RDP encryption options*, not TLS cipher suites.
    # When Native RDP is disabled, do not report old RC4 choices as exploitable.
    if 'Native RDP: SUCCESS' not in section:
        return []
    matches = re.findall(r'^\|[_ ]*(40-bit RC4|56-bit RC4): SUCCESS', section, re.M)
    if matches:
        return [{'id': 'LEGACY_RDP_ENCRYPTION', 'title': 'Weak native RDP encryption accepted', 'evidence': matches, 'confidence': 'confirmed protocol negotiation'}]
    return []


def port_open(output, port):
    match = re.search(r'^' + re.escape(str(port)) + r'/tcp\s+(open|closed|filtered|open\|filtered)\b', output, re.M)
    return match.group(1) if match else 'unknown'


def main():
    ap = argparse.ArgumentParser(description='RDP configuration/NLA assessment with saved PoC evidence')
    ap.add_argument('target', help='One authorized IP address or hostname')
    ap.add_argument('--port', type=int, default=3389)
    ap.add_argument('--deep-tls', action='store_true', help='Enumerate accepted TLS ciphers (many connections; more intrusive)')
    ap.add_argument('--screenshot', type=Path, help='Existing FreeRDP screenshot to attach to the evidence folder')
    ap.add_argument('--out', type=Path, default=Path('rdp_audit_results'))
    ap.add_argument('--timeout', type=int, default=150)
    args = ap.parse_args()
    if not 1 <= args.port <= 65535:
        ap.error('Port must be between 1 and 65535')
    if not shutil.which('nmap'):
        sys.exit('ERROR: nmap is required. Install with: sudo apt install nmap')
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', args.target)[:100]
    out = args.out / f'{safe}_{args.port}_{stamp}'
    out.mkdir(parents=True, exist_ok=False)
    print(f'[+] RDP-Audit: {args.target}:{args.port}')
    print('[+] Checking RDP security negotiation and non-authenticated metadata...')
    basic = run_nmap(args.target, args.port,
                     ['rdp-enum-encryption', 'rdp-ntlm-info', 'ssl-cert'], args.timeout)
    (out / 'nmap_basic.txt').write_text(basic['output'], encoding='utf-8')
    status = port_open(basic['output'], args.port)
    verdict, why, modes = nla_result(basic['output']) if status == 'open' and basic['exit_code'] == 0 else ('INCONCLUSIVE', 'Port not confirmed open or Nmap failed.', {})
    security_section = script_section(basic['output'], 'rdp-enum-encryption')
    findings = legacy_rdp_finding(security_section)
    limitations = []
    if basic['error'] or basic['exit_code'] != 0:
        limitations.append('Basic scan failed or timed out; see raw evidence.')
    deep = None
    if args.deep_tls and status == 'open':
        print('[+] Enumerating TLS versions and ciphers (noisy scan)...')
        deep = run_nmap(args.target, args.port, ['ssl-enum-ciphers'], max(args.timeout, 240))
        (out / 'nmap_tls.txt').write_text(deep['output'], encoding='utf-8')
        if deep['exit_code'] == 0:
            more, notices = tls_findings(script_section(deep['output'], 'ssl-enum-ciphers'))
            findings.extend(more)
            limitations.extend(notices)
        else:
            limitations.append('TLS cipher scan failed; no TLS cipher conclusions drawn.')
    else:
        limitations.append('TLS cipher enumeration not run; add --deep-tls to enable.')
    if verdict == 'NOT_ENFORCED':
        findings.insert(0, {'id': 'NLA_NOT_ENFORCED', 'title': 'RDP Network Level Authentication not enforced', 'evidence': [why], 'confidence': 'confirmed protocol negotiation, not an authenticated session'})
    if args.screenshot:
        if not args.screenshot.is_file():
            sys.exit(f'ERROR: Screenshot not found: {args.screenshot}')
        screenshot_dest = out / ('screenshot' + args.screenshot.suffix.lower())
        shutil.copy2(args.screenshot, screenshot_dest)
    report = {
        'tool': 'RDP-Audit', 'timestamp_utc': stamp, 'target': args.target, 'port': args.port,
        'port_state': status, 'nla_verdict': verdict, 'nla_reason': why, 'security_modes': modes,
        'findings': findings, 'limitations': limitations,
        'certificate': 'See nmap_basic.txt ssl-cert section; no automatic certificate-trust claim is made.',
        'identity_metadata': 'See nmap_basic.txt rdp-ntlm-info section; metadata is not proof of OS patch status.',
        'raw_files': ['nmap_basic.txt'] + (['nmap_tls.txt'] if deep else []),
        'scope_note': 'No credentials, brute force, exploit attempts, or successful logon tests performed.'
    }
    (out / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    summary = [f'# RDP Audit PoC: {args.target}:{args.port}', '', f'- Timestamp (UTC): {stamp}',
               f'- RDP port: {status}', f'- **NLA: {verdict.replace("_", " ")}**', f'- Basis: {why}', '',
               '## RDP negotiation modes']
    summary += [f'- {name}: {value or "NOT OBSERVED"}' for name, value in modes.items()]
    summary += ['', '## Findings']
    summary += [f'- **{f["title"]}** ({f["confidence"]}): {", ".join(map(str, f["evidence"]))}' for f in findings] or ['- None confirmed by enabled checks.']
    summary += ['', '## Limitations'] + [f'- {x}' for x in limitations]
    summary += ['', '## Evidence', '- nmap_basic.txt: full command output', '- report.json: structured results']
    if deep:
        summary.append('- nmap_tls.txt: TLS cipher output')
    if args.screenshot:
        summary.append(f'- {screenshot_dest.name}: user-supplied FreeRDP screen evidence')
    summary += ['', 'No authentication attempted. NLA verdict reflects server protocol negotiation, not a completed authenticated desktop session.']
    (out / 'POC.md').write_text('\n'.join(summary) + '\n', encoding='utf-8')
    digests = []
    for p in sorted(out.iterdir()):
        if p.is_file():
            digests.append(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}')
    (out / 'SHA256SUMS.txt').write_text('\n'.join(digests) + '\n', encoding='utf-8')
    print(f'\nRDP PORT : {status.upper()}')
    print(f'NLA      : {verdict.replace("_", " ")}')
    print(f'REASON   : {why}')
    print(f'FINDINGS : {len(findings)} confirmed by enabled checks')
    print(f'POC      : {out / "POC.md"}')
    print(f'RAW      : {out / "nmap_basic.txt"}')
    if limitations:
        print('NOTES    : ' + '; '.join(limitations))


if __name__ == '__main__':
    main()
