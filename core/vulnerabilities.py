import subprocess

def scan_ip(ip):
    try:
        result = subprocess.check_output(f"nmap -sV {ip}", shell=True).decode()
        print(result)
        return result
    except Exception as e:
        print(f"[-] Nmap scan failed: {e}")
        return ""

def interpret_vulnerabilities(scan_text):
    checks = {
        "sslv2": "❌ SSLv2 protocol detected — insecure, should be disabled.",
        "sslv3": "❌ SSLv3 protocol detected — outdated and vulnerable.",
        "tlsv1.0": "⚠️ TLS 1.0 detected — upgrade to TLS 1.2 or higher.",
        "tlsv1.1": "⚠️ TLS 1.1 detected — also considered insecure.",
        "weak-ciphers": "❌ Weak encryption ciphers enabled — easily cracked.",
        "self-signed": "⚠️ Self-signed SSL certificate — not trusted by browsers.",
        "boa": "❌ Boa HTTP server detected — outdated and vulnerable.",
        "apache": "ℹ️ Apache server found — ensure it's updated.",
        "nginx": "ℹ️ nginx server — check version for vulnerabilities.",
        "dnsmasq": "⚠️ dnsmasq found — older versions are vulnerable to DNS attacks.",
        "bind": "⚠️ BIND DNS server — check CVEs for known issues.",
        "ftp": "❌ FTP open — risky if anonymous/default credentials allowed.",
        "telnet": "❌ Telnet open — unencrypted, should be disabled.",
        "ssh": "ℹ️ SSH found — use strong passwords and key authentication.",
        "upnp": "⚠️ UPnP found — can expose internal services to internet.",
        "snmp": "⚠️ SNMP enabled — check default community strings.",
        "wep": "❌ WEP encryption used — crackable within minutes.",
        "wpa1": "⚠️ WPA1 in use — upgrade to WPA2/WPA3.",
        "default password": "❌ Default credentials detected — change immediately.",
        "traceroute": "ℹ️ Traceroute enabled — can leak internal network info.",
        "open port 23": "❌ Telnet port 23 open — insecure, should be disabled.",
        "open port 21": "❌ FTP port 21 open — should be closed unless needed.",
        "open port 80": "ℹ️ Web server running on port 80 — check for vulnerabilities.",
        "open port 443": "ℹ️ HTTPS enabled — ensure SSL/TLS is strong.",
        "open port 53": "ℹ️ DNS service running — check for DNS hijacking risks.",
        "open port 1900": "⚠️ UPnP service on port 1900 — check if exposed to WAN.",
    }

    scan_lower = scan_text.lower()
    findings = []
    for pattern, explanation in checks.items():
        if pattern in scan_lower:
            findings.append(explanation)
    if not findings:
        findings.append("✅ No obvious vulnerabilities found. Perform manual analysis for deeper issues.")
    return findings
