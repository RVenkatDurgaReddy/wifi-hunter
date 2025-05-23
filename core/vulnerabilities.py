import re

# Dictionary of known Wi-Fi vulnerabilities and detections
vuln_db = {
    "sslv2": "❌ SSLv2 protocol detected — insecure, should be disabled.",
    "sslv3": "❌ SSLv3 protocol detected — outdated and vulnerable.",
    "tlsv1.0": "⚠️ TLS 1.0 detected — considered insecure; upgrade to TLS 1.2 or higher.",
    "weak-ciphers": "❌ Weak encryption ciphers enabled, making your connection vulnerable.",
    "self-signed": "⚠️ Self-signed SSL certificate found — may not be fully trusted or secure.",
    "boa httpd": "⚠️ Router runs Boa HTTP Server — outdated and may have security flaws.",
    "apache httpd": "ℹ️ Router uses Apache HTTP Server — ensure it is up to date.",
    "nginx": "ℹ️ Router uses nginx server — check it's not outdated.",
    "dnsmasq": "⚠️ dnsmasq DNS server detected — older versions have vulnerabilities.",
    "bind": "⚠️ BIND DNS server detected — check for known vulnerabilities.",
    "ftp": "❌ FTP port open — if anonymous/default credentials allowed, this is risky.",
    "telnet": "❌ Telnet service detected — insecure and should be disabled.",
    "ssh": "ℹ️ SSH service detected — ensure strong authentication is configured.",
    "upnp": "⚠️ UPnP service detected — may expose device to external attacks.",
    "snmp": "⚠️ SNMP service detected — verify community strings and access control.",
    "wep": "❌ WEP encryption detected — very insecure, upgrade to WPA2/WPA3 immediately.",
    "wpa1": "⚠️ WPA1 encryption detected — considered insecure, upgrade recommended.",
    "default password": "❌ Default or weak credentials detected — change immediately.",
    "traceroute": "ℹ️ Traceroute enabled — can reveal internal network information.",
}

# Parser that checks the Nmap output against the dictionary
def parse_nmap_output(output):
    findings = []

    checks = {
        "sslv2": r"sslv2",
        "sslv3": r"sslv3",
        "tlsv1.0": r"tlsv1\.0",
        "weak-ciphers": r"weak ciphers|CBC|RC4|DES",
        "self-signed": r"Self-signed|commonName=.*?/organizationName=.*?",
        "boa httpd": r"Boa HTTPd",
        "apache httpd": r"Apache.*http",
        "nginx": r"nginx",
        "dnsmasq": r"dnsmasq",
        "bind": r"BIND",
        "ftp": r"\b21/tcp\s+open",
        "telnet": r"\b23/tcp\s+open",
        "ssh": r"\b22/tcp\s+open",
        "upnp": r"upnp|1900/udp",
        "snmp": r"snmp|161/udp",
        "wep": r"Encryption key:on.+WEP",
        "wpa1": r"WPA Version 1",
        "default password": r"default credentials|admin:admin|user:user|password:password",
        "traceroute": r"TRACEROUTE",
    }

    for key, pattern in checks.items():
        if re.search(pattern, output, re.IGNORECASE):
            findings.append((key, vuln_db[key]))

    return findings
