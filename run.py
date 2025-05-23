from utils.banner import show_banner
from core.scanner import scan_router
from core.vulnerabilities import parse_nmap_output

def main():
    show_banner()

    print("\n[+] Make sure you're connected to the target Wi-Fi.\n")

    target_ip = input("[?] Enter router IP (default 192.168.1.1): ").strip() or "192.168.1.1"

    print(f"\n[+] Scanning router {target_ip} with Nmap...\n")

    output = scan_router(target_ip)

    print("[+] Raw Nmap Output:\n" + "-" * 50)
    print(output)
    print("-" * 50)

    print("\n[+] Analyzing vulnerabilities...\n")
    vulnerabilities = parse_nmap_output(output)

    if vulnerabilities:
        print("⚠️  Detected Vulnerabilities:")
        print("=" * 50)
        for name, desc in vulnerabilities:
            print(f"[{name}]")
            print(f"  ↳ {desc}\n")
    else:
        print("✅ No known vulnerabilities found in the scanned services.")

if __name__ == "__main__":
    main()
