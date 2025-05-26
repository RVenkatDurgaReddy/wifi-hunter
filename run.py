from utils.banner import show_banner
from core.scanner import list_interfaces, list_wifi_networks
from core.vulnerabilities import scan_ip, interpret_vulnerabilities

def main():
    show_banner()
    interfaces = list_interfaces()
    if not interfaces:
        print("[-] No wireless interfaces found.")
        return

    print("[+] Wireless Interfaces:")
    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")

    selected = input("[?] Choose interface (number): ")
    try:
        iface = interfaces[int(selected) - 1]
    except:
        print("[-] Invalid selection.")
        return

    wifi_list = list_wifi_networks(iface)
    if not wifi_list:
        print("[-] No Wi-Fi networks found.")
    else:
        print("[+] Nearby Wi-Fi networks:")
        for ssid in wifi_list:
            print(f"  - {ssid}")

    connected = input("[?] Are you connected to the target Wi-Fi? (yes/no): ").strip().lower()
    if connected != "yes":
        print("[-] Connect to the target Wi-Fi first. Exiting...")
        return

    ip = input("[?] Enter the target router IP address: ")
    print(f"[+] Scanning {ip}...")
    scan_result = scan_ip(ip)

    print("\n[+] Interpreting vulnerabilities:\n")
    interpretations = interpret_vulnerabilities(scan_result)
    for entry in interpretations:
        print(entry)

if __name__ == "__main__":
    main()
