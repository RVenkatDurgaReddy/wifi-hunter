import subprocess

def list_interfaces():
    try:
        result = subprocess.check_output("nmcli device status", shell=True).decode()
        interfaces = []
        for line in result.splitlines()[1:]:
            if "wifi" in line or "wlan" in line or "wlx" in line:
                iface = line.split()[0]
                interfaces.append(iface)
        return interfaces
    except Exception as e:
        print(f"[-] Error listing interfaces: {e}")
        return []

def list_wifi_networks(interface):
    try:
        subprocess.run(f"nmcli device wifi rescan ifname {interface}", shell=True)
        result = subprocess.check_output(f"nmcli -t -f SSID device wifi list ifname {interface}", shell=True).decode()
        ssids = list(set(filter(None, result.strip().split('\n'))))
        return ssids
    except Exception as e:
        print(f"[-] Error scanning networks: {e}")
        return []
