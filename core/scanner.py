import subprocess

def scan_router(ip):
    try:
        result = subprocess.check_output(['nmap', '-sV', '-Pn', ip], universal_newlines=True)
        return result
    except subprocess.CalledProcessError as e:
        return f"Scan failed: {e}"
