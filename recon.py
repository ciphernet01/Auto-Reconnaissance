import os
import subprocess
import socket
import whois
import requests
import dns.resolver

def is_host_up(ip):
    response = os.system(f"ping -n 1 {ip}" if os.name == "nt" else f"ping -c 1 {ip}")
    return response == 0

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        print(f"\n[WHOIS Info for {domain}]\n{w}")
    except Exception as e:
        print(f"[!] WHOIS lookup failed: {e}")

def run_nmap_scan(ip):
    print(f"\n[Running Nmap Scan on {ip}]")
    try:
        output = subprocess.check_output(["nmap", "-Pn", "-sS", "-T4", "-F", ip], text=True)
        print(output)
    except Exception as e:
        print(f"[!] Nmap failed: {e}")

def subdomain_enum(domain):
    print(f"\n[Enumerating Subdomains for {domain}]")
    common_subs = ['www', 'mail', 'ftp', 'test', 'dev', 'admin', 'webmail']
    for sub in common_subs:
        subdomain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            print(f"Found: {subdomain} -> {ip}")
        except socket.gaierror:
            pass

def get_headers(url):
    print(f"\n[Fetching Headers for {url}]")
    try:
        resp = requests.get(url, timeout=5)
        print(resp.headers)
    except Exception as e:
        print(f"[!] Failed to get headers: {e}")

def main():
    target = input("Enter target domain or IP: ").strip()
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[!] Cannot resolve domain.")
        return

    print(f"\n[*] Target Resolved: {target} -> {ip}")
    
    if is_host_up(ip):
        print(f"[+] Host {ip} is up")
    else:
        print(f"[!] Host {ip} seems down")
        return

    if not target.replace('.', '').isdigit():
        whois_lookup(target)
        subdomain_enum(target)
        get_headers(f"http://{target}")

    run_nmap_scan(ip)

if __name__ == "__main__":
    main()
