import requests
import json
import whois
import subprocess
import pyfiglet
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import os

# --- KONFIGURATION ---
CVE_API = "https://services.nvd.nist.gov/rest/json/cves/1.0?keyword="


def print_banner():
    banner = pyfiglet.figlet_format("VulnCHK")
    print(banner)


print_banner()


def init_colorama():
    """Initialisiert colorama für farbige Ausgaben."""
    init(autoreset=True)


def print_status(message, color=Fore.WHITE):
    print(f"{color}{message}{Style.RESET_ALL}")


def get_technologies(url):
    """Analysiert die Technologien einer Website."""
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        tech = {}
        # Prüfe auf bekannte CMS-Indikatoren
        if "wp-content" in response.text:
            tech["CMS"] = "WordPress"
        elif "Joomla" in response.text:
            tech["CMS"] = "Joomla"
        # Hier können weitere Erkennungen ergänzt werden.
        server = response.headers.get("Server", "Unbekannt")
        tech["Webserver"] = server
        return tech
    except requests.exceptions.RequestException as e:
        print_status(f"Fehler beim Abrufen der Website: {e}", Fore.RED)
        return None


def check_sql_injection(url):
    """Testet auf SQL-Injection über verschiedene Payloads."""
    payloads = ["' OR 1=1--", "' OR 'a'='a", "'; DROP TABLE users--"]
    error_signatures = [
        "sql syntax", "mysql_fetch", "sql error", "database error",
        "you have an error in your sql syntax", "unterminated", "syntax error"
    ]
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        try:
            response = requests.get(test_url, timeout=5)
            text = response.text.lower()
            if any(sig in text for sig in error_signatures):
                return True
        except requests.exceptions.RequestException as e:
            print_status(f"Fehler beim Testen von SQL-Injection: {e}", Fore.RED)
    return False


def check_xss(url):
    """Testet auf Cross-Site Scripting (XSS) an mehreren gängigen Parametern."""
    payload = "<script>alert('XSS')</script>"
    parameters = ["search", "q", "input"]
    for param in parameters:
        test_url = f"{url}?{param}={payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if payload in response.text:
                return True
        except requests.exceptions.RequestException as e:
            print_status(f"Fehler beim Testen von XSS: {e}", Fore.RED)
    return False


def check_cve(technology):
    """Prüft, ob zu einer Technologie bekannte CVEs existieren."""
    if not technology:
        return []
    try:
        response = requests.get(CVE_API + technology, timeout=5)
        data = response.json()
        cve_list = [item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "Unbekannt")
                    for item in data.get("result", {}).get("CVE_Items", [])]
        return cve_list
    except Exception as e:
        print_status(f"Fehler beim Abrufen der CVE-Daten: {e}", Fore.RED)
        return []


def check_http_headers(url):
    """Prüft auf kritische HTTP-Sicherheitsheader."""
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        missing = []
        critical = {
            "Strict-Transport-Security": "Schützt vor Downgrade-Angriffen",
            "X-Content-Type-Options": "Verhindert MIME-Type-Sniffing",
            "X-Frame-Options": "Schützt vor Clickjacking",
            "X-XSS-Protection": "Schützt vor einfachen XSS-Angriffen"
        }
        for header, desc in critical.items():
            if header not in headers:
                missing.append(f"{header} ({desc})")
        return missing if missing else None
    except requests.exceptions.RequestException as e:
        print_status(f"Fehler beim Überprüfen der HTTP-Header: {e}", Fore.RED)
        return None


def get_contact_info(domain):
    """Liefert Kontaktinformationen via WHOIS."""
    try:
        domain_info = whois.whois(domain)
        emails = domain_info.emails
        return emails if emails else "Keine E-Mail gefunden"
    except Exception as e:
        print_status(f"Fehler beim Abrufen der WHOIS-Daten: {e}", Fore.RED)
        return "Fehler beim Abrufen der WHOIS-Daten"


def run_gobuster(url):
    """Führt einen Gobuster-Scan durch."""
    wordlist_path = "path/to/file/wordlist.txt"
    if not os.path.exists(wordlist_path):
        return "Fehler: Wordlist-Datei nicht gefunden."
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist_path]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return f"Fehler beim Ausführen von Gobuster: {e}"


def generate_report(url, tech, cve, contact, sql_inj, xss, gobuster_results, http_headers_info):
    """Erstellt einen strukturierten Bericht."""
    vulnerabilities = []
    vulnerabilities.append(
        f"{Fore.RED}SQL-Injection: Gefunden{Style.RESET_ALL}" if sql_inj
        else f"{Fore.GREEN}SQL-Injection: Sicher{Style.RESET_ALL}"
    )
    vulnerabilities.append(
        f"{Fore.RED}XSS: Gefunden{Style.RESET_ALL}" if xss
        else f"{Fore.GREEN}XSS: Sicher{Style.RESET_ALL}"
    )
    vulnerabilities.append(
        f"{Fore.RED}Bekannte CVEs: {', '.join(cve)}{Style.RESET_ALL}" if cve
        else f"{Fore.GREEN}Keine bekannten CVEs gefunden{Style.RESET_ALL}"
    )
    if http_headers_info:
        vulnerabilities.append(
            f"{Fore.RED}Fehlende Sicherheitsheader:\n    {', '.join(http_headers_info)}{Style.RESET_ALL}"
        )

    report = f"""{Style.RESET_ALL}[+] Sicherheitsbericht für {url}
########################################################################################################################
Gefundene Technologien:
{json.dumps(tech, indent=2)}

Kontaktinformationen:
{contact}

Sicherheitslücken:"""
    for vuln in vulnerabilities:
        report += f"\n    {vuln}"
    report += f"""

Gobuster-Ergebnisse:
{gobuster_results}

########################################################################################################################
"""
    return report


def main():
    init_colorama()
    website = input("🔍 Gebe eine Website (mit https://) ein: ").strip()

    use_gobuster = input("\nMöchtest du den Gobuster-Scan durchführen? [y/n]: ").strip().lower()
    while use_gobuster not in ["y", "n"]:
        use_gobuster = input("Bitte gib 'y' für Ja oder 'n' für Nein ein: ").strip().lower()

    print_status("[+] Scanne Website...", Fore.YELLOW)
    technologies = get_technologies(website)
    if not technologies:
        print_status("[!] Website nicht erreichbar oder unbekannt.", Fore.RED)
        return

    sql_injection = check_sql_injection(website)
    xss = check_xss(website)
    print_status("[+] Schwachstellen-Check abgeschlossen.", Fore.YELLOW)

    http_headers_info = check_http_headers(website)
    print_status("[+] HTTP-Header-Check abgeschlossen.", Fore.YELLOW)

    gobuster_results = "Gobuster-Scan übersprungen."
    if use_gobuster == "y":
        gobuster_results = run_gobuster(website)
        print_status("[+] Gobuster-Scan abgeschlossen.", Fore.YELLOW)

    domain = website.split("//")[-1].split("/")[0]
    contact = get_contact_info(domain)
    print_status("[+] Kontaktinformationen abgerufen.", Fore.YELLOW)

    # Prüfe CVEs anhand des erkannten CMS, ansonsten des Webservers
    tech_to_check = technologies.get("CMS") or technologies.get("Webserver", "")
    cve = check_cve(tech_to_check)

    report = generate_report(website, technologies, cve, contact, sql_injection, xss, gobuster_results,
                             http_headers_info)
    print_status(report, Fore.WHITE)


if __name__ == "__main__":
    main()
