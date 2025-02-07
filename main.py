import requests
import json
import whois
import subprocess
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import os

# --- KONFIGURATION ---
CVE_API = "https://services.nvd.nist.gov/rest/json/cves/1.0?keyword="


# --- FUNKTIONEN ---

def init_colorama():
    """Initialisiert die colorama-Bibliothek für farbige Ausgabe im Terminal."""
    init(autoreset=True)


def print_status(message, color=Fore.WHITE):
    """Gibt Statusmeldungen in gewünschter Farbe aus."""
    print(f"{color}{message}{Style.RESET_ALL}")

def get_technologies(url):
    """Analysiert die Technologien einer Website."""
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(response.text, "html.parser")

        tech = {}
        if "wp-content" in response.text:
            tech["CMS"] = "WordPress"
        elif "Joomla" in response.text:
            tech["CMS"] = "Joomla"

        server = response.headers.get("Server", "Unbekannt")
        tech["Webserver"] = server

        return tech
    except requests.exceptions.RequestException:
        return None


def check_sql_injection(url):
    """Testet auf SQL-Injection mit verbesserten Erkennungsmerkmalen."""
    payloads = ["' OR 1=1--", "' OR 'a'='a", "'; DROP TABLE users--"]
    error_signatures = ["sql syntax", "mysql_fetch", "sql error", "database error",
                        "you have an error in your sql syntax"]

    for payload in payloads:
        test_url = f"{url}?id={payload}"
        response = requests.get(test_url, timeout=5)
        response_text = response.text.lower()

        if any(err in response_text for err in error_signatures):
            return True
    return False


def check_xss(url):
    """Testet auf Cross-Site Scripting (XSS)."""
    payload = "<script>alert('XSS')</script>"
    test_url = f"{url}?search={payload}"
    response = requests.get(test_url, timeout=5)
    return payload in response.text


def check_cve(technology):
    """Prüft, ob für eine Technologie bekannte Schwachstellen existieren."""
    try:
        response = requests.get(CVE_API + technology, timeout=5)
        data = response.json()
        cve_list = [item["cve"]["CVE_data_meta"]["ID"] for item in data.get("result", {}).get("CVE_Items", [])]
        return cve_list
    except:
        return []


def check_http_headers(url):
    """Prüft auf kritische HTTP-Sicherheitsheader."""
    response = requests.get(url, timeout=5)
    headers = response.headers
    missing_headers = []

    critical_headers = {
        "Strict-Transport-Security": "Schützt vor Downgrade-Angriffen",
        "X-Content-Type-Options": "Verhindert MIME-Type-Sniffing",
        "X-Frame-Options": "Schützt vor Clickjacking",
        "X-XSS-Protection": "Schützt vor einfachen XSS-Angriffen"
    }

    for header, desc in critical_headers.items():
        if header not in headers:
            missing_headers.append(f"{header} ({desc})")

    return missing_headers if missing_headers else None


def get_contact_info(domain):
    """Findet Kontaktinfos über WHOIS."""
    try:
        domain_info = whois.whois(domain)
        return domain_info.emails if domain_info.emails else "Keine E-Mail gefunden"
    except:
        return "Fehler beim Abrufen der WHOIS-Daten"


def run_gobuster(url):
    """Führt einen Gobuster-Scan durch."""
    wordlist_path = "C:/Users/marsg/PycharmProjects/OBSINT-Test1/.venv/wordlist.txt"
    if not os.path.exists(wordlist_path):
        return "Fehler: Wordlist-Datei nicht gefunden."

    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist_path]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return f"Fehler beim Ausführen von Gobuster: {str(e)}"


def generate_report(url, tech, cve, contact, sql_injection, xss, gobuster_results, http_headers_info):
    """Erstellt einen strukturierten Bericht."""
    vulnerabilities = []

    # Sicherheitslücken farblich hervorheben
    vulnerabilities.append(
        f"{Fore.RED}SQL-Injection: Gefunden{Style.RESET_ALL}" if sql_injection else f"{Fore.GREEN}SQL-Injection: Sicher{Style.RESET_ALL}")
    vulnerabilities.append(
        f"{Fore.RED}XSS: Gefunden{Style.RESET_ALL}" if xss else f"{Fore.GREEN}XSS: Sicher{Style.RESET_ALL}")
    vulnerabilities.append(
        f"{Fore.RED}Bekannte CVEs: {', '.join(cve)}{Style.RESET_ALL}" if cve else f"{Fore.GREEN}Keine bekannten CVEs gefunden{Style.RESET_ALL}")

    if http_headers_info:
        vulnerabilities.append(
            f"{Fore.RED}Fehlende Sicherheitsheader:\n    {', '.join(http_headers_info)}{Style.RESET_ALL}")

    report = f"""{Style.RESET_ALL}[+] Sicherheitsbericht für {url}
############################################################
    Gefundene Technologien:
    {json.dumps(tech, indent=2)}

    Kontaktinformationen:
    {contact}

    Sicherheitslücken:"""

    for vulnerability in vulnerabilities:
        report += f"\n    {vulnerability}"

    # Gobuster-Ergebnisse ans Ende setzen
    report += f"""

    Gobuster-Ergebnisse:
{gobuster_results}

############################################################
"""
    return report


# --- HAUPTLAUF ---

def main():
    init_colorama()

    website = input("🔍 Geben Sie eine Website (mit https://) ein: ").strip()

    print_status("[+] Scanne Website...", Fore.YELLOW)
    technologies = get_technologies(website)
    if not technologies:
        print_status("[!] Website nicht erreichbar oder unbekannt.", Fore.RED)
        return

    sql_injection = check_sql_injection(website)
    xss = check_xss(website)
    print_status("[+] Schwachstellen-Check abgeschlossen.", Fore.YELLOW)

    http_headers_info = check_http_headers(website)
    print_status("[+] HTTP Header-Check abgeschlossen.", Fore.YELLOW)

    gobuster_results = run_gobuster(website)
    print_status("[+] Gobuster-Scan abgeschlossen.", Fore.YELLOW)

    domain = website.split("//")[-1].split("/")[0]
    contact = get_contact_info(domain)
    print_status("[+] Kontaktinformationen abgerufen.", Fore.YELLOW)

    report = generate_report(website, technologies,
                             check_cve(technologies.get("CMS", technologies.get("Webserver", ""))), contact,
                             sql_injection, xss, gobuster_results, http_headers_info)
    print_status(report, Fore.WHITE)


if __name__ == "__main__":
    main()
