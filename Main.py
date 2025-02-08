import requests
import json
import whois
import subprocess
import pyfiglet
from requests.utils import quote
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore, Style, init
import os

# --- KONFIGURATION ---
CVE_API = "https://services.nvd.nist.gov/rest/json/cves/1.0?keyword="


def print_banner():
    banner = pyfiglet.figlet_format("VulnCHK")
    print(banner)


print_banner()


def init_colorama():
    init(autoreset=True)


def print_status(message, color=Fore.WHITE):
    print(f"{color}{message}{Style.RESET_ALL}")


def get_technologies(url):
    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        tech = {}
        if "wp-content" in response.text:
            tech["CMS"] = "WordPress"
        elif "Joomla" in response.text:
            tech["CMS"] = "Joomla"
        server = response.headers.get("Server", "Unknown")
        tech["Webserver"] = server
        return tech
    except requests.exceptions.RequestException as e:
        print_status(f"[X] Error retrieving the website: {e}", Fore.RED)
        return None


def check_sql_injection(url):
    payloads = [
        "' OR 1=1--", "' OR 'a'='a", "' UNION SELECT NULL--",
        "' UNION SELECT 1,2,3--", "' AND SLEEP(5)--", "' OR 'x'='x'--"
    ]
    error_signatures = [
        "sql syntax", "mysql_fetch", "database error",
        "you have an error in your sql syntax", "syntax error",
        "unterminated", "warning: pg_query()", "fatal error"
    ]
    for payload in payloads:
        test_url = f"{url}?id={quote(payload)}"
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 500 or any(sig in response.text.lower() for sig in error_signatures):
                return True
        except requests.exceptions.RequestException:
            pass
    return False


def check_xss(url):
    payloads = [
        "<script>alert('XSS')</script>",
        "\" onmouseover=alert('XSS') \"",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert('XSS')>"
    ]

    try:
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        if response.status_code != 200:
            print_status(f"[X] Error retrieving the website({response.status_code})", Fore.RED)
            return False

        soup = BeautifulSoup(response.text, "html.parser")

        input_fields = [tag.get("name") for tag in soup.find_all("input") if tag.get("name")]
        forms = soup.find_all("form")

        if not input_fields and not forms:
            print_status("[+] No input fields or forms found.", Fore.YELLOW)

        vulnerable = False

        for param in input_fields:
            for payload in payloads:
                test_url = f"{url}?{param}={payload}"
                response = requests.get(test_url, timeout=5)
                if payload in response.text:
                    print_status(f"[!] XSS found via parameter: {param}", Fore.RED)
                    vulnerable = True

        for form in forms:
            action = urljoin(url, form.get("action", "/"))
            method = form.get("method", "get").lower()
            inputs = {tag.get("name", ""): payload for tag in form.find_all("input") if tag.get("name")}

            if method == "post":
                response = requests.post(action, data=inputs, timeout=5)
            else:
                response = requests.get(action, params=inputs, timeout=5)

            if payload in response.text:
                print_status(f"[!] XSS found via form with action: {action}", Fore.LIGHTRED_EX)
                vulnerable = True

        return vulnerable

    except requests.exceptions.RequestException as e:
        print_status(f"[X] Error when testing XSS: {e}", Fore.RED)
        return False


def check_cve(technology, version=""):
    query = quote(technology)
    if version:
        query += f"%20{quote(version)}"

    query_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keyword={query}"
    try:
        response = requests.get(query_url, timeout=5)
        if response.status_code != 200:
            return []

        data = response.json()
        cve_list = [
            item["cve"]["id"]
            for item in data.get("vulnerabilities", [])
        ]
        return cve_list
    except (requests.exceptions.RequestException, json.JSONDecodeError):
        return []


def check_http_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        issues = []

        header_checks = {
            "\n - Strict-Transport-Security": "Missing HSTS header",
            "\n - X-Content-Type-Options": "Missing X-Content-Type-Options",
            "\n - X-Frame-Options": "Missing X-Frame-Options",
            "\n - X-XSS-Protection": "Missing X-XSS-Protection",
            "\n - Content-Security-Policy": "Missing Content-Security-Policy",
            "\n - Referrer-Policy": "Missing Referrer-Policy"
        }

        for header, warning in header_checks.items():
            if header not in headers:
                issues.append(f"{header}: {warning}")

        return issues if issues else None
    except requests.exceptions.RequestException as e:
        print_status(f"[X] Error when checking the HTTP headers: {e}", Fore.RED)
        return None


def get_contact_info(domain):
    try:
        domain_info = whois.whois(domain)
        emails = domain_info.emails
        return emails if emails else "No e-mail found"
    except Exception as e:
        print_status(f"[X] Fehler beim Abrufen der WHOIS-Daten: {e}", Fore.RED)
        return "[X] Fehler beim Abrufen der WHOIS-Daten"


def run_gobuster(url):
    """Führt einen Gobuster-Scan durch."""
    wordlist_path = "path/to/File/Wordlist.txt"
    if not os.path.exists(wordlist_path):
        return print_status("[X] Error Wordlist file not found.", Fore.RED)

    # Prüfe, ob Gobuster installiert ist
    try:
        subprocess.run(["gobuster", "--version"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        return print_status("[X] Error Gobuster is not installed.", Fore.RED)

    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist_path]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return print_status("[X] Error when running Gobuster: {e}", Fore.RED)


def generate_report(url, tech, cve, contact, sql_inj, xss, gobuster_results, http_headers_info):
    vulnerabilities = []
    vulnerabilities.append(
        f"{Fore.RED}SQL-Injection: Found{Style.RESET_ALL}" if sql_inj
        else f"{Fore.GREEN}SQL-Injection: Safe{Style.RESET_ALL}"
    )
    vulnerabilities.append(
        f"{Fore.RED}XSS: Found{Style.RESET_ALL}" if xss
        else f"{Fore.GREEN}XSS: Safe{Style.RESET_ALL}"
    )
    vulnerabilities.append(
        f"{Fore.RED}known CVEs: {', '.join(cve)}{Style.RESET_ALL}" if cve
        else f"{Fore.GREEN}No known CVEs found{Style.RESET_ALL}"
    )
    if http_headers_info:
        vulnerabilities.append(
            f"{Fore.RED}Missing security headers:\n    {', '.join(http_headers_info)}{Style.RESET_ALL}"
        )

    report = f"""{Style.RESET_ALL}[+] Vulnerability report for {url}

########################################################################################################################

Technologies found:
{json.dumps(tech, indent=2)}

Contact information:
{contact}

Security vulnerabilities:"""
    for vuln in vulnerabilities:
        report += f"\n    {vuln}"
    report += f"""

Gobuster results:
{gobuster_results}

"""
    return report


def main():
    init_colorama()
    website = input("🔍 Enter a website (with https://): ").strip()

    use_gobuster = input("\nRun Gobuster? [y/n]: ").strip().lower()
    while use_gobuster not in ["y", "n"]:
        use_gobuster = input("Please enter 'y' for yes or 'n' for no: ").strip().lower()

    print_status("[+] Scan website...", Fore.YELLOW)
    technologies = get_technologies(website)
    if not technologies:
        print_status("[X] Website not available or unknown.", Fore.RED)
        return

    sql_injection = check_sql_injection(website)
    xss = check_xss(website)
    print_status("[+] Vulnerability check completed.", Fore.YELLOW)

    http_headers_info = check_http_headers(website)
    print_status("[+] HTTP header check completed.", Fore.YELLOW)

    gobuster_results = "Gobuster scan skipped."
    if use_gobuster == "y":
        gobuster_results = run_gobuster(website)
        print_status("[+] Gobuster scan completed.", Fore.YELLOW)

    domain = website.split("//")[-1].split("/")[0]
    contact = get_contact_info(domain)
    print_status("[+] Contact information retrieved.", Fore.YELLOW)

    tech_to_check = technologies.get("CMS") or technologies.get("Webserver", "")
    cve = check_cve(tech_to_check)

    report = generate_report(website, technologies, cve, contact, sql_injection, xss, gobuster_results,
                             http_headers_info)
    print_status(report, Fore.WHITE)


if __name__ == "__main__":
    main()
