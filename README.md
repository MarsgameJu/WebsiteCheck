

---

# Website Vulnerability Checker  

This tool scans a website for security vulnerabilities such as SQL Injection, XSS, and missing HTTP security headers. It also detects technologies used on the site and checks for known vulnerabilities (CVEs).  

## 🚀 Installation  

1. **Navigate to the project directory**  
   ```bash
   cd /path/to/project
   ```

2. **Install dependencies**  
   Run the following command to install the required Python packages:  
   ```bash
   pip install requests beautifulsoup4 python-whois colorama
   ```
   ```bash
   pip install pyfiglet
   ```

3. **Install Gobuster**  
   Gobuster is an external tool that needs to be installed separately.  

   - **Linux (e.g., Kali Linux)**  
     ```bash
     sudo apt install gobuster
     ```
   - **Windows**  
     Download Gobuster from [GitHub](https://github.com/OJ/gobuster) and add it to your system path.
     
   - **Install via Go** (Linux/Mac/Windows)  
     If you have [Go]((https://go.dev/dl/)) installed, you can install Gobuster with:  
     ```bash
     go install github.com/OJ/gobuster/v3@latest
     ```  
     Ensure that `$GOPATH/bin` is in your system `PATH` so you can run Gobuster globally.  

4. **Set the correct wordlist path**  
   Open `main.py` and update the wordlist path:  
   ```python
   wordlist_path = "C:/path/to/wordlist.txt"
   ```

## ▶️ Usage  

1. Start the tool with:  
   ```bash
   python main.py
   ```
2. Enter the target website (including `https://`) to begin the scan.  

## 📌 Features  

- Detects technologies (CMS, web server)  
- Checks for SQL Injection and Cross-Site Scripting (XSS) vulnerabilities  
- Analyzes HTTP security headers  
- Fetches known vulnerabilities from the CVE database  
- Runs Gobuster scans (if installed)  
- Retrieves WHOIS contact information  

---

⚠ **Disclaimer:** This tool is for educational and ethical security testing purposes only!
