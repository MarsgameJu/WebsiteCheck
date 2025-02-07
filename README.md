## Website Security Checker  

Dieses Tool überprüft eine Website auf Sicherheitslücken wie SQL-Injection, XSS und fehlende HTTP-Sicherheitsheader. Zudem werden Technologien erkannt und bekannte Schwachstellen (CVEs) abgefragt.  

### 🚀 Installation  

1. **Abhängigkeiten installieren**  
   Führe folgenden Befehl aus, um die benötigten Python-Pakete zu installieren:  

   ```bash
   pip install requests beautifulsoup4 python-whois colorama
   ```

2. **Gobuster installieren**  
   Da Gobuster ein externes Tool ist, muss es separat installiert werden:  

   - **Linux (z. B. Kali Linux)**  
     ```bash
     sudo apt install gobuster
     ```
   - **Windows**  
     Lade Gobuster von [GitHub](https://github.com/OJ/gobuster) herunter und füge es zum Pfad hinzu.  

3. **Wordlist-Pfad anpassen**  
   Öffne die Datei `main.py` und passe den Pfad zur Wordlist an, z. B.:  

   ```python
   wordlist_path = "C:/Pfad/zur/wordlist.txt"
   ```

### ▶️ Nutzung  

1. Navigiere in das Verzeichnis des Projekts:  
   ```bash
   cd /pfad/zum/projekt
   ```
2. Starte das Tool mit:  
   ```bash
   python main.py
   ```
3. Gib die gewünschte Website (mit `https://`) ein, um die Analyse zu starten.  

### 📌 Funktionen  

- Erkennt verwendete Technologien (CMS, Webserver)  
- Prüft auf SQL-Injection und Cross-Site Scripting (XSS)  
- Analysiert HTTP-Sicherheitsheader  
- Sucht nach bekannten Schwachstellen (CVE-Datenbank)  
- Führt Gobuster-Scans durch (sofern installiert)  
- Zeigt WHOIS-Kontaktinformationen an  

---

Falls du Fragen oder Probleme hast, kannst du mich gerne fragen! 😊
