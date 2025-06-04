![IOC-SwiftDraw Pro Logo](icons/banner.png)

# IOC-SwiftDraw Pro

> Ready. Set. Investigate.

IOC-SwiftDraw Pro is a fast, privacy-first Chrome/Firefox extension built for security analysts, threat hunters, and OSINT researchers who need to pivot on Indicators of Compromise instantly—without ever leaving the browser. With a single right-click, you can query your choice of dozens of specialized services across IPs, domains, hashes, URLs, emails, sandbox artifacts, ASNs and more, either one at a time or all at once via fully customizable “SwiftDraw Pro” loadouts.

---

## 🚀 Features

- 🕵️‍♂️ **Profiles & Presets**  
  Pick a role to auto-load its curated toolset:
  - Default  
  - ALL  
  - SOC Analyst  
  - Incident Responder  
  - Threat Intel  
  - OSINT Investigator  

- 🗂️ **Custom Context Menus**  
  Toggle exactly which OSINT sources appear under each IOC type.

- 🏹 **SwiftDraw Pro Loadouts**  
  Pre-select your go-to tools and launch them all at once (bulk-open checked sources).

- 🧛‍♂️ **Defang & Re-fang Support**  
  Automatically “defang” and re-inject common IOC obfuscations (`hxxp`, `[.]`, `(dot)`, `[at]`) so you can right-click even defanged text.

- **Two-Column Options UI**  
  - 📄 **OSINT Sources** – include/exclude tools in your right-click menu  
  - 🏹 **SwiftDraw Pro Loadout** – include/exclude tools in each category’s SwiftDraw loadout

- 🧰 **Extensible Categories & Tools**  
  Customize which of these categories and dozens of sources you want:
  - IP  
  - Domain  
  - Hash  
  - URL  
  - Email  
  - Sandbox  
  - ASN  
  - File  
  - Vulnerabilities  
  - Blockchain  
  - Utilities  
  - ThreatIntel  
  - Misc  

- 🔒 **Privacy-First**  
  No tracking or analytics—settings stay in your browser, synced only via Chrome’s storage.

---

## ⚙️ Usage

1. **Highlight** or **right-click** any IOC in your browser.  
2. Choose your category (IP, Domain, Hash, URL, Email, Sandbox, ASN, File, etc.).  
3. Click an individual OSINT tool to query the IOC, or **🏹 SwiftDraw** under that category to fire all your pre-selected loadout tools.

---

## 🛠 How to Configure

1. Open the Extensions page:  
   - **Chrome:** `chrome://extensions` → find **IOC-SwiftDraw Pro** → **Details** → **Extension options**  
   - **Firefox:** `about:addons` → find **IOC-SwiftDraw Pro** → **Preferences** (or see “Load Temporary Add-on” if installing unpacked)  
2. In the options UI:  
   - **Profile Selector**: pick a preset or **Custom**.  
   - **Two-Column Grid**:  
     - Left column (📄): check the tools you want in your right-click menu.  
     - Right column (🏹): check the tools you want in each category’s SwiftDraw loadout.  
3. Click **💾 Save**. Menus rebuild instantly.

---

## 🛠 IOC Types & Supported Tools

### IP
- AbuseIPDB  
- AlienVault OTX  
- ARIN WHOIS  
- BlacklistMaster  
- BGPView  
- Censys  
- DNSlytics  
- GreyNoise  
- HackerTarget  
- Hurricane BGP  
- IPInfo  
- IPVoid  
- MXToolbox  
- ONYPHE  
- OTX (AlienVault)  
- Pulsedive  
- Robtex  
- Scamalytics  
- SecurityTrails  
- Shodan  
- Spur  
- Talos Intelligence  
- ThreatMiner  
- TOR Relay Search  
- URLhaus  
- VirusTotal  
- X-Force Exchange  
- ZoomEye  

### Domain
- BlueCoat  
- Censys  
- host.io  
- MXToolbox  
- Pulsedive  
- SecurityTrails  
- Shodan  
- Talos Intelligence  
- ThreatMiner  
- URLhaus  
- VirusTotal  
- X-Force Exchange  

### Hash
- OHT HashTools  
- AlienVault OTX  
- Hybrid Analysis  
- Joe Sandbox  
- MalShare  
- MalwareBazaar  
- ThreatMiner  
- VirusTotal  
- X-Force Exchange  

### URL
- Any.Run  
- Archive.today  
- Archive.org  
- BlueCoat  
- Browserling  
- Checkphish  
- Hybrid Analysis  
- OTX (AlienVault)  
- Pulsedive  
- Sucuri SiteCheck  
- URLhaus  
- urlscan.io  
- VirusTotal  
- X-Force Exchange  
- Zscaler Zulu  

### Email
- EmailRep  
- Have I Been Pwned  
- ICANN WHOIS Lookup  
- MXToolbox  
- Thatsthem  
- ThreatConnect  
- Usersearch  

### Sandbox
- ANY.RUN  
- Browserling  
- Hybrid Analysis  
- Joe Sandbox  
- Siteshot  
- Triage  
- urlscan.io  
- VirusTotal  

### ASN
- BGPView  
- Censys  
- Hurricane BGP  
- IPInfo  

### File
- CyberChef  
- LOLBAS  
- OHT HashTools  
- Regex101  
- Dynamite Lab  
- EMN Tools  

### Vulnerabilities
- MITRE CVE  
- NVD  
- Exploit-DB  
- CISA Known Exploited Vulnerabilities Catalog  
- OSV  
- Recorded Future Vulnerability Database  
- Snyk Security  
- Feedly CVE  

### Blockchain
- BitcoinAbuse  
- Blockchain.com  
- Blockchair  
- BlockCypher  
- Etherscan  
- Ethplorer  

### Utilities
- Regex101  
- EMN Tools  
- CyberChef  
- Pastebin  
- Grep.app  
- Exif.Tools  

### ThreatIntel
- Intelligence X  
- OOCPR  
- Pulsedive  
- ThreatFox  
- TIP (ThreatIntelligencePlatform)  
- Spamhaus  

### Misc
- Fast.com  
- Speedtest.net  
- Downdetector  
- IsItDownRightNow  
- IsUp.me  
- Check Point Threat Map  
- Kaspersky Cybermap  
- JSON Formatter & Validator  

---

## 💾 Installation

### Chrome
1. Go to `chrome://extensions`
2. Enable “Developer mode”
3. Click “Load unpacked”
4. Select this repo’s `chrome/` folder

### Firefox
1. Go to `about:debugging#/runtime/this-firefox`
2. Click “Load Temporary Add-on”
3. Select `firefox/manifest.json`


## 🔧 Development

git clone https://github.com/StephenLacey27/IOC-SwiftDraw-Pro.git
cd IOC-SwiftDraw-Pro
# Edit background.js, options.js, or options.html
# Reload the extension to test your changes

## 🤝 Contributing

    Fork this repo

    Create a branch: git checkout -b feature/YourFeature

    Commit: git commit -m "Add YourFeature"

    Push & open a PR

## 📄 License

Distributed under the MIT License. See LICENSE for details.

© 2025 Stephen Lacey | Cybersecurity Analyst & OSINT Engineer

## 🙏 Acknowledgments
Special thanks to Beau Brasher for his invaluable help with profiles and testing throughout development. Your insights and feedback have helped IOC-SwiftDraw Pro reach its full potential!

