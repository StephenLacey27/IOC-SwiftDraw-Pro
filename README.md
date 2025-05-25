![IOC-SwiftDraw Pro Logo](icons/banner.png)

# IOC-SwiftDraw Pro

> Ready. Set. Investigate.

A fast, secure, and fully customizable Chrome and Firefox extension for cybersecurity pros. Pivot on IOCs (IPs, domains, hashes, URLs, emails, sandbox artifacts) in a single right-click.

---

## 🚀 Features

* **Custom Context Menus**
  Toggle exactly which OSINT sources appear under each IOC type.

* **🏹 SwiftDraw Pro Loadouts**
  Pre-select your go-to tools and launch them all at once (bulk-open checked sources).

* **Two-Column Options UI**

  * 📁 **OSINT Sources:** include/exclude tools in your right-click menu
  * 🏹 **SwiftDraw Pro Loadout:** include/exclude tools in the multi-launch action

* **Pre-Configured Defaults**
  Ready on first install with a curated loadout. 

* **Privacy-First**
  No tracking or analytics—settings stay in your browser.

---

## ⚙️ Usage

1. **Highlight** or **right-click** any IOC in your browser.
2. Choose your category (IP, Domain, Hash, URL, Email, Sandbox).
3. Click an individual OSINT tool to query the IOC, or **🏹 SwiftDraw Pro** to open all your pre-selected tools.

---

## 🛠 How to Configure the Extension

1. Navigate to your browser’s extensions page (`chrome://extensions` or `about:debugging#/runtime/this-firefox`).
2. Find **IOC-SwiftDraw Pro** and click **Details**.
3. Click **Extension options**.
4. On the settings page, use the two columns:

   * **OSINT Sources** (📁): check the boxes for tools you want in your context menu.
   * **SwiftDraw Pro Loadout** (🏹): check the boxes for tools you want included in the bulk launch.
5. Click **Save Settings**.

> **Note:** Firefox support is coming soon.

---

## 🛠 IOC Types and Supported Tools

### IP

* AbuseIPDB
* AlienVault OTX
* ARIN
* BlacklistMaster
* FortiGuard
* GreyNoise
* HackerTarget
* IPInfo
* IPVoid
* IPQualityScore
* MXToolbox
* Pulsedive
* Scamalytics
* SecurityTrails
* Shodan
* Spur.us
* Spyse
* Talos
* ThreatCrowd
* ThreatMiner
* Tor Relay Search
* URLhaus
* VirusTotal
* X-Force

### Domain

* Alexa
* Bluecoat
* Censys
* FortiGuard
* Host.io
* MXToolbox
* Pulsedive
* SecurityTrails
* Shodan
* Spyse
* Talos
* ThreatCrowd
* ThreatMiner
* Tor Relay Search
* URLhaus
* VirusTotal
* X-Force
* SSL Labs

### Hash

* AlienVault OTX
* Hybrid Analysis
* MalShare
* Talos
* ThreatMiner
* URLhaus
* VirusTotal
* X-Force

### URL

* ANY.RUN
* Bluecoat
* FortiGuard
* HackerTarget Extract Links
* Sucuri SiteCheck
* TrendMicro Site Safety
* URLhaus
* VirusTotal
* X-Force
* Zscaler Zulu

### Email

* ICANN WHOIS Lookup
* Have I Been Pwned
* MXToolbox

### Sandbox

* ANY.RUN
* Joe Sandbox
* Triage
* Browserling
* Siteshot
* URLScan

---

## 💾 Installation

### Chrome

```bash
# 1. Go to chrome://extensions  
# 2. Enable “Developer mode”  
# 3. Click “Load unpacked”  
# 4. Select this repo’s `chrome/` folder
```

### Firefox (Coming Soon)

```bash
# 1. Go to about:debugging#/runtime/this-firefox  
# 2. Click “Load Temporary Add-on”  
# 3. Select `manifest.json` from the `firefox/` folder
```

---

## 🔧 Development

```bash
git clone https://github.com/StephenLacey27/IOC-SwiftDraw-Pro.git
cd IOC-SwiftDraw-Pro
```

* Edit `background.js`, `options.html`, or `options.js`.
* Reload the unpacked extension in Chrome/Firefox to test.

---

## 🤝 Contributing

1. Fork this repo
2. Create a branch:

   ```bash
   git checkout -b feature/YourFeature
   ```
3. Commit your changes:

   ```bash
   git commit -m "Add YourFeature"
   ```
4. Push & open a PR.

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

© 2025 Stephen Lacey | Cybersecurity Analyst & OSINT Engineer
