![IOC-SwiftDraw Pro Logo](icons/icon-128.png)

# IOC-SwiftDraw Pro

> Ready. Set. Investigate.

A fast, secure, and fully customizable Chrome and Firefox extension for cybersecurity pros—pivot on IOCs (IPs, domains, hashes, URLs, emails, sandbox artifacts) in a single right-click.

---

## 🚀 Features

- **Custom Context Menus**  
  Toggle exactly which OSINT sources appear under each IOC type.

- **🏹 SwiftDraw Pro Loadouts**  
  Pre-select your go-to tools and launch them all at once.

- **Two-Column Options UI**  
  - 📁 **OSINT Sources:** include/exclude tools in your right-click menu  
  - 🏹 **SwiftDraw Pro Loadout:** include/exclude tools in the multi-launch action

- **Pre-Configured Defaults**  
  Comes ready on first install with a curated loadout.

- **Privacy-First**  
  No tracking or analytics—settings stay in your browser.

---

## 💾 Installation

### Chrome

```bash
# 1. Go to chrome://extensions  
# 2. Enable “Developer mode”  
# 3. Click “Load unpacked”  
# 4. Select this repo’s `chrome/` folder
```

### Firefox

```bash
# 1. Go to about:debugging#/runtime/this-firefox  
# 2. Click “Load Temporary Add-on”  
# 3. Select `manifest.json` from the `firefox/` folder
```

---

## ⚙️ Usage

1. **Highlight** or **right-click** any IOC in your browser.  
2. Choose your category (IP, Domain, Hash, URL, Email, Sandbox).  
3. Click an individual tool or **🏹 SwiftDraw Pro** to open all your pre-selected tools.  
4. To customize, open **Options** (`IOC-SwiftDraw Pro → Options`), toggle your sources, then click **💾 Save Settings**.

---

## 🔧 Development

```bash
git clone https://github.com/StephenLacey27/IOC-SwiftDraw-Pro.git
cd IOC-SwiftDraw-Pro
```

- Edit `background.js`, `options.html` or `options.js`.  
- Reload the unpacked extension in Chrome/Firefox to test.  

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
