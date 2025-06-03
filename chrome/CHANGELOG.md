# Changelog – IOC-SwiftDraw Pro

All notable changes to this project will be documented in this file.


## [1.2.0] – 2025-05-29

### Added
- New and updated OSINT tool list in both **options.js** and **background.js**, covering all categories: IP, Domain, Hash, URL, Email, Sandbox, ASN, File, Vulnerabilities, Blockchain, Utilities, ThreatIntel, Misc.
- Added new Utilities sources: **Grep.app**, **Exif.Tools**.
- Added new File‐category sources: **OHT HashTools**, **Regex101**, **Dynamite Lab**, **EMN Tools**.
- Updated Profiles to match new master tool set (Default, ALL, SOC Analyst, Incident Responder, Threat Intel, OSINT Investigator).

### Changed
- **options.js**: Completely replaced categories and tool definitions with the vetted master list; preserved existing UI and profile logic.
- **background.js**: Swapped in new `osintUrls` map with `{IOC}` placeholders; retained refang/detectLogic, storage‐driven menu creation, nested “SwiftDraw” submenu, and click handlers.
- Context menus now correctly nest under the root “IOC-SwiftDraw Pro” → Category → Tools, and launch the proper endpoints.
- Ensured all URL templates encode the selected IOC and resolve without 404s.

### Removed
- Deprecated or broken sources removed across all categories (e.g., ManyContacts, Tookie-OSINT, IP Quality Score, FortiGuard, RiskIQ, Spyse, TrendMicro, Scumware, etc.).
- **PasteDarkWeb** category removed; **Pastebin** moved to Utilities as a landing-page.

---

## [1.1.0] – 2025-05-27

### Added
- Automatic seeding of the **Default** profile on first install/startup so the context menu never starts empty.
- New categories (Email, Sandbox, ASN, File, Vulnerabilities, Blockchain, Utilities, ThreatIntel, PasteDarkWeb, Misc) and dozens of new OSINT tools drawn from the master list.
- **Profile pre-loading**: roles (Default, ALL, SOC Analyst, Incident Responder, Threat Intel, OSINT Investigator) now auto-check their toolsets on load.

### Changed
- **background.js** completely refactored:
  - Context menus now read from `chrome.storage.sync` and only build category parents & tool items the user has selected in the options page.
  - The global “SwiftDraw (Open Loadout)” menu was removed; instead each category now shows its own **🏹 SwiftDraw** child entry when any “bow” sources are enabled.
  - Replaced partial/placeholder URL templates with a full `osintUrls` map covering every tool key and IOC type (`ip`, `domain`, `url`, `hash`).
  - Menu creation now runs on `onInstalled`, `onStartup`, and in response to `chrome.storage.onChanged`, providing real-time sync with the options page.
  - Click handler split into per-category SwiftDraw launches (`swiftdraw_<category>`) and individual tool launches (`tool_<category>|<key>`), each respecting the detected IOC type.

### Fixed
- Removed or replaced deprecated/404-prone links. 
- Ensured all right-click URL mappings correctly encode `{IOC}` and open the proper endpoint.


---

## [1.0.0] – 2024-05-25
### Initial Release

- Project forked from [IOC-Quickdraw](https://github.com/StephenLacey27/IOC-Quickdraw) and inspired by the Sputnik OSINT Extension.
- Complete rewrite and redesign for extensibility and Chrome Web Store compliance.
- Added support for full user customization of OSINT sources per IOC type.
- **Two-column options interface:**  
  - **OSINT Source Selection (📁):** Choose which sources appear in right-click menus.
  - **SwiftDraw (🏹):** Choose which sources launch in a multi-source burst.
- Support for multiple IOC types: IPs, Domains, Hashes, URLs, Emails, and Sandbox/Artifact lookups.
- Added dozens of built-in OSINT platforms.
- Chrome storage sync for persistent, private user settings.
- Minimal, privacy-focused permissions.
- Clean UI and codebase ready for open-source contribution.

---

## Project Creation History

- **2023–2024:**  
  Initial work began with IOC-Quickdraw, focusing on fast context menu OSINT lookups for security analysts.
- **Spring 2024:**  
  Lessons learned and user feedback led to a full refactor—IOC-SwiftDraw Pro is built for greater flexibility, better UI, and full customization for both new and experienced users.

---

## [Unreleased]
- [Planned features and enhancements will be listed here.]

---

