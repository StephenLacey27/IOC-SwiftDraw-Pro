// options.js
// IOC-SwiftDraw Pro Options Script

// Polyfill for Chrome/Firefox API compatibility
const browser = chrome || browser;

// --- Complete OSINT Source Definitions ---
const osintTools = {
  "IP": [
    { key: "abuseipdb", name: "AbuseIPDB" },
    { key: "alienvault", name: "AlienVault OTX" },
    { key: "arin", name: "ARIN WHOIS" },
    { key: "blacklistmaster", name: "BlacklistMaster" },
    { key: "bgpview", name: "BGPView" },
    { key: "censys", name: "Censys" },
    { key: "dnslytics", name: "DNSlytics" },
    { key: "greynoise", name: "GreyNoise" },
    { key: "hackertarget", name: "HackerTarget" },
    { key: "he", name: "Hurricane BGP" },
    { key: "ipinfo", name: "IPInfo" },
    { key: "ipvoid", name: "IPVoid" },
    { key: "mxtoolbox", name: "MXToolbox" },
    { key: "onyphe", name: "ONYPHE" },
    { key: "otx", name: "OTX (AlienVault)" },
    { key: "pulsedive", name: "Pulsedive" },
    { key: "robtex", name: "Robtex" },
    { key: "scamalytics", name: "Scamalytics" },
    { key: "securitytrails", name: "SecurityTrails" },
    { key: "shodan", name: "Shodan" },
    { key: "spur", name: "Spur" },
    { key: "talos", name: "Talos Intelligence" },
    { key: "threatminer", name: "ThreatMiner" },
    { key: "torrelay", name: "TOR Relay Search" },
    { key: "urlhaus", name: "URLhaus" },
    { key: "virustotal", name: "VirusTotal" },
    { key: "xforceexchange", name: "X-Force Exchange" },
    { key: "zoomeye", name: "ZoomEye" }
  ],
  "Domain": [
    { key: "bluecoat", name: "BlueCoat" },
    { key: "censys", name: "Censys" },
    { key: "hostio", name: "host.io" },
    { key: "mxtoolbox", name: "MXToolbox" },
    { key: "pulsedive", name: "Pulsedive" },
    { key: "securitytrails", name: "SecurityTrails" },
    { key: "shodan", name: "Shodan" },
    { key: "talos", name: "Talos Intelligence" },
    { key: "threatminer", name: "ThreatMiner" },
    { key: "urlhaus", name: "URLhaus" },
    { key: "virustotal", name: "VirusTotal" },
    { key: "xforceexchange", name: "X-Force Exchange" }
  ],
  "Hash": [
    { key: "ohthashtools", name: "OHT HashTools" },
    { key: "alienvault", name: "AlienVault OTX" },
    { key: "hybridanalysis", name: "Hybrid Analysis" },
    { key: "joesandbox", name: "Joe Sandbox" },
    { key: "malshare", name: "MalShare" },
    { key: "malwarebazaar", name: "MalwareBazaar" },
    { key: "threatminer", name: "ThreatMiner" },
    { key: "virustotal", name: "VirusTotal" },
    { key: "xforceexchange", name: "X-Force Exchange" }
  ],
  "URL": [
    { key: "anyrun", name: "Any.Run" },
    { key: "archive_today", name: "Archive.today" },
    { key: "archive_org", name: "Archive.org" },
    { key: "bluecoat", name: "BlueCoat" },
    { key: "browserling", name: "Browserling" },
    { key: "checkphish", name: "Checkphish" },
    { key: "hybridanalysis", name: "Hybrid Analysis" },
    { key: "otx", name: "OTX (AlienVault)" },
    { key: "pulsedive", name: "Pulsedive" },
    { key: "sucuri", name: "Sucuri SiteCheck" },
    { key: "urlhaus", name: "URLhaus" },
    { key: "urlscan", name: "urlscan.io" },
    { key: "virustotal", name: "VirusTotal" },
    { key: "xforceexchange", name: "X-Force Exchange" },
    { key: "zscaler", name: "Zscaler Zulu" }
  ],
  "Email": [
    { key: "emailrep", name: "EmailRep" },
    { key: "hibp", name: "Have I Been Pwned" },
    { key: "icann", name: "ICANN WHOIS Lookup" },
    { key: "mxtoolbox", name: "MXToolbox" },
    { key: "thatsthem", name: "Thatsthem" },
    { key: "threatconnect", name: "ThreatConnect" },
    { key: "usersearch", name: "Usersearch" }
  ],
  "Sandbox": [
    { key: "anyrun", name: "ANY.RUN" },
    { key: "browserling", name: "Browserling" },
    { key: "hybridanalysis", name: "Hybrid Analysis" },
    { key: "joesandbox", name: "Joe Sandbox" },
    { key: "siteshot", name: "Siteshot" },
    { key: "triage", name: "Triage" },
    { key: "urlscan", name: "urlscan.io" },
    { key: "virustotal", name: "VirusTotal" }
  ],
  "ASN": [
    { key: "bgpview", name: "BGPView" },
    { key: "censys", name: "Censys" },
    { key: "he", name: "Hurricane BGP" },
    { key: "ipinfo", name: "IPInfo" }
  ],
  "File": [
    { key: "cyberchef", name: "CyberChef" },
    { key: "lolbas", name: "LOLBAS" },
    { key: "ohthashtools", name: "OHT HashTools" },
    { key: "regex101", name: "Regex101" },
    { key: "dynamitelab", name: "Dynamite Lab" },
    { key: "emntools", name: "EMN Tools" }
  ],
  "Vulnerabilities": [
    { key: "cve", name: "MITRE CVE" },
    { key: "nvd", name: "NVD" },
    { key: "exploitdb", name: "Exploit-DB" },
    { key: "cisa", name: "CISA Known Exploited Vulnerabilities Catalog" },
    { key: "osv", name: "OSV" },
    { key: "recordedfuture", name: "Recorded Future Vulnerability Database" },
    { key: "snyk", name: "Snyk Security" },
    { key: "feedlycve", name: "Feedly CVE" }
  ],
  "Blockchain": [
    { key: "bitcoinabuse", name: "BitcoinAbuse" },
    { key: "blockchaincom", name: "Blockchain.com" },
    { key: "blockchair", name: "Blockchair" },
    { key: "blockcypher", name: "BlockCypher" },
    { key: "etherscan", name: "Etherscan" },
    { key: "ethplorer", name: "Ethplorer" }
  ],
  "Utilities": [
    { key: "regex101", name: "Regex101" },
    { key: "emntools", name: "EMN Tools" },
    { key: "cyberchef", name: "CyberChef" },
    { key: "pastebin", name: "Pastebin" },
    { key: "grepapp", name: "Grep.app" },
    { key: "exiftools", name: "Exif.Tools" }
  ],
  "ThreatIntel": [
    { key: "intelx", name: "Intelligence X" },
    { key: "ooctr", name: "OOCPR" },
    { key: "pulsedive", name: "Pulsedive" },
    { key: "threatfox", name: "ThreatFox" },
    { key: "tip", name: "TIP (ThreatIntelligencePlatform)" },
    { key: "spamhaus", name: "Spamhaus" }
  ],
  "Misc": [
    { key: "fast", name: "Fast.com" },
    { key: "speedtest", name: "Speedtest.net" },
    { key: "downdetector", name: "Downdetector" },
    { key: "isitdownrightnow", name: "IsItDownRightNow" },
    { key: "isupme", name: "IsUp.me" },
    { key: "checkpointthreatmap", name: "Check Point Threat Map" },
    { key: "kasperskycybermap", name: "Kaspersky Cybermap" },
    { key: "jsonformatter", name: "JSON Formatter & Validator" }
  ]
};

// --- Profiles (Default, ALL, SOC Analyst, Incident Responder, Threat Intel, OSINT Investigator, None, Custom) ---
const osintProfiles = {
  "Default": Object.fromEntries(
    Object.entries(osintTools).map(([cat, tools]) => [cat, tools.map(t => t.key)])
  ),
  "ALL": Object.fromEntries(
    Object.entries(osintTools).map(([cat, tools]) => [cat, tools.map(t => t.key)])
  ),
  "SOC Analyst": {
    "IP": ["abuseipdb", "alienvault", "censys", "shodan", "virustotal"],
    "Domain": ["censys", "securitytrails", "shodan"],
    "Hash": ["hybridanalysis", "virustotal"],
    "URL": ["hybridanalysis", "urlscan", "virustotal"],
    "Email": ["emailrep", "hibp"],
    "Sandbox": ["anyrun", "hybridanalysis"],
    "Utilities": ["regex101", "cyberchef"],
    "ThreatIntel": ["intelx", "spamhaus"]
  },
  "Incident Responder": {
    "IP": ["abuseipdb", "alienvault", "censys", "ipinfo", "shodan", "virustotal"],
    "Domain": ["censys", "securitytrails", "shodan"],
    "Hash": ["hybridanalysis", "malwarebazaar"],
    "URL": ["anyrun", "hybridanalysis", "urlscan"],
    "Email": ["emailrep"],
    "Sandbox": ["anyrun", "hybridanalysis"],
    "File": ["cyberchef", "lolbas"],
    "Utilities": ["cyberchef", "pastebin"]
  },
  "Threat Intel": {
    "ThreatIntel": ["intelx", "ooctr", "pulsedive", "spamhaus"],
    "IP": ["abuseipdb", "alienvault", "shodan"],
    "Domain": ["securitytrails", "virustotal"]
  },
  "OSINT Investigator": Object.fromEntries(
    Object.entries(osintTools).map(([cat, tools]) => [cat, tools.map(t => t.key)])
  ),
  "None": {},
  "Custom": {}
};

// --- Utility Functions ---
function getAllCategories() {
  return Object.keys(osintTools);
}

function getToolsForCategory(cat) {
  return osintTools[cat] || [];
}

// --- Save osintTools to storage ---
function saveOsintTools() {
  browser.storage.sync.set({ osintTools }, () => {
    console.log('osintTools saved to storage');
  });
}

// --- Save with feedback ---
function saveOptions() {
  const profile = document.getElementById('profileSelector').value;
  const checkedSources = {}, checkedSourcesSwiftDraw = {};
  getAllCategories().forEach(cat => {
    checkedSources[cat] = [];
    checkedSourcesSwiftDraw[cat] = [];
    getToolsForCategory(cat).forEach(tool => {
      const main = document.getElementById(`${cat}|${tool.key}|main`);
      const bow = document.getElementById(`${cat}|${tool.key}|bow`);
      if (main && main.checked) checkedSources[cat].push(tool.key);
      if (bow && bow.checked) checkedSourcesSwiftDraw[cat].push(tool.key);
    });
  });
  let newProfile = ["Default", "ALL", "None"].includes(profile) ? profile : "Custom";
  browser.storage.sync.set({ profile: newProfile, checkedSources, checkedSourcesSwiftDraw }, () => {
    let msg = document.getElementById('saveMsg');
    if (!msg) {
      msg = document.createElement('span');
      msg.id = 'saveMsg';
      msg.style.marginLeft = '1em';
      document.getElementById('saveBtn').after(msg);
    }
    msg.textContent = '✅ Saved!';
    setTimeout(() => msg.textContent = '', 2000);
  });
}

// --- Profile selector render ---
function renderProfileSelector(current) {
  const div = document.getElementById('profileSelectorDiv');
  div.innerHTML = '';
  const label = document.createElement('label');
  label.textContent = 'Select Profile: ';
  const select = document.createElement('select');
  select.id = 'profileSelector';
  Object.keys(osintProfiles).forEach(p => {
    const opt = document.createElement('option');
    opt.value = p;
    opt.textContent = p;
    if (p === current) opt.selected = true;
    select.append(opt);
  });
  select.addEventListener('change', () => {
    const p = select.value;
    const defs = getDefaultCheckedSources(p);
    renderOptions(p, defs.checked, defs.swiftdraw);
    browser.storage.sync.set({ profile: p, checkedSources: defs.checked, checkedSourcesSwiftDraw: defs.swiftdraw }, () => {
      console.log(`Profile ${p} saved`);
    });
  });
  div.append(label, select);
}

// --- Defaults helper ---
function getDefaultCheckedSources(profile) {
  const checked = {}, swiftdraw = {};
  if (osintProfiles[profile]) {
    Object.entries(osintProfiles[profile]).forEach(([cat, list]) => {
      checked[cat] = [...list];
      swiftdraw[cat] = [];
    });
  }
  return { checked, swiftdraw };
}

// --- Load on start ---
function loadOptions() {
  saveOsintTools();
  browser.storage.sync.get(['profile', 'checkedSources', 'checkedSourcesSwiftDraw'], data => {
    const p = data.profile || 'Default';
    const defs = ['Default', 'ALL', 'None'].includes(p)
      ? getDefaultCheckedSources(p)
      : { checked: data.checkedSources || {}, swiftdraw: data.checkedSourcesSwiftDraw || {} };
    renderProfileSelector(p);
    renderOptions(p, defs.checked, defs.swiftdraw);
  });
}

// --- Render table with two columns ---
function renderOptions(profile, checkedSources, checkedSourcesSwiftDraw) {
  const container = document.getElementById('categories');
  container.innerHTML = '';
  getAllCategories().forEach(cat => {
    const catDiv = document.createElement('div');
    catDiv.className = 'category';
    catDiv.innerHTML = `<h3>${cat}</h3>`;
    const table = document.createElement('table');
    table.style.width = '100%';
    table.style.borderCollapse = 'collapse';
    table.style.marginBottom = '1em';
    const hdr = table.insertRow();
    hdr.insertCell().outerHTML = `<th style="width:40%;padding:0.5em;border-bottom:1px solid #ccc;text-align:left;">📄 OSINT Sources</th>`;
    hdr.insertCell().outerHTML = `<th style="width:30%;padding:0.5em;border-bottom:1px solid #ccc;text-align:center;">🏹 SwiftDraw Pro Loadout</th>`;
    getToolsForCategory(cat).forEach((tool, i) => {
      const row = table.insertRow();
      if (i % 2) row.style.background = '#f5f6fa';
      const c1 = row.insertCell();
      c1.style.padding = '0.4em';
      c1.style.textAlign = 'left';
      const cb1 = document.createElement('input');
      cb1.type = 'checkbox';
      cb1.id = `${cat}|${tool.key}|main`;
      cb1.checked = checkedSources[cat]?.includes(tool.key) || false;
      cb1.addEventListener('change', saveOptions);
      c1.append(cb1, document.createElement('label'));
      c1.lastChild.htmlFor = cb1.id;
      c1.lastChild.textContent = ' ' + tool.name;
      const c2 = row.insertCell();
      c2.style.padding = '0.4em';
      c2.style.textAlign = 'center';
      const cb2 = document.createElement('input');
      cb2.type = 'checkbox';
      cb2.id = `${cat}|${tool.key}|bow`;
      cb2.checked = checkedSourcesSwiftDraw[cat]?.includes(tool.key) || false;
      cb2.addEventListener('change', saveOptions);
      c2.append(cb2);
    });
    catDiv.append(table);
    container.append(catDiv);
  });
  let btn = document.getElementById('saveBtn');
  if (!btn) {
    btn = document.createElement('button');
    btn.id = 'saveBtn';
    btn.textContent = '💾 Save';
    container.append(btn);
  }
  btn.onclick = saveOptions;
}

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
  if (!document.getElementById('profileSelectorDiv')) {
    document.body.insertBefore(document.createElement('div'), document.body.firstChild).id = 'profileSelectorDiv';
  }
  if (!document.getElementById('categories')) {
    document.body.appendChild(document.createElement('div')).id = 'categories';
  }
  loadOptions();
});