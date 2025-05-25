// background.js
// IOC-SwiftDraw Pro

// OSINT tool categories
const CATEGORIES = {
  ip: ["AbuseIPDB","AlienVault OTX","ARIN","Bad Packets","BlacklistMaster","FortiGuard","GreyNoise","HackerTarget","IPInfo","IPVoid","IPQualityScore","MXToolbox","Pulsedive","Scamalytics","SecurityTrails","Shodan","Spur.us","Spyse","Talos","ThreatCrowd","ThreatMiner","Tor Relay Search","URLhaus","VirusTotal","X-Force"],
  domain: ["Alexa","Bluecoat","Censys","FortiGuard","Host.io","MXToolbox","Pulsedive","SecurityTrails","Shodan","Spyse","Talos","ThreatCrowd","ThreatMiner","Tor Relay Search","URLhaus","VirusTotal","X-Force"],
  hash: ["AlienVault OTX","Hybrid Analysis","MalShare","Talos","ThreatMiner","URLhaus","VirusTotal","X-Force"],
  url: ["Any.Run","Bluecoat","FortiGuard","Hackertarget Extract Links","Sucuri SiteCheck","TrendMicro Site Safety","URLhaus","VirusTotal","X-Force","Zscaler Zulu"],
  email: ["ICANN WHOIS Lookup","Have I Been Pwned","MXToolbox"],
  sandbox: ["ANY.RUN","Joe Sandbox","Triage","Browserling","Siteshot","URLScan"]
};

// Storage key helpers
const menuKey = cat => `${cat}_menu`;
const swiftdrawKey = cat => `${cat}_swiftdraw`;

// URL builder functions
const OSINT_URLS = {
  "AbuseIPDB": ip => `https://www.abuseipdb.com/check/${ip}`,
  "AlienVault OTX": ip => `https://otx.alienvault.com/indicator/ip/${ip}`,
  "ARIN": ip => `https://search.arin.net/rdap/?query=${ip}`,
  "Bad Packets": ip => `https://badpackets.net/ip/${ip}`,
  "BlacklistMaster": ip => `https://blacklistmaster.com/ip/${ip}`,
  "FortiGuard": value => `https://www.fortiguard.com/webfilter?q=${value}`,
  "GreyNoise": ip => `https://viz.greynoise.io/ip/${ip}`,
  "HackerTarget": ip => `https://api.hackertarget.com/geoip/?q=${ip}`,
  "IPInfo": ip => `https://ipinfo.io/${ip}`,
  "IPVoid": ip => `https://www.ipvoid.com/ip-blacklist/${ip}`,
  "IPQualityScore": ip => `https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/${ip}`,
  "MXToolbox": value => `https://mxtoolbox.com/SuperTool.aspx?action=${value.match(/\d+\./) ? 'ip' : 'domain'}:${value}`,
  "Pulsedive": value => `https://pulsedive.com/indicator/${value.match(/\d+\./) ? 'ip' : 'domain'}/${value}`,
  "Scamalytics": ip => `https://scamalytics.com/lookup/${ip}`,
  "SecurityTrails": value => `https://securitytrails.com/${value.match(/\d+\./) ? 'list/ip' : 'domain'}/${value}`,
  "Shodan": value => `https://www.shodan.io/${value.match(/\d+\./) ? 'host' : 'search?query='}${value}`,
  "Spur.us": ip => `https://spur.us/ip/${ip}`,
  "Spyse": value => `https://spyse.com/${value.match(/\d+\./) ? 'host' : 'domain'}/${value}`,
  "Talos": value => `https://talosintelligence.com/reputation_center/lookup?search=${value}`,
  "ThreatCrowd": value => `https://www.threatcrowd.org/search.html?q=${value}`,
  "ThreatMiner": value => {
    if (/^[0-9a-f]{32,64}$/i.test(value)) return `https://www.threatminer.org/file.php?file=${value}`;
    if (value.match(/\d+\./))    return `https://www.threatminer.org/host.php?host=${value}`;
    return                        `https://www.threatminer.org/domain.php?domain=${value}`;
  },
  "Tor Relay Search": value => `https://metrics.torproject.org/rs.html#search/${value}`,
  "URLhaus": value => `https://urlhaus.abuse.ch/browse/host/${value}`,
  "VirusTotal": value => {
    if (value.match(/^\d+\./))           return `https://www.virustotal.com/gui/ip-address/${value}/detection`;
    if (/^[0-9a-f]{32,64}$/i.test(value)) return `https://www.virustotal.com/gui/file/${value}/detection`;
    if (value.includes('/'))              return `https://www.virustotal.com/gui/url/${encodeURIComponent(value)}/detection`;
    return                                 `https://www.virustotal.com/gui/domain/${value}`;
  },
  "X-Force": value => `https://exchange.xforce.ibmcloud.com/${value.match(/^\d+\./) ? 'ip' : 'url'}/${value}`,

  "Alexa": domain => `https://www.alexa.com/siteinfo/${domain}`,
  "Bluecoat": domain => `https://sitereview.bluecoat.com/#/lookup?url=${domain}`,
  "Censys": domain => `https://censys.io/domain/${domain}`,
  "Host.io": domain => `https://host.io/domain/${domain}`,

  "Hybrid Analysis": hash => `https://www.hybrid-analysis.com/sample/${hash}`,
  "MalShare": hash => `https://malshare.com/sample.php?action=search&query=${hash}`,

  "Any.Run": url => `https://any.run/tasks?url=${encodeURIComponent(url)}`,
  "Hackertarget Extract Links": url => `https://api.hackertarget.com/pagelinks/?q=${encodeURIComponent(url)}`,
  "Sucuri SiteCheck": url => `https://sitecheck.sucuri.net/results?url=${encodeURIComponent(url)}`,
  "TrendMicro Site Safety": url => `https://global.sitesafety.trendmicro.com/?url=${encodeURIComponent(url)}`,
  "URLScan": url => `https://urlscan.io/search/#${encodeURIComponent(url)}`,

  "ICANN WHOIS Lookup": email => `https://whois.icann.org/en/lookup?name=${email}`,
  "Have I Been Pwned": email => `https://haveibeenpwned.com/account/${email}`,
  "Joe Sandbox": value => `https://www.joesandbox.com/search/?query=${encodeURIComponent(value)}`,
  "Triage": value => `https://tria.ge/url/${encodeURIComponent(value)}`,
  "Browserling": url => `https://www.browserling.com/browse/${encodeURIComponent(url)}`,
  "Siteshot": url => `https://siteshot.io/result?url=${encodeURIComponent(url)}`
};

// Build context menus dynamically per category
function buildContextMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.storage.sync.get(null, data => {
      Object.keys(CATEGORIES).forEach(cat => {
        const selected = data[menuKey(cat)] || [];
        if (!selected.length) return;

        // Create category parent menu
        const parentId = chrome.contextMenus.create({
          id: `category_${cat}`,
          title: cat.charAt(0).toUpperCase() + cat.slice(1),
          contexts: ['selection']
        });

        // Add SwiftDraw entry for this category
        chrome.contextMenus.create({
          id: `swiftdraw_${cat}`,
          parentId,
          title: `🏹 SwiftDraw ${cat.charAt(0).toUpperCase() + cat.slice(1)}`,
          contexts: ['selection']
        });

        // Add each tool under the category
        selected.forEach(tool => {
          chrome.contextMenus.create({
            id: `ioc_${cat}_${tool.replace(/\s+/g,'_')}`,
            parentId,
            title: tool,
            contexts: ['selection']
          });
        });
      });
    });
  });
}

// Set defaults on first install
chrome.runtime.onInstalled.addListener(details => {
  if (details.reason === 'install') {
    const defaults = {};
    Object.keys(CATEGORIES).forEach(cat => {
      defaults[menuKey(cat)] = [...CATEGORIES[cat]];
      defaults[swiftdrawKey(cat)] = [...CATEGORIES[cat]];
    });
    chrome.storage.sync.set(defaults);
  }
  buildContextMenus();
});

// Rebuild menus on settings change
chrome.storage.onChanged.addListener(buildContextMenus);

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener(info => {
  const { menuItemId: id, selectionText: selection } = info;
  const parts = id.split('_');
  const action = parts[0];
  const cat = parts[1];

  if (action === 'swiftdraw') {
    chrome.storage.sync.get(swiftdrawKey(cat), data => {
      (data[swiftdrawKey(cat)] || []).forEach(tool => {
        const builder = OSINT_URLS[tool];
        if (builder) chrome.tabs.create({ url: builder(selection) });
      });
    });
  } else if (action === 'ioc') {
    const toolName = parts.slice(2).join(' ').replace(/_/g, ' ');
    const builder = OSINT_URLS[toolName];
    if (builder) chrome.tabs.create({ url: builder(selection) });
    else console.warn(`No URL builder for '${toolName}'.`);
  }
});
