// background.js
// IOC-SwiftDraw Pro Background Script

// Polyfill for Chrome/Firefox API compatibility
const browser = chrome || browser;

// --- Refanging and IOC detection helpers ---
function refang(input) {
  return input
    .replace(/\[\.\]/g, '.')
    .replace(/\(dot\)/gi, '.')
    .replace(/hxxp:\/\//gi, 'http://')
    .replace(/hxxtp:\/\//gi, 'https://')
    .replace(/\[at\]/gi, '@')
    .replace(/\(at\)/gi, '@');
}

function detectType(ioc) {
  const ipPattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const hashPattern = /^[A-Fa-f0-9]{32,128}$/;
  const urlPattern = /^https?:\/\/.+/i;
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const domainPattern = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
  if (ipPattern.test(ioc)) return 'ip';
  if (hashPattern.test(ioc)) return 'hash';
  if (urlPattern.test(ioc)) return 'url';
  if (emailPattern.test(ioc)) return 'email';
  if (domainPattern.test(ioc)) return 'domain';
  return 'misc';
}

// --- Full OSINT URL templates ---
const osintUrls = {
  "IP": {
    "abuseipdb": "https://www.abuseipdb.com/check/{IOC}",
    "alienvault": "https://otx.alienvault.com/indicator/ip/{IOC}",
    "arin": "https://search.arin.net/rdap/?query={IOC}",
    "blacklistmaster": "https://www.blacklistmaster.com/check?t={IOC}",
    "bgpview": "https://bgpview.io/ip/{IOC}",
    "censys": "https://censys.io/ipv4/{IOC}",
    "dnslytics": "https://dnslytics.com/ip/{IOC}",
    "greynoise": "https://www.greynoise.io/viz/ip/{IOC}",
    "hackertarget": "https://hackertarget.com/reverse-ip-lookup/?q={IOC}",
    "he": "https://bgp.he.net/ip/{IOC}",
    "ipinfo": "https://ipinfo.io/{IOC}",
    "ipvoid": "https://www.ipvoid.com/ip-address/{IOC}",
    "mxtoolbox": "https://mxtoolbox.com/SuperTool.aspx?action=ip%3a{IOC}",
    "onyphe": "https://search.onyphe.io/search?q=category%3Adatascan+{IOC}",
    "otx": "https://otx.alienvault.com/indicator/ip/{IOC}",
    "pulsedive": "https://pulsedive.com/explore/?q={IOC}",
    "robtex": "https://www.robtex.com/ip/{IOC}",
    "scamalytics": "https://scamalytics.com/ip/{IOC}",
    "securitytrails": "https://securitytrails.com/list/ip/{IOC}",
    "shodan": "https://www.shodan.io/host/{IOC}",
    "spur": "https://app.spur.us/search?q={IOC}",
    "talos": "https://talosintelligence.com/reputation_center/lookup?search={IOC}",
    "threatminer": "https://www.threatminer.org/host.php?q={IOC}",
    "torrelay": "https://metrics.torproject.org/ip/{IOC}.json",
    "urlhaus": "https://urlhaus.abuse.ch/browse.php?search={IOC}",
    "virustotal": "https://www.virustotal.com/gui/ip-address/{IOC}",
    "xforceexchange": "https://exchange.xforce.ibmcloud.com/ip/{IOC}",
    "zoomeye": "https://www.zoomeye.org/searchResult?q=ip:{IOC}"
  },
  "Domain": {
    "bluecoat": "https://sitereview.bluecoat.com/#/lookup-result/{IOC}",
    "censys": "https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q={IOC}",
    "hostio": "https://host.io/{IOC}",
    "mxtoolbox": "https://mxtoolbox.com/SuperTool.aspx?action=domain%3a{IOC}",
    "pulsedive": "https://pulsedive.com/explore/?q=domain%2F{IOC}",
    "securitytrails": "https://securitytrails.com/domain/{IOC}",
    "shodan": "https://www.shodan.io/search?query={IOC}",
    "talos": "https://talosintelligence.com/reputation_center/lookup?search={IOC}",
    "threatminer": "https://www.threatminer.org/domain.php?q={IOC}",
    "urlhaus": "https://urlhaus.abuse.ch/browse.php?search={IOC}",
    "virustotal": "https://www.virustotal.com/gui/domain/{IOC}",
    "xforceexchange": "https://exchange.xforce.ibmcloud.com/url/{IOC}"
  },
  "Hash": {
    "ohthashtools": "https://onlinehashtools.com/?q={IOC}",
    "alienvault": "https://otx.alienvault.com/indicator/file/{IOC}",
    "hybridanalysis": "https://www.hybrid-analysis.com/sample/{IOC}",
    "joesandbox": "https://www.joesandbox.com/analysis/search?q={IOC}",
    "malshare": "https://malshare.com/sample.php?action=detail&hash={IOC}",
    "malwarebazaar": "https://bazaar.abuse.ch/sample/{IOC}/",
    "threatminer": "https://www.threatminer.org/sample.php?q={IOC}",
    "virustotal": "https://www.virustotal.com/gui/file/{IOC}",
    "xforceexchange": "https://exchange.xforce.ibmcloud.com/malware/{IOC}"
  },
  "URL": {
    "anyrun": "https://app.any.run/submissions/?query={IOC}",
    "archive_today": "https://archive.today/{IOC}",
    "archive_org": "https://web.archive.org/web/*/{IOC}",
    "bluecoat": "https://sitereview.bluecoat.com/#/lookup-result/{IOC}",
    "browserling": "https://www.browserling.com/browse?url={IOC}",
    "checkphish": "https://checkphish.ai/?url={IOC}",
    "hybridanalysis": "https://www.hybrid-analysis.com/search?query={IOC}",
    "otx": "https://otx.alienvault.com/indicator/url/{IOC}",
    "pulsedive": "https://pulsedive.com/explore/?q={IOC}",
    "sucuri": "https://sitecheck.sucuri.net/results/{IOC}",
    "urlhaus": "https://urlhaus.abuse.ch/browse.php?search={IOC}",
    "urlscan": "https://urlscan.io/search/#{IOC}",
    "virustotal": "https://www.virustotal.com/gui/url/{IOC}",
    "xforceexchange": "https://exchange.xforce.ibmcloud.com/url/{IOC}",
    "zscaler": "https://zulu.zscaler.com/?url={IOC}"
  },
  "Email": {
    "emailrep": "https://emailrep.io/{IOC}",
    "hibp": "https://haveibeenpwned.com/account/{IOC}",
    "icann": "https://lookup.icann.org/en/lookup?name={IOC}",
    "mxtoolbox": "https://mxtoolbox.com/SuperTool.aspx?action=email%3a{IOC}",
    "thatsthem": "https://thatsthem.com/search?q={IOC}",
    "threatconnect": "https://app.threatconnect.com/auth/search/search.xhtml?searchTerm={IOC}",
    "usersearch": "https://usersearch.org/results_email.php?email={IOC}"
  },
  "Sandbox": {
    "anyrun": "https://app.any.run/submissions/?query={IOC}",
    "browserling": "https://www.browserling.com/browse?url={IOC}",
    "hybridanalysis": "https://www.hybrid-analysis.com/sample/{IOC}",
    "joesandbox": "https://www.joesandbox.com/analysis/search?q={IOC}",
    "siteshot": "https://www.site-shot.com/?url={IOC}",
    "triage": "https://tria.ge/s?q={IOC}",
    "urlscan": "https://urlscan.io/search/#{IOC}",
    "virustotal": "https://www.virustotal.com/gui/file/{IOC}"
  },
  "ASN": {
    "bgpview": "https://bgpview.io/asn/{IOC}",
    "censys": "https://censys.io/ipv4/{IOC}",
    "he": "https://bgp.he.net/{IOC}",
    "ipinfo": "https://ipinfo.io/{IOC}"
  },
  "File": {
    "cyberchef": "https://gchq.github.io/CyberChef/?input={IOC}",
    "lolbas": "https://lolbas-project.github.io/#{IOC}",
    "ohthashtools": "https://onlinehashtools.com/?q={IOC}",
    "regex101": "https://regex101.com/?regex={IOC}",
    "dynamitelab": "https://lab.dynamite.ai/?q={IOC}",
    "emntools": "https://emn178.github.io/online-tools/?q={IOC}"
  },
  "Vulnerabilities": {
    "cve": "https://cve.mitre.org/cgi-bin/cvename.cgi?name={IOC}",
    "nvd": "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={IOC}",
    "exploitdb": "https://www.exploit-db.com/search?q={IOC}",
    "cisa": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search={IOC}",
    "osv": "https://osv.dev/list?q={IOC}",
    "recordedfuture": "https://www.recordedfuture.com/vulnerability-database?q={IOC}",
    "snyk": "https://security.snyk.io/vuln?q={IOC}",
    "feedlycve": "https://feedly.com/cve/{IOC}"
  },
  "Blockchain": {
    "bitcoinabuse": "https://www.bitcoinabuse.com/reports/{IOC}",
    "blockchaincom": "https://www.blockchain.com/btc/address/{IOC}",
    "blockchair": "https://blockchair.com/bitcoin/address/{IOC}",
    "blockcypher": "https://live.blockcypher.com/btc/address/{IOC}/",
    "etherscan": "https://etherscan.io/address/{IOC}",
    "ethplorer": "https://ethplorer.io/address/{IOC}"
  },
  "Utilities": {
    "regex101": "https://regex101.com/?regex={IOC}",
    "emntools": "https://emn178.github.io/online-tools/?q={IOC}",
    "cyberchef": "https://gchq.github.io/CyberChef/?input={IOC}",
    "pastebin": "https://pastebin.com/search/{IOC}",
    "grepapp": "https://grep.app/search?q={IOC}",
    "exiftools": "https://exif.tools/?q={IOC}"
  },
  "ThreatIntel": {
    "intelx": "https://intelx.io/?s={IOC}",
    "ooctr": "https://www.occrp.org/en/search?query={IOC}",
    "pulsedive": "https://pulsedive.com/explore/?q={IOC}",
    "threatfox": "https://threatfox.abuse.ch/?q={IOC}",
    "tip": "https://www.threatintelligenceplatform.com/?q={IOC}",
    "spamhaus": "https://www.spamhaus.org/query/ip/{IOC}"
  },
  "Misc": {
    "fast": "https://fast.com/",
    "speedtest": "https://www.speedtest.net/",
    "downdetector": "https://downdetector.com/search/?q={IOC}",
    "isitdownrightnow": "https://www.isitdownrightnow.com/{IOC}.html",
    "isupme": "https://www.isup.me/{IOC}",
    "checkpointthreatmap": "https://threatmap.checkpoint.com/",
    "kasperskycybermap": "https://cybermap.kaspersky.com/",
    "jsonformatter": "https://jsonformatter.org/?data={IOC}"
  }
};

// --- Read selections and osintTools from storage ---
function getSelections(cb) {
  browser.storage.sync.get(['checkedSources', 'checkedSourcesSwiftDraw', 'osintTools'], data => {
    const osintTools = data.osintTools || {};
    const checkedSources = data.checkedSources || {};
    const checkedSourcesSwiftDraw = data.checkedSourcesSwiftDraw || {};
    cb(checkedSources, checkedSourcesSwiftDraw, osintTools);
  });
}

// --- Build context menus ---
function createMenus() {
  getSelections((checkedSources, checkedSourcesSwiftDraw, osintTools) => {
    browser.contextMenus.removeAll(() => {
      // Only create root menu if there are selected tools
      let hasTools = false;
      Object.values(checkedSources).forEach(tools => {
        if (tools.length > 0) hasTools = true;
      });

      if (hasTools) {
        browser.contextMenus.create({
          id: 'root_ioc_swiftdraw',
          title: 'IOC-SwiftDraw Pro',
          contexts: ['selection']
        });
      }

      Object.entries(checkedSources).forEach(([cat, tools]) => {
        if (!tools.length) return;

        // Category submenu under root
        browser.contextMenus.create({
          id: `cat_${cat}`,
          parentId: 'root_ioc_swiftdraw',
          title: cat,
          contexts: ['selection']
        });

        // SwiftDraw submenu
        const bows = checkedSourcesSwiftDraw[cat] || [];
        if (bows.length) {
          browser.contextMenus.create({
            id: `swiftdraw_${cat}`,
            parentId: `cat_${cat}`,
            title: '🏹 SwiftDraw',
            contexts: ['selection']
          });
        }

        // Individual tools
        tools.forEach(key => {
          const toolInfo = (osintTools[cat] || []).find(t => t.key === key);
          const displayName = toolInfo ? toolInfo.name : key.charAt(0).toUpperCase() + key.slice(1);
          browser.contextMenus.create({
            id: `tool_${cat}|${key}`,
            parentId: `cat_${cat}`,
            title: displayName,
            contexts: ['selection']
          });
        });
      });
    });
  });
}

// --- Handle clicks ---
browser.contextMenus.onClicked.addListener((info, tab) => {
  const clean = refang(info.selectionText.trim());
  if (!clean) {
    console.error('No valid IOC selected');
    return;
  }

  getSelections((checkedSources, checkedSourcesSwiftDraw, osintTools) => {
    // SwiftDraw actions
    if (info.menuItemId.startsWith('swiftdraw_')) {
      const cat = info.menuItemId.replace('swiftdraw_', '');
      const tools = checkedSourcesSwiftDraw[cat] || [];
      if (tools.length === 0) {
        console.error(`No SwiftDraw tools selected for category: ${cat}`);
        return;
      }
      tools.forEach(key => {
        const tpl = osintUrls[cat]?.[key];
        if (!tpl) {
          console.error(`No URL template for tool: ${key} in category: ${cat}`);
          return;
        }
        const url = tpl.includes('{IOC}') ? tpl.replace('{IOC}', encodeURIComponent(clean)) : tpl;
        browser.tabs.create({ url }, () => {
          console.log(`Opened URL: ${url}`);
        });
      });
      return;
    }

    // Single tool
    if (info.menuItemId.startsWith('tool_')) {
      const [, payload] = info.menuItemId.split('tool_');
      const [cat, key] = payload.split('|');
      const tpl = osintUrls[cat]?.[key];
      if (!tpl) {
        console.error(`No URL template for tool: ${key} in category: ${cat}`);
        return;
      }
      const url = tpl.includes('{IOC}') ? tpl.replace('{IOC}', encodeURIComponent(clean)) : tpl;
      browser.tabs.create({ url }, () => {
        console.log(`Opened URL: ${url}`);
      });
    }
  });
});

// --- Listeners ---
browser.runtime.onInstalled.addListener(createMenus);
browser.runtime.onStartup.addListener(createMenus);
browser.storage.onChanged.addListener((changes, area) => {
  if (area === 'sync' && (changes.checkedSources || changes.checkedSourcesSwiftDraw || changes.osintTools)) {
    createMenus();
  }
});