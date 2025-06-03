// background.js

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
  const ipPattern   = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const hashPattern = /^[A-Fa-f0-9]{32,128}$/;
  if (ipPattern.test(ioc))        return 'ip';
  if (hashPattern.test(ioc))      return 'hash';
  if (/^https?:\/\//i.test(ioc))  return 'url';
  return 'domain';
}

// --- Full OSINT URL templates ---
const osintUrls = {
  "IP": {
    "abuseipdb":       "https://www.abuseipdb.com/check/{IOC}",
    "alienvault":      "https://otx.alienvault.com/indicator/ip/{IOC}",
    "arin":            "https://search.arin.net/rdap/?query={IOC}",
    "blacklistmaster": "https://www.blacklistmaster.com/check?t={IOC}",
    "bgpview":         "https://bgpview.io/ip/{IOC}",
    "censys":          "https://censys.io/ipv4/{IOC}",
    "dnslytics":       "https://dnslytics.com/ip/{IOC}",
    "greynoise":       "https://www.greynoise.io/viz/ip/{IOC}",
    "hackertarget":    "https://hackertarget.com/reverse-ip-lookup/?q={IOC}",
    "he":              "https://bgp.he.net/ip/{IOC}",
    "ipinfo":          "https://ipinfo.io/{IOC}",
    "ipvoid":          "https://www.ipvoid.com/ip-address/{IOC}",
    "mxtoolbox":       "https://mxtoolbox.com/",
    "onyphe":          "https://search.onyphe.io/search?q=category%3Adatascan+{IOC}",
    "otx":             "https://otx.alienvault.com/indicator/ip/{IOC}",
    "pulsedive":       "https://pulsedive.com/explore/?q={IOC}",
    "robtex":          "https://www.robtex.com/ip/{IOC}",
    "scamalytics":     "https://scamalytics.com/ip/{IOC}",
    "securitytrails":  "https://securitytrails.com/list/ip/{IOC}",
    "shodan":          "https://www.shodan.io/host/{IOC}",
    "spur":            "https://app.spur.us/search?q={IOC}",
    "talos":           "https://talosintelligence.com/reputation_center/lookup?search={IOC}",
    "threatminer":     "https://www.threatminer.org/host.php?q={IOC}",
    "torrelay":        "https://metrics.torproject.org/ip/{IOC}.json",
    "urlhaus":         "https://urlhaus.abuse.ch/browse.php?search={IOC}",
    "virustotal":      "https://www.virustotal.com/gui/ip-address/{IOC}",
    "xforceexchange":  "https://exchange.xforce.ibmcloud.com/ip/{IOC}",
    "zoomeye":         "https://www.zoomeye.org/searchResult?q=ip:{IOC}"
  },
  "Domain": {
    "bluecoat":       "https://sitereview.bluecoat.com/#/lookup-result/{IOC}",
    "censys":         "https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q={IOC}",
    "hostio":         "https://host.io/{IOC}",
    "mxtoolbox":      "https://mxtoolbox.com/",
    "pulsedive":      "https://pulsedive.com/explore/?q=domain%2F{IOC}",
    "securitytrails": "https://securitytrails.com/domain/{IOC}",
    "shodan":         "https://www.shodan.io/search?query={IOC}",
    "talos":          "https://talosintelligence.com/reputation_center/lookup?search={IOC}",
    "threatminer":    "https://www.threatminer.org/domain.php?q={IOC}",
    "urlhaus":        "https://urlhaus.abuse.ch/browse.php?search={IOC}",
    "virustotal":     "https://www.virustotal.com/gui/domain/{IOC}",
    "xforceexchange": "https://exchange.xforce.ibmcloud.com/url/{IOC}"
  },
  "Hash": {
    "ohthashtools":   "https://onlinehashtools.com",
    "alienvault":     "https://otx.alienvault.com/indicator/file/{IOC}",
    "hybridanalysis": "https://www.hybrid-analysis.com/sample/{IOC}",
    "joesandbox":     "https://www.joesandbox.com/analysis/search?q={IOC}",
    "malshare":       "https://malshare.com/sample.php?action=detail&hash={IOC}",
    "malwarebazaar":  "https://bazaar.abuse.ch/sample/{IOC}/",
    "threatminer":    "https://www.threatminer.org/sample.php?q={IOC}",
    "virustotal":     "https://www.virustotal.com/gui/file/{IOC}",
    "xforceexchange": "https://exchange.xforce.ibmcloud.com/malware/{IOC}"
  },
  "URL": {
    "anyrun":         "https://app.any.run/",
    "archive_today":  "https://archive.today/",
    "archive_org":    "https://web.archive.org/",
    "bluecoat":       "https://sitereview.bluecoat.com/#/lookup-result/{IOC}",
    "browserling":    "https://www.browserling.com/",
    "checkphish":     "https://checkphish.ai/",
    "hybridanalysis": "https://www.hybrid-analysis.com/search?query={IOC}",
    "otx":            "https://otx.alienvault.com/indicator/url/{IOC}",
    "pulsedive":      "https://pulsedive.com/explore/?q={IOC}",
    "sucuri":         "https://sitecheck.sucuri.net/results/{IOC}",
    "urlhaus":        "https://urlhaus.abuse.ch/browse.php?search={IOC}",
    "urlscan":        "https://urlscan.io/",
    "virustotal":     "https://www.virustotal.com/gui/domain/{IOC}",
    "xforceexchange": "https://exchange.xforce.ibmcloud.com/url/{IOC}",
    "zscaler":        "https://zulu.zscaler.com/"
  },
  "Email": {
    "emailrep":       "https://emailrep.io/{IOC}",
    "hibp":           "https://haveibeenpwned.com/account/{IOC}",
    "icann":          "https://lookup.icann.org/en/lookup?name={IOC}",
    "mxtoolbox":      "https://mxtoolbox.com/",
    "thatsthem":      "https://thatsthem.com/search?q={IOC}",
    "threatconnect":  "https://app.threatconnect.com/",
    "usersearch":     "https://usersearch.org/"
  },
  "Sandbox": {
    "anyrun":         "https://app.any.run/",
    "browserling":    "https://www.browserling.com/",
    "hybridanalysis": "https://www.hybrid-analysis.com/sample/{IOC}",
    "joesandbox":     "https://www.joesandbox.com/analysis/search?q={IOC}",
    "siteshot":       "https://www.site-shot.com/",
    "triage":         "https://tria.ge/",
    "urlscan":        "https://urlscan.io/",
    "virustotal":     "https://www.virustotal.com/gui/file/{IOC}"
  },
  "ASN": {
    "bgpview":        "https://bgpview.io/asn/{IOC}",
    "censys":         "https://censys.io/ipv4/{IOC}",
    "he":             "https://bgp.he.net/{IOC}",
    "ipinfo":         "https://ipinfo.io/{IOC}"
  },
  "File": {
    "cyberchef":      "https://gchq.github.io/CyberChef/",
    "lolbas":         "https://lolbas-project.github.io/#{IOC}",
    "ohthashtools":   "https://onlinehashtools.com",
    "regex101":       "https://regex101.com/",
    "dynamitelab":    "https://lab.dynamite.ai/",
    "emntools":       "https://emn178.github.io/online-tools"
  },
  "Vulnerabilities": {
    "cve":             "https://cve.mitre.org/",
    "nvd":             "https://nvd.nist.gov/",
    "exploitdb":       "https://www.exploit-db.com/",
    "cisa":            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "osv":             "https://osv.dev/list",
    "recordedfuture":  "https://www.recordedfuture.com/vulnerability-database",
    "snyk":            "https://security.snyk.io/",
    "feedlycve":       "https://feedly.com/cve"
  },
  "Blockchain": {
    "bitcoinabuse":    "https://www.bitcoinabuse.com/reports/{IOC}",
    "blockchaincom":   "https://www.blockchain.com/btc/address/{IOC}",
    "blockchair":      "https://blockchair.com/bitcoin/address/{IOC}",
    "blockcypher":     "https://live.blockcypher.com/btc/address/{IOC}/",
    "etherscan":       "https://etherscan.io/address/{IOC}",
    "ethplorer":       "https://ethplorer.io/address/{IOC}"
  },
  "Utilities": {
    "regex101":        "https://regex101.com/",
    "emntools":        "https://emn178.github.io/online-tools",
    "cyberchef":       "https://gchq.github.io/CyberChef/",
    "pastebin":        "https://pastebin.com/",
    "grepapp":         "https://grep.app/search?q={IOC}",
    "exiftools":       "https://exif.tools/"
  },
  "ThreatIntel": {
    "intelx":          "https://intelx.io/?s={IOC}",
    "ooctr":           "https://www.occrp.org/",
    "pulsedive":       "https://pulsedive.com/explore/?q={IOC}",
    "threatfox":       "https://threatfox.abuse.ch/",
    "tip":             "https://www.threatintelligenceplatform.com/",
    "spamhaus":        "https://www.spamhaus.org/query/ip/{IOC}"
  },
  "Misc": {
    "fast":            "https://fast.com/",
    "speedtest":       "https://www.speedtest.net/",
    "downdetector":    "https://downdetector.com/",
    "isitdownrightnow":"https://www.isitdownrightnow.com/",
    "isupme":          "https://www.isup.me/",
    "checkpointthreatmap":"https://threatmap.checkpoint.com/",
    "kasperskycybermap":"https://cybermap.kaspersky.com/",
    "jsonformatter":   "https://jsonformatter.org/"
  }
};

// --- Read selections from storage ---
function getSelections(cb) {
  chrome.storage.sync.get(['checkedSources','checkedSourcesSwiftDraw'], data => {
    cb(data.checkedSources || {}, data.checkedSourcesSwiftDraw || {});
  });
}

// --- Build context menus ---
function createMenus() {
  getSelections((checkedSources, checkedSourcesSwiftDraw) => {
    chrome.contextMenus.removeAll(() => {
      Object.entries(checkedSources).forEach(([cat, tools]) => {
        if (!tools.length) return;

        // Category header
        chrome.contextMenus.create({
          id: `cat_${cat}`,
          title: cat,
          contexts: ['selection']
        });

        // SwiftDraw submenu
        const bows = checkedSourcesSwiftDraw[cat] || [];
        if (bows.length) {
          chrome.contextMenus.create({
            id: `swiftdraw_${cat}`,
            parentId: `cat_${cat}`,
            title: '🏹 SwiftDraw',
            contexts: ['selection']
          });
        }

        // Individual tools
        tools.forEach(key => {
          const title = key.charAt(0).toUpperCase() + key.slice(1);
          chrome.contextMenus.create({
            id: `tool_${cat}|${key}`,
            parentId: `cat_${cat}`,
            title,
            contexts: ['selection']
          });
        });
      });
    });
  });
}

// --- Handle clicks ---
chrome.contextMenus.onClicked.addListener(info => {
  const clean = refang(info.selectionText.trim());
  const type  = detectType(clean);

  getSelections((checkedSources, checkedSourcesSwiftDraw) => {
    // SwiftDraw actions
    if (info.menuItemId.startsWith('swiftdraw_')) {
      const cat = info.menuItemId.split('_')[1];
      (checkedSourcesSwiftDraw[cat] || []).forEach(key => {
        const tpl = osintUrls[cat] && osintUrls[cat][key];
        if (tpl) {
          const url = tpl.replace('{IOC}', encodeURIComponent(clean));
          chrome.tabs.create({ url });
        }
      });
      return;
    }

    // Single tool
    if (info.menuItemId.startsWith('tool_')) {
      const [, payload] = info.menuItemId.split('tool_');
      const [cat, key]  = payload.split('|');
      const tpl = osintUrls[cat] && osintUrls[cat][key];
      if (tpl) {
        const url = tpl.replace('{IOC}', encodeURIComponent(clean));
        chrome.tabs.create({ url });
      }
    }
  });
});

// --- Listeners ---
chrome.runtime.onInstalled.addListener(createMenus);
chrome.runtime.onStartup.addListener(createMenus);
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'sync' &&
      (changes.checkedSources || changes.checkedSourcesSwiftDraw)) {
    createMenus();
  }
});
