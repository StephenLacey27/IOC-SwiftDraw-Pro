// options.js
// IOC-SwiftDraw Pro Options Script: Tool & SwiftDraw Pro Loadout Configuration

const CATEGORIES = {
  ip: [
    "AbuseIPDB", "AlienVault OTX", "ARIN", "BlacklistMaster", "FortiGuard", "GreyNoise",
    "HackerTarget", "IPInfo", "IPVoid", "IPQualityScore", "MXToolbox", "Pulsedive",
    "Scamalytics", "SecurityTrails", "Shodan", "Spur.us", "Spyse", "Talos",
    "ThreatCrowd", "ThreatMiner", "Tor Relay Search", "URLhaus", "VirusTotal", "X-Force"
  ],
  domain: [
    "Alexa", "Bluecoat", "Censys", "FortiGuard", "Host.io", "MXToolbox", "Pulsedive",
    "SecurityTrails", "Shodan", "Spyse", "Talos", "ThreatCrowd", "ThreatMiner",
    "Tor Relay Search", "URLhaus", "VirusTotal", "X-Force", "SSL Labs"
  ],
  hash: [
    "AlienVault OTX", "Hybrid Analysis", "MalShare", "Talos",
    "ThreatMiner", "URLhaus", "VirusTotal", "X-Force"
  ],
  url: [
    "Any.Run", "Bluecoat", "FortiGuard", "Hackertarget Extract Links",
    "Sucuri SiteCheck", "TrendMicro Site Safety", "URLhaus", "VirusTotal",
    "X-Force", "Zscaler Zulu"
  ],
  email: [
    "ICANN WHOIS Lookup", "Have I Been Pwned", "MXToolbox"
  ],
  sandbox: [
    "ANY.RUN", "Joe Sandbox", "Triage", "Browserling", "Siteshot", "URLScan"
  ]
};

function menuKey(cat) { return `${cat}_menu`; }
function swiftdrawKey(cat) { return `${cat}_swiftdraw`; }

// Build the options UI dynamically
function buildUI() {
  // <-- Updated line to match your HTML -->
  const container = document.getElementById('swift-categories');
  container.innerHTML = '';

  Object.entries(CATEGORIES).forEach(([cat, tools]) => {
    const section = document.createElement('fieldset');
    section.innerHTML = `
      <legend>${cat.toUpperCase()}</legend>
      <table>
        <thead>
          <tr>
            <th>📄 OSINT Sources</th>
            <th>🏹 SwiftDraw Pro Loadout</th>
          </tr>
        </thead>
        <tbody>
          ${tools.map(tool => `
            <tr>
              <td><input type="checkbox" data-key="${menuKey(cat)}" value="${tool}"> ${tool}</td>
              <td><input type="checkbox" data-key="${swiftdrawKey(cat)}" value="${tool}"></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
    container.appendChild(section);
  });
}

// Restore saved settings into the UI
function restoreOptions() {
  buildUI();
  chrome.storage.sync.get(null, data => {
    Object.entries(data).forEach(([key, values]) => {
      if (!Array.isArray(values)) return;
      values.forEach(val => {
        const selector = `input[data-key="${key}"][value="${val}"]`;
        const checkbox = document.querySelector(selector);
        if (checkbox) checkbox.checked = true;
      });
    });
  });
}

// Save current selections
function saveOptions(event) {
  event.preventDefault();
  const inputs = document.querySelectorAll('input[type=checkbox]');
  const toSave = {};
  inputs.forEach(cb => {
    const key = cb.getAttribute('data-key');
    if (!toSave[key]) toSave[key] = [];
    if (cb.checked) toSave[key].push(cb.value);
  });
  chrome.storage.sync.set(toSave, () => {
    const status = document.getElementById('status');
    status.textContent = 'Settings saved.';
    setTimeout(() => status.textContent = '', 3000);
  });
}

// Event listeners
document.addEventListener('DOMContentLoaded', restoreOptions);
document.getElementById('options-form').addEventListener('submit', saveOptions);
