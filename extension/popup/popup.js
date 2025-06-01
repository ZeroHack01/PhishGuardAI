// PhishGuardAI Popup: Neon control center
console.log('%cPhishGuardAI: %cPopup Initialized', 'color: magenta', 'color: #0ff');

// Matrix Canvas Animation
const canvas = document.getElementById('matrixCanvas');
const ctx = canvas.getContext('2d');
canvas.width = 400;
canvas.height = 600;
const chars = '01@#AI';
const fontSize = 10;
const columns = canvas.width / fontSize;
const drops = Array(Math.floor(columns)).fill(1);

function drawMatrix() {
  ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#0ff';
  ctx.font = `${fontSize}px 'JetBrains Mono'`;
  drops.forEach((y, i) => {
    const text = chars[Math.floor(Math.random() * chars.length)];
    ctx.fillText(text, i * fontSize, y * fontSize);
    if (y * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
    drops[i]++;
  });
}
setInterval(drawMatrix, 0);

// Threat Analysis
function updateAnalysis(score, url, domain, vulnerabilities = []) {
  const riskScore = Math.round(score * 100);
  document.getElementById('riskScore').textContent = riskScore;
  document.getElementById('riskGaugeFill').style.transform = `rotate(${Math.min(score, 1) * 180}deg)`;
  document.getElementById('urlDomain').textContent = domain || 'N/A';
  document.getElementById('urlProtocol').textContent = url?.startsWith('http://') ? 'http://' : 'https://';
  document.getElementById('targetStatus').textContent = score > 0.7 ? 'HIGH_RISK' : score > 0.3 ? 'MODERATE_RISK' : 'LOW';
  document.getElementById('statusText').textContent = score > 0.7 ? 'ALERT' : 'STABLE';
  document.getElementById('threatLevel').textContent = score > 0.7 ? 'HIGH_THREAT' : score > 0.3 ? 'MODERATE_THREAT' : 'NO';
  const threatContent = document.getElementById('threatContent');
  threatContent.innerHTML = '';
  if (vulnerabilities.length > 0) {
    document.getElementById('vulnerabilities').style.display = 'block';
    const vulnList = document.getElementById('vulnList');
    vulnList.innerHTML = vulnerabilities.map(v => `<div class="vuln">${v}</div>`).join('');
  } else {
    threatContent.textContent = 'NO_VULNERABILITIES';
  }
}

// Fetch Initial Data
function fetchData() {
  chrome.runtime.sendMessage({ action: 'getScore' }, response => {
    if (response.status) {
      updateAnalysis(response.score, response.url, response.domain, response.vulnerabilities);
      document.getElementById('threatsNeutralized').textContent = response.stats?.threats || 0;
      document.getElementById('nodesScanned').textContent = response.stats?.nodes || 0;
      document.getElementById('uptime').textContent = response.stats?.uptime || 0;
    }
  });
}
fetchData();

// Button Events
document.getElementById('refreshAnalysis').addEventListener('click', () => {
  console.log('%cPhishGuardAI: %cRescan', 'color: cyan', 'color: #0ff');
  chrome.runtime.sendMessage({ action: 'refresh' });
  fetchData();
});
document.getElementById('reportThreatBtn').addEventListener('click', () => {
  console.log('%cPhishGuardAI: %cThreat Reported', 'color: green', 'color: red');
  chrome.runtime.sendMessage({ action: 'report' });
  addLogEntry('REPORT', 'Threat reported');
});
document.getElementById('whitelistBtn').addEventListener('click', () => {
  console.log('%cPhishGuardAI: %cSite Whitelisted', 'color: green', 'color: #0ff');
  chrome.runtime.sendMessage({ action: 'whitelist' });
  addLogEntry('WHITELIST', 'Site added to trusted nodes');
});

// Modal Controls
document.getElementById('configBtn').addEventListener('click', () => {
  document.getElementById('settingsModal').classList.add('active');
});
document.getElementById('aboutBtn').addEventListener('click', () => {
  document.getElementById('aboutModal').classList.add('active');
});
document.getElementById('closeSettingsBtn').addEventListener('click', () => {
  document.getElementById('settingsModal').classList.remove('active');
});
document.getElementById('closeAboutBtn').addEventListener('click', () => {
  document.getElementById('aboutModal').classList.remove('active');
});

// Settings
const settings = {
  realTime: true,
  notifications: true,
  autoBlock: false,
  sensitivity: 'medium'
};
document.getElementById('enableRealTime').checked = settings.realTime;
document.getElementById('enableNotifications').checked = settings.notifications;
document.getElementById('enableAutoBlock').checked = settings.autoBlock;
document.getElementById('protectionLevel').value = settings.sensitivity;

document.getElementById('saveConfigBtn').addEventListener('click', () => {
  settings.realTime = document.getElementById('enableRealTime').checked;
  settings.notifications = document.getElementById('enableNotifications').checked;
  settings.autoBlock = document.getElementById('enableAutoBlock').checked;
  settings.sensitivity = document.getElementById('protectionLevel').value;
  chrome.runtime.sendMessage({ action: 'saveSettings', settings });
  addLogEntry('CONFIG', 'Settings saved');
  document.getElementById('settingsModal').classList.remove('active');
});
document.getElementById('resetConfigBtn').addEventListener('click', () => {
  settings.realTime = true;
  settings.notifications = true;
  settings.autoBlock = false;
  settings.sensitivity = 'medium';
  document.getElementById('enableRealTime').checked = true;
  document.getElementById('enableNotifications').checked = true;
  document.getElementById('enableAutoBlock').checked = false;
  document.getElementById('protectionLevel').value = 'medium';
  addLogEntry('CONFIG', 'Settings reset');
});

// Whitelist
document.getElementById('addWhitelistBtn').addEventListener('click', () => {
  const domain = document.getElementById('whitelistInput').value.trim();
  if (domain) {
    chrome.runtime.sendMessage({ action: 'addWhitelist', domain });
    const nodes = document.getElementById('trustedNodes');
    nodes.innerHTML = '';
    nodes.appendChild(document.createElement('div')).textContent = domain;
    document.getElementById('whitelistInput').value = '';
    addLogEntry('WHITELIST', `Added ${domain}`);
  }
});

// Log Entries
function addLogEntry(level, message) {
  const logContent = document.getElementById('threatLogContent');
  const entry = document.createElement('div');
  entry.className = `log-entry system-entry ${level.toLowerCase()}`;
  entry.innerHTML = `
    <span class="log-time">[${new Date().toLocaleTimeString()}]</span>
    <span class="log-level ${level.toLowerCase()}">${level}</span>
    <span class="log-message">${message}</span>
  `;
  logContent.appendChild(entry);
  logContent.scrollTop = logContent.scrollHeight;
}

document.getElementById('clearLogBtn').addEventListener('click', () => {
  document.getElementById('threatLogContent').innerHTML = '';
  addLogEntry('INFO', 'Logs cleared');
});

// Toast Notifications
function showToast(message) {
  const toast = document.createElement('div');
  toast.className = 'matrix-toast';
  toast.textContent = message;
  document.getElementById('toastMatrix').appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

// External Links
document.getElementById('visitMatrixBtn').addEventListener('click', () => {
  window.open('https://phishguard.ai', '_blank');
});
document.getElementById('viewCodeBtn').addEventListener('click', () => {
  window.open('https://github.com/ZeroHack01/PhishGuardAI', '_blank');
});

// Listen for background.js updates
chrome.runtime.onMessage.addEventListener('click', (msg) => {
  if (msg.action === 'updateAnalysis') {
    updateAnalysis(msg.score, msg.url, msg.domain, msg.vulnerabilities);
  } else if (msg.action === 'showToast') {
    showToast(msg.message);
  }
});
