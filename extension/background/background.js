// PhishGuardAI: Background neon core
console.log('%cPhishGuardAI: %cBackground Initialized', 'color: green', 'color: #0ff');

let latestData = {
  score: 0,
  url: '',
  domain: '',
  vulnerabilities: [],
  stats: { threats: 0, nodes: 5, uptime: 2 }
};
let settings = {
  realTime: true,
  notifications: true,
  autoBlock: false,
  sensitivity: 'medium'
};
let whitelist = [];

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  console.log('%cPhishGuardAI: %cMessage: %o', 'color: purple', 'color: #0ff', msg);
  if (msg.action === 'analysis') {
    latestData.score = msg.score;
    latestData.url = msg.url;
    latestData.domain = msg.domain;
    latestData.vulnerabilities = msg.vulnerabilities;
    if (msg.score > 0.7 && settings.notifications) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: 'PhishGuardAI Alert',
        message: `Potential phishing site detected: ${msg.domain}`
      });
      latestData.stats.threats++;
    }
    latestData.stats.nodes++;
    chrome.runtime.sendMessage({ action: 'updateAnalysis', ...latestData });
  } else if (msg.action === 'getScore') {
    sendResponse(latestData);
  } else if (msg.action === 'refresh') {
    chrome.runtime.sendMessage({ action: 'analyzePage' });
  } else if (msg.action === 'report') {
    latestData.stats.threats++;
    chrome.runtime.sendMessage({ action: 'showToast', message: 'Threat reported' });
  } else if (msg.action === 'whitelist') {
    if (latestData.domain && !whitelist.includes(latestData.domain)) {
      whitelist.push(latestData.domain);
      chrome.runtime.sendMessage({ action: 'showToast', message: 'Site whitelisted' });
    }
  } else if (msg.action === 'addWhitelist') {
    if (msg.domain && !whitelist.includes(msg.domain)) {
      whitelist.push(msg.domain);
      chrome.runtime.sendMessage({ action: 'showToast', message: `Whitelisted: ${msg.domain}` });
    }
  } else if (msg.action === 'saveSettings') {
    settings = msg.settings;
    chrome.runtime.sendMessage({ action: 'showToast', message: 'Settings saved' });
  }
});
