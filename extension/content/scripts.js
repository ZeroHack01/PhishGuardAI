const logStyles = {
  cyan: 'color: #00f7ff; font-family: "Courier New", monospace; font-weight: bold;',
  magenta: 'color: #ff00ff; font-family: "Courier New", monospace; font-weight: bold;',
  green: 'color: #00ff00; font-family: "Courier New", monospace; font-weight: bold;',
  red: 'color: #ff0000; font-family: "Courier New", monospace; font-weight: bold;'
};

function log(message, style = 'cyan') {
  console.log(`%c[PhishGuardAI Content] ${message}`, logStyles[style]);
}

function analyzePage() {
  log('Starting page analysis...', 'cyan');
  const features = {
    hasLoginForm: document.querySelectorAll('form input[type="password"]').length > 0,
    suspiciousKeywords: ['login', 'password', 'verify', 'account'].some(keyword =>
      document.body.innerText.toLowerCase().includes(keyword)),
    urlEntropy: calculateUrlEntropy(window.location.href),
    externalLinks: document.querySelectorAll('a[href^="http"]').length
  };
  log(`Extracted features: ${JSON.stringify(features)}`, 'magenta');

  // Placeholder scoring (to be replaced by TensorFlow.js model)
  let score = 0;
  if (features.hasLoginForm) score += 0.4;
  if (features.suspiciousKeywords) score += 0.3;
  if (features.urlEntropy > 4) score += 0.2;
  if (features.externalLinks > 5) score += 0.1;

  score = Math.min(Math.max(score, 0), 1);
  log(`Calculated threat score: ${score.toFixed(2)}`, 'green');
  return score;
}

function calculateUrlEntropy(url) {
  const chars = url.split('');
  const freq = {};
  chars.forEach(c => freq[c] = (freq[c] || 0) + 1);
  const length = chars.length;
  let entropy = 0;
  for (let c in freq) {
    const p = freq[c] / length;
    entropy -= p * Math.log2(p);
  }
  log(`URL entropy: ${entropy.toFixed(2)}`, 'magenta');
  return entropy;
}

function monitorDynamicContent() {
  log('Setting up MutationObserver for dynamic content', 'cyan');
  const observer = new MutationObserver((mutations) => {
    mutations.forEach(mutation => {
      if (mutation.addedNodes.length) {
        log('Detected DOM changes, re-analyzing...', 'magenta');
        const score = analyzePage();
        chrome.runtime.sendMessage({ action: 'analysis', score });
      }
    });
  });
  observer.observe(document.body, { childList: true, subtree: true });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  log(`Received message: ${request.action}`, 'cyan');
  if (request.action === 'analyze') {
    const score = analyzePage();
    sendResponse({ score });
    chrome.runtime.sendMessage({ action: 'analysis', score });
  }
  return true; // Keep message channel open for async response
});

document.addEventListener('DOMContentLoaded', () => {
  log('PhishGuardAI Content Script Initialized', 'cyan');
  const score = analyzePage();
  chrome.runtime.sendMessage({ action: 'analysis', score });
  monitorDynamicContent();
});
