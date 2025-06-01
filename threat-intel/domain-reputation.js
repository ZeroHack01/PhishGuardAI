const logStyles = {
  cyan: 'color: #00f7ff; font-family: "Courier New", monospace; font-weight: bold;',
  magenta: 'color: #ff00ff; font-family: "Courier New", monospace; font-weight: bold;',
  green: 'color: #00ff00; font-family: "Courier New", monospace; font-weight: bold;',
  red: 'color: #ff0000; font-family: "Courier New", monospace; font-weight: bold;'
};

function log(message, style = 'cyan') {
  console.log(`%c[PhishGuardAI Domain Reputation] ${message}`, logStyles[style]);
}

function getDomainFromUrl(url) {
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname;
    log(`Extracted domain: ${domain}`, 'cyan');
    return domain;
  } catch (e) {
    log(`Error parsing URL ${url}: ${e.message}`, 'red');
    return null;
  }
}

function simulateApiCheck(domain) {
  // Simulated API response for testing (replace with real API like VirusTotal in production)
  log(`Simulating API check for ${domain}`, 'cyan');
  const knownMalicious = ['phish.example.com', 'malicious.site'];
  const isMalicious = knownMalicious.some(mal => domain.includes(mal));
  const score = isMalicious ? 0.9 : 0.1; // High score for malicious, low for safe
  log(`Simulated reputation score for ${domain}: ${score.toFixed(2)}`, 'green');
  return { score, success: true };
}

async function checkReputationApi(domain) {
  log(`Checking reputation for ${domain}`, 'magenta');
  try {
    // Placeholder for real API (e.g., VirusTotal, Google Safe Browsing)
    // const response = await fetch(`https://api.virustotal.com/v3/domains/${domain}`, {
    //   headers: { 'x-apikey': 'YOUR_API_KEY' }
    // });
    // const data = await response.json();
    // return { score: data.malicious ? 0.9 : 0.1, success: true };

    // Use simulated response for completeness
    return simulateApiCheck(domain);
  } catch (e) {
    log(`API error for ${domain}: ${e.message}`, 'red');
    return { score: 0.5, success: false, error: e.message };
  }
}

async function cacheReputation(domain, result) {
  log(`Caching reputation for ${domain}`, 'cyan');
  try {
    const cache = await new Promise(resolve => {
      chrome.storage.local.get(['domainCache'], data => resolve(data.domainCache || {}));
    });
    cache[domain] = { ...result, timestamp: Date.now() };
    await new Promise(resolve => {
      chrome.storage.local.set({ domainCache: cache }, () => {
        log(`Cached reputation for ${domain}: ${result.score.toFixed(2)}`, 'green');
        resolve();
      });
    });
  } catch (e) {
    log(`Error caching reputation: ${e.message}`, 'red');
  }
}

async function getCachedReputation(domain) {
  log(`Checking cache for ${domain}`, 'cyan');
  try {
    const cache = await new Promise(resolve => {
      chrome.storage.local.get(['domainCache'], data => resolve(data.domainCache || {}));
    });
    const cached = cache[domain];
    if (cached && Date.now() - cached.timestamp < 24 * 60 * 60 * 1000) { // 24-hour TTL
      log(`Cache hit for ${domain}: ${cached.score.toFixed(2)}`, 'green');
      return cached;
    }
    return null;
  } catch (e) {
    log(`Error accessing cache: ${e.message}`, 'red');
    return null;
  }
}

async function checkDomainReputation(url) {
  const domain = getDomainFromUrl(url);
  if (!domain) {
    return { score: 0.5, success: false, error: 'Invalid URL' };
  }

  // Check cache first
  const cached = await getCachedReputation(domain);
  if (cached) {
    return cached;
  }

  // Query API and cache result
  const result = await checkReputationApi(domain);
  if (result.success) {
    await cacheReputation(domain, result);
  }
  return result;
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  log(`Received message: ${request.action}`, 'cyan');
  if (request.action === 'checkReputation') {
    checkDomainReputation(request.url).then(result => {
      sendResponse(result);
    });
    return true; // Keep channel open for async response
  }
});

chrome.runtime.onInstalled.addListener(() => {
  log('Initializing domain reputation system', 'cyan');
  chrome.storage.local.set({ domainCache: {} }, () => {
    log('Domain cache initialized', 'green');
  });
});
