const DEBUG = false; // Toggle for production (set via build config or extension settings)

const logStyles = {
  cyan: 'color: #00f7ff; font-family: "Courier New", monospace; font-weight: bold;',
  magenta: 'color: #ff00ff; font-family: "Courier New", monospace; font-weight: bold;',
  green: 'color: #00ff00; font-family: "Courier New", monospace; font-weight: bold;',
  red: 'color: #ff0000; font-family: "Courier New", monospace; font-weight: bold;'
};

function log(message, style = 'cyan') {
  if (DEBUG) {
    console.log(`%c[PhishGuardAI Content] ${message}`, logStyles[style]);
  }
}

// List of trusted domains to reduce false positives
const trustedDomains = [
  'bankofamerica.com',
  'paypal.com',
  'google.com',
  'microsoft.com'
];

// Check if the current domain is trusted
function isTrustedDomain() {
  return trustedDomains.some(domain => window.location.hostname.includes(domain));
}

// Calculate URL entropy based on pathname for more reliable phishing detection
function calculateUrlEntropy(url) {
  try {
    const parsedUrl = new URL(url).pathname; // Focus on path, exclude query params
    if (parsedUrl.length < 5) {
      log('URL too short for entropy calculation', 'magenta');
      return 0;
    }
    const chars = parsedUrl.split('');
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
  } catch (error) {
    log(`Error calculating URL entropy: ${error.message}`, 'red');
    return 0;
  }
}

// Analyze page for phishing indicators
function analyzePage() {
  log('Starting page analysis...', 'cyan');

  // Check if domain is trusted to skip analysis
  if (isTrustedDomain()) {
    log('Trusted domain detected, skipping analysis', 'green');
    return 0;
  }

  if (!document.body) {
    log('Document body not available', 'red');
    return 0;
  }

  try {
    const features = {
      hasLoginForm: document.querySelectorAll('form input[type="password"]').length > 0,
      suspiciousKeywords: ['login', 'password', 'verify', 'account'].some(keyword =>
        document.body.innerText.toLowerCase().includes(keyword)),
      urlEntropy: calculateUrlEntropy(window.location.href),
      externalLinks: document.querySelectorAll('a[href^="http"]').length
    };
    log(`Extracted features: ${JSON.stringify(features, null, 2)}`, 'magenta');

    // Placeholder scoring (to be replaced by TensorFlow.js model)
    let score = 0;
    if (features.hasLoginForm) score += 0.4;
    if (features.suspiciousKeywords) score += 0.3;
    if (features.urlEntropy > 4) score += 0.2;
    if (features.externalLinks > 5) score += 0.1;

    score = Math.min(Math.max(score, 0), 1);
    log(`Calculated threat score: ${score.toFixed(2)}`, 'green');

    /*
    // Future TensorFlow.js integration (example)
    // Requires: <script src="https://cdn.jsdelivr.net/npm/@tensorflow/tfjs@latest"></script> in manifest.json
    async function loadModelAndPredict(features) {
      try {
        const model = await tf.loadLayersModel('path/to/model.json');
        const input = tf.tensor([[
          features.hasLoginForm ? 1 : 0,
          features.suspiciousKeywords ? 1 : 0,
          features.urlEntropy,
          features.externalLinks
        ]]);
        const prediction = model.predict(input);
        const score = prediction.dataSync()[0];
        input.dispose();
        prediction.dispose();
        return score;
      } catch (error) {
        log(`Error loading model: ${error.message}`, 'red');
        return 0;
      }
    }
    // const score = await loadModelAndPredict(features);
    */

    return score;
  } catch (error) {
    log(`Error in page analysis: ${error.message}`, 'red');
    return 0;
  }
}

// Monitor dynamic content changes with MutationObserver
function monitorDynamicContent() {
  if (!window.MutationObserver) {
    log('MutationObserver not supported, dynamic monitoring disabled', 'red');
    return;
  }

  log('Setting up MutationObserver for dynamic content', 'cyan');
  let lastAnalysis = 0;
  const throttleMs = 1000; // Throttle analysis to once per second

  const observer = new MutationObserver((mutations) => {
    if (Date.now() - lastAnalysis < throttleMs) return; // Throttle
    lastAnalysis = Date.now();

    mutations.forEach(mutation => {
      if (mutation.addedNodes.length) {
        log('Detected DOM changes, re-analyzing...', 'magenta');
        const score = analyzePage();
        try {
          chrome.runtime.sendMessage({ action: 'analysis', score }, (response) => {
            if (chrome.runtime.lastError) {
              log(`Messaging error: ${chrome.runtime.lastError.message}`, 'red');
            }
          });
        } catch (error) {
          log(`Error sending message: ${error.message}`, 'red');
        }
      }
    });
  });

  try {
    const target = document.querySelector('form') || document.body;
    observer.observe(target, { childList: true, subtree: true });
  } catch (error) {
    log(`Error setting up MutationObserver: ${error.message}`, 'red');
  }
}

// Handle messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  log(`Received message: ${request.action}`, 'cyan');
  if (request.action === 'analyze') {
    try {
      const score = analyzePage();
      sendResponse({ score });
      chrome.runtime.sendMessage({ action: 'analysis', score }, (response) => {
        if (chrome.runtime.lastError) {
          log(`Messaging error: ${chrome.runtime.lastError.message}`, 'red');
        }
      });
    } catch (error) {
      log(`Error handling analyze message: ${error.message}`, 'red');
      sendResponse({ score: 0 });
    }
  }
  return true; // Keep message channel open for async response
});

// Initialize on DOM content loaded
document.addEventListener('DOMContentLoaded', () => {
  log('PhishGuardAI Content Script Initialized', 'cyan');
  try {
    const score = analyzePage();
    chrome.runtime.sendMessage({ action: 'analysis', score }, (response) => {
      if (chrome.runtime.lastError) {
        log(`Messaging error: ${chrome.runtime.lastError.message}`, 'red');
      }
    });
    monitorDynamicContent();
  } catch (error) {
    log(`Initialization error: ${error.message}`, 'red');
  }
});
