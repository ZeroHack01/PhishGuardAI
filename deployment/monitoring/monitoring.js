const logStyles = {
  cyan: 'color: #00f7ff; font-family: "Courier New", monospace; font-weight: bold;',
  magenta: 'color: #ff00ff; font-family: "Courier New", monospace; font-weight: bold;',
  green: 'color: #00ff00; font-family: "Courier New", monospace; font-weight: bold;',
  red: 'color: #ff0000; font-family: "Courier New", monospace; font-weight: bold;'
};

function log(message, style = 'cyan') {
  console.log(`%c[PhishGuardAI Analytics] ${message}`, logStyles[style]);
}

// Simple hash function for anonymizing URLs
function hashUrl(url) {
  let hash = 0;
  for (let i = 0; i < url.length; i++) {
    const char = url.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return hash.toString(16);
}

async function recordEvent(eventType, data = {}) {
  log(`Recording event: ${eventType}`, 'cyan');
  try {
    const event = {
      type: eventType,
      timestamp: Date.now(),
      data: { ...data, urlHash: data.url ? hashUrl(data.url) : null }
    };
    const metrics = await new Promise(resolve => {
      chrome.storage.local.get(['analytics'], data => resolve(data.analytics || []));
    });
    metrics.push(event);
    await new Promise(resolve => {
      chrome.storage.local.set({ analytics: metrics }, () => {
        log(`Event ${eventType} recorded`, 'green');
        resolve();
      });
    });
  } catch (error) {
    log(`Error recording event: ${error.message}`, 'red');
  }
}

async function aggregateMetrics() {
  log('Aggregating metrics...', 'magenta');
  try {
    const metrics = await new Promise(resolve => {
      chrome.storage.local.get(['analytics'], data => resolve(data.analytics || []));
    });
    const summary = {
      totalEvents: metrics.length,
      byType: {},
      lastHour: 0
    };
    const oneHourAgo = Date.now() - 60 * 60 * 1000;
    metrics.forEach(event => {
      summary.byType[event.type] = (summary.byType[event.type] || 0) + 1;
      if (event.timestamp > oneHourAgo) {
        summary.lastHour++;
      }
    });
    console.log(`%c[PhishGuardAI Analytics] Summary: ${JSON.stringify(summary, null, 2)}`, logStyles.green);
    return summary;
  } catch (error) {
    log(`Error aggregating metrics: ${error.message}`, 'red');
    return null;
  }
}

async function clearOldMetrics(maxAgeMs = 7 * 24 * 60 * 60 * 1000) {
  log('Clearing old metrics...', 'cyan');
  try {
    const metrics = await new Promise(resolve => {
      chrome.storage.local.get(['analytics'], data => resolve(data.analytics || []));
    });
    const now = Date.now();
    const filtered = metrics.filter(event => now - event.timestamp < maxAgeMs);
    await new Promise(resolve => {
      chrome.storage.local.set({ analytics: filtered }, () => {
        log(`Cleared ${metrics.length - filtered.length} old metrics`, 'green');
        resolve();
      });
    });
  } catch (error) {
    log(`Error clearing metrics: ${error.message}`, 'red');
  }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'recordEvent') {
    recordEvent(request.eventType, request.data).then(() => {
      sendResponse({ success: true });
    });
    return true; // Keep channel open for async response
  }
});

chrome.runtime.onInstalled.addListener(() => {
  log('Initializing analytics system', 'cyan');
  chrome.storage.local.set({ analytics: [] }, () => {
    log('Analytics storage initialized', 'green');
  });
});

// Aggregate metrics every hour
setInterval(() => aggregateMetrics(), 60 * 60 * 1000);

// Clear old metrics every 24 hours
setInterval(() => clearOldMetrics(), 24 * 60 * 60 * 1000);

// Example event listeners for integration
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analysis') {
    recordEvent('page_analysis', { url: sender.tab?.url, score: request.score });
  } else if (request.action === 'report') {
    recordEvent('user_report', { url: request.data.url });
  }
});
