const logStyles = {
  cyan: 'color: #00f7ff; font-family: "Courier New", monospace; font-weight: bold;',
  magenta: 'color: #ff00ff; font-family: "Courier New", monospace; font-weight: bold;',
  green: 'color: #00ff00; font-family: "Courier New", monospace; font-weight: bold;',
  red: 'color: #ff0000; font-family: "Courier New", monospace; font-weight: bold;'
};

function log(message, style = 'cyan') {
  console.log(`%c[PhishGuardAI Crowdsourcing] ${message}`, logStyles[style]);
}

function validateReport(report) {
  log(`Validating report for ${report.url}`, 'cyan');
  try {
    const url = new URL(report.url);
    const isValid = url.protocol === 'https:' || url.protocol === 'http:';
    if (!isValid) {
      log(`Invalid URL in report: ${report.url}`, 'red');
      return false;
    }
    if (!report.userComment || typeof report.userComment !== 'string') {
      log('Invalid or missing user comment', 'red');
      return false;
    }
    log('Report validated successfully', 'green');
    return true;
  } catch (e) {
    log(`Error validating report: ${e.message}`, 'red');
    return false;
  }
}

async function updateUserReputation(userId, isValid) {
  log(`Updating reputation for user ${userId}`, 'cyan');
  try {
    const reputations = await new Promise(resolve => {
      chrome.storage.local.get(['userReputations'], data => resolve(data.userReputations || {}));
    });
    const currentRep = reputations[userId] || { score: 0.5, reports: 0 };
    currentRep.reports += 1;
    currentRep.score = Math.min(Math.max(currentRep.score + (isValid ? 0.1 : -0.1), 0), 1);
    reputations[userId] = currentRep;
    await new Promise(resolve => {
      chrome.storage.local.set({ userReputations }, () => {
        log(`User ${userId} reputation updated: ${currentRep.score.toFixed(2)}`, 'green');
        resolve();
      });
    });
    return currentRep.score;
  } catch (e) {
    log(`Error updating reputation: ${e.message}`, 'red');
    return 0.5;
  }
}

async function storeReport(report) {
  log(`Storing report for ${report.url}`, 'cyan');
  try {
    const reports = await new Promise(resolve => {
      chrome.storage.local.get(['reports'], data => resolve(data.reports || []));
    });
    reports.push({
      ...report,
      id: `report_${Date.now()}_${Math.random().toString(36).slice(2)}`,
      validated: true,
      processed: false
    });
    await new Promise(resolve => {
      chrome.storage.local.set({ reports }, () => {
        log(`Report stored: ${report.url}`, 'green');
        resolve();
      });
    });
    return true;
  } catch (e) {
    log(`Error storing report: ${e.message}`, 'red');
    return false;
  }
}

async function exportReportsToJson(outputFile = 'crowdsourced_reports.json') {
  log(`Exporting reports to ${outputFile}`, 'cyan');
  try {
    const reports = await new Promise(resolve => {
      chrome.storage.local.get(['reports'], data => resolve(data.reports || []));
    });
    const exportData = reports.filter(report => report.validated && !report.processed);
    // Simulate file export (Chrome extensions can't write to disk, so log data)
    console.log(`%c[PhishGuardAI Crowdsourcing] Exported Data: ${JSON.stringify(exportData, null, 2)}`, logStyles.magenta);
    // Mark exported reports as processed
    for (let report of reports) {
      if (exportData.includes(report)) {
        report.processed = true;
      }
    }
    await new Promise(resolve => {
      chrome.storage.local.set({ reports }, () => {
        log(`Exported ${exportData.length} reports`, 'green');
        resolve();
      });
    });
  } catch (e) {
    log(`Error exporting reports: ${e.message}`, 'red');
  }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  log(`Received message: ${request.action}`, 'cyan');
  if (request.action === 'report') {
    const report = request.data;
    const userId = 'user_' + (Math.random().toString(36).slice(2)); // Placeholder user ID
    if (validateReport(report)) {
      updateUserReputation(userId, true).then(reputation => {
        if (reputation >= 0.3) { // Minimum reputation threshold
          storeReport({ ...report, userId, reputation }).then(success => {
            sendResponse({ success });
            if (success) {
              exportReportsToJson();
            }
          });
        } else {
          log(`Report rejected: Low user reputation (${reputation.toFixed(2)})`, 'red');
          sendResponse({ success: false, error: 'Low user reputation' });
        }
      });
    } else {
      updateUserReputation(userId, false);
      sendResponse({ success: false, error: 'Invalid report' });
    }
    return true; // Keep channel open for async response
  }
});

chrome.runtime.onInstalled.addListener(() => {
  log('Initializing crowdsourcing system', 'cyan');
  chrome.storage.local.set({ userReputations: {}, reports: [] }, () => {
    log('Crowdsourcing storage initialized', 'green');
  });
});

// Periodic export every 24 hours
setInterval(() => exportReportsToJson(), 24 * 60 * 60 * 1000);
