const statusElement = document.getElementById('status');
const scoreElement = document.getElementById('score');
const reportButton = document.getElementById('report-btn');
const themeToggle = document.getElementById('theme-toggle');

const logStyles = {
  cyan: 'color: #00f7ff; font-family: "Courier New", monospace; font-weight: bold;',
  magenta: 'color: #ff00ff; font-family: "Courier New", monospace; font-weight: bold;',
  green: 'color: #00ff00; font-family: "Courier New", monospace; font-weight: bold;',
  red: 'color: #ff0000; font-family: "Courier New", monospace; font-weight: bold;'
};

function log(message, style = 'cyan') {
  console.log(`%c[PhishGuardAI] ${message}`, logStyles[style]);
}

function updateUI(score, isSafe) {
  log(`Updating UI: Score=${score}, Status=${isSafe ? 'Safe' : 'Danger'}`, 'green');
  scoreElement.textContent = score.toFixed(2);
  statusElement.textContent = isSafe ? 'Safe' : 'Potential Phishing';
  statusElement.className = `status ${isSafe ? 'safe' : 'danger'}`;
}

function analyzePage() {
  log('Initiating page analysis...', 'cyan');
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      chrome.tabs.sendMessage(tabs[0].id, { action: 'analyze' }, (response) => {
        if (chrome.runtime.lastError) {
          log(`Error: ${chrome.runtime.lastError.message}`, 'red');
          updateUI(0, true); // Fallback to safe
          return;
        }
        if (response && response.score !== undefined) {
          const score = Math.min(Math.max(response.score * 100, 0), 100);
          const isSafe = score < 50;
          updateUI(score, isSafe);
          log(`Analysis complete: Score=${score}, Safe=${isSafe}`, 'magenta');
        } else {
          log('No valid response from content script', 'red');
          updateUI(0, true);
        }
      });
    } else {
      log('No active tab found', 'red');
      updateUI(0, true);
    }
  });
}

function reportSite() {
  log('User initiated site report', 'cyan');
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      const url = tabs[0].url;
      const reportData = { url, timestamp: Date.now(), userComment: 'Reported from popup' };
      log(`Reporting URL: ${url}`, 'magenta');
      // Placeholder: Send to crowdsource.js or external endpoint
      chrome.runtime.sendMessage({ action: 'report', data: reportData }, (response) => {
        if (response && response.success) {
          log('Report submitted successfully', 'green');
          alert('Thank you for reporting!');
        } else {
          log('Report submission failed', 'red');
          alert('Failed to submit report. Try again later.');
        }
      });
    } else {
      log('No active tab to report', 'red');
      alert('No active tab found.');
    }
  });
}

function toggleTheme() {
  const isLightMode = document.body.classList.toggle('light-mode');
  const theme = isLightMode ? 'light' : 'dark';
  log(`Switching to ${theme} mode`, 'cyan');
  chrome.storage.local.set({ theme }, () => {
    log(`Theme saved: ${theme}`, 'green');
  });
}

document.addEventListener('DOMContentLoaded', () => {
  log('PhishGuardAI Popup Initialized', 'cyan');
  chrome.storage.local.get(['theme'], (data) => {
    if (data.theme === 'light') {
      document.body.classList.add('light-mode');
      log('Loaded light mode from storage', 'green');
    }
  });
  analyzePage();
});

reportButton.addEventListener('click', reportSite);
themeToggle.addEventListener('click', toggleTheme);

// Periodic analysis every 10 seconds
setInterval(analyzePage, 10000);
