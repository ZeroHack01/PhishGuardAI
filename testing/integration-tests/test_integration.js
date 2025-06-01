const { expect } = require('chai');
const { JSDOM } = require('jsdom');
const sinon = require('sinon');

const logStyles = {
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  reset: '\x1b[0m'
};

function log(message, style = 'cyan') {
  console.log(`${logStyles[style]}[PhishGuardAI Integration Tests] ${message}${logStyles.reset}`);
}

// Mock content/scripts.js
const contentScript = {
  analyzePage: function() {
    const features = {
      hasLoginForm: document.querySelectorAll('form input[type="password"]').length > 0,
      suspiciousKeywords: ['login', 'password', 'verify', 'account'].some(keyword =>
        document.body.innerText.toLowerCase().includes(keyword)),
      urlEntropy: this.calculateUrlEntropy(window.location.href),
      externalLinks: document.querySelectorAll('a[href^="http"]').length
    };
    let score = 0;
    if (features.hasLoginForm) score += 0.4;
    if (features.suspiciousKeywords) score += 0.3;
    if (features.urlEntropy > 4) score += 0.2;
    if (features.externalLinks > 5) score += 0.1;
    return Math.min(Math.max(score, 0), 1);
  },
  calculateUrlEntropy: function(url) {
    const chars = url.split('');
    const freq = {};
    chars.forEach(c => freq[c] = (freq[c] || 0) + 1);
    const length = chars.length;
    let entropy = 0;
    for (let c in freq) {
      const p = freq[c] / length;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }
};

// Mock background/background.js
const backgroundScript = {
  cacheResult: function(url, score, callback) {
    chrome.storage.local.get(['threatCache'], (data) => {
      const cache = data.threatCache || {};
      cache[url] = { score, timestamp: Date.now() };
      chrome.storage.local.set({ threatCache: cache }, callback);
    });
  },
  sendNotification: function(url, score) {
    if (score > 0.5) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: '../icons/icon48.png',
        title: 'PhishGuardAI Alert',
        message: `Warning: ${url} may be a phishing site! Threat score: ${(score * 100).toFixed(0)}/100`,
        priority: 2
      });
    }
  }
};

// Mock popup/script.js
const popupScript = {
  updateThreatScore: function(score) {
    document.getElementById('threat-score').textContent = (score * 100).toFixed(0);
  }
};

describe('PhishGuardAI Integration Tests', () => {
  let dom;
  let sandbox;
  let mockStorage;
  let mockNotifications;
  let mockRuntime;

  beforeEach(() => {
    log('Setting up integration test environment...', 'cyan');
    sandbox = sinon.createSandbox();

    // Set up jsdom
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="content"></div>
          <div id="popup">
            <span id="threat-score">0</span>
            <button id="report-button">Report</button>
          </div>
        </body>
      </html>
    `, { url: 'http://malicious.com' });

    // Mock chrome.storage.local
    mockStorage = {
      data: {},
      get: sinon.stub().callsFake((keys, callback) => {
        const result = {};
        keys.forEach(key => {
          result[key] = mockStorage.data[key] || null;
        });
        callback(result);
      }),
      set: sinon.stub().callsFake((data, callback) => {
        Object.assign(mockStorage.data, data);
        callback();
      })
    };

    // Mock chrome.notifications
    mockNotifications = {
      create: sinon.stub().callsFake((options, callback) => {
        callback('notification_id');
      })
    };

    // Mock chrome.runtime
    mockRuntime = {
      onMessage: {
        addListener: sinon.stub()
      },
      sendMessage: sinon.stub().callsFake((message, callback) => {
        const listeners = mockRuntime.onMessage.addListener.getCalls();
        listeners.forEach(call => {
          const listener = call.args[0];
          listener(message, { tab: { url: 'http://malicious.com' } }, callback);
        });
      })
    };

    // Assign mocks to global
    global.document = dom.window.document;
    global.window = dom.window;
    global.chrome = {
      storage: { local: mockStorage },
      notifications: mockNotifications,
      runtime: mockRuntime
    };
  });

  afterEach(() => {
    log('Cleaning up integration test environment...', 'cyan');
    sandbox.restore();
    global.document = undefined;
    global.window = undefined;
    global.chrome = undefined;
    mockStorage.data = {};
  });

  it('should complete end-to-end flow: content analysis to popup display', (done) => {
    log('Testing end-to-end flow...', 'magenta');

    // Simulate content script analysis
    document.body.innerHTML = `
      <form>
        <input type="password" />
      </form>
      <div>Please login to your account</div>
    `;
    const score = contentScript.analyzePage();

    // Simulate background script processing
    mockRuntime.onMessage.addListener.callsFake((listener) => {
      listener({ action: 'analysis', score }, { tab: { url: 'http://malicious.com' } }, (response) => {
        expect(response.success).to.be.true;
        expect(mockStorage.set.called).to.be.true;
        expect(mockStorage.data.threatCache['http://malicious.com']).to.exist;
        expect(mockStorage.data.threatCache['http://malicious.com'].score).to.equal(score);
        expect(mockNotifications.create.called).to.be.true;
      });
    });
    backgroundScript.cacheResult('http://malicious.com', score, () => {
      backgroundScript.sendNotification('http://malicious.com', score);
    });

    // Simulate popup requesting score
    mockRuntime.sendMessage.callsFake((message, callback) => {
      if (message.action === 'analyze') {
        callback({ score });
      }
    });
    popupScript.updateThreatScore(score);

    // Verify popup display
    const displayedScore = parseInt(document.getElementById('threat-score').textContent);
    expect(displayedScore).to.equal(Math.round(score * 100));
    expect(displayedScore).to.be.at.least(70); // Login form (0.4) + keywords (0.3)

    log('End-to-end flow test passed', 'green');
    done();
  });

  it('should handle user report submission flow', (done) => {
    log('Testing report submission flow...', 'magenta');

    // Simulate popup sending report
    const reportData = {
      url: 'http://malicious.com',
      timestamp: Date.now(),
      userComment: 'Suspicious login page'
    };
    mockRuntime.onMessage.addListener.callsFake((listener) => {
      listener({ action: 'report', data: reportData }, {}, (response) => {
        expect(response.success).to.be.true;
        expect(mockStorage.set.called).to.be.true;
        expect(mockStorage.data.reports).to.have.length(1);
        expect(mockStorage.data.reports[0].url).to.equal(reportData.url);
      });
    });

    // Trigger report
    chrome.runtime.sendMessage({ action: 'report', data: reportData }, (response) => {
      expect(response.success).to.be.true;
      log('Report submission flow test passed', 'green');
      done();
    });
  });
});
