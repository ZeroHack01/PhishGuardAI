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
  console.log(`${logStyles[style]}[PhishGuardAI Performance Tests] ${message}${logStyles.reset}`);
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

describe('PhishGuardAI Performance Tests', () => {
  let dom;
  let sandbox;
  let mockStorage;
  let mockNotifications;

  beforeEach(() => {
    log('Setting up performance test environment...', 'cyan');
    sandbox = sinon.createSandbox();

    // Set up jsdom
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="content"></div>
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

    // Assign mocks to global
    global.document = dom.window.document;
    global.window = dom.window;
    global.chrome = {
      storage: { local: mockStorage },
      notifications: mockNotifications
    };
  });

  afterEach(() => {
    log('Cleaning up performance test environment...', 'cyan');
    sandbox.restore();
    global.document = undefined;
    global.window = undefined;
    global.chrome = undefined;
    mockStorage.data = {};
  });

  it('should analyze a complex page within 100ms', (done) => {
    log('Testing page analysis performance...', 'magenta');
    
    // Create a complex DOM
    let html = `
      <form>
        <input type="password" />
        <input type="text" />
      </form>
      <div>Please login to your account</div>
    `;
    for (let i = 0; i < 100; i++) {
      html += `<a href="http://external${i}.com">Link ${i}</a>`;
    }
    document.body.innerHTML = html;

    const startTime = performance.now();
    const score = contentScript.analyzePage();
    const duration = performance.now() - startTime;

    expect(score).to.be.at.least(0.8); // Login form (0.4) + keywords (0.3) + links (0.1)
    expect(duration).to.be.below(100);
    log(`Page analysis completed in ${duration.toFixed(2)}ms`, 'green');
    done();
  });

  it('should cache result within 50ms', (done) => {
    log('Testing cacheResult performance...', 'magenta');
    
    const url = 'http://malicious.com';
    const score = 0.75;
    
    const startTime = performance.now();
    backgroundScript.cacheResult(url, score, () => {
      const duration = performance.now() - startTime;
      
      expect(mockStorage.set.calledOnce).to.be.true;
      expect(mockStorage.data.threatCache[url].score).to.equal(score);
      expect(duration).to.be.below(50);
      log(`Cache operation completed in ${duration.toFixed(2)}ms`, 'green');
      done();
    });
  });

  it('should send notification within 20ms', (done) => {
    log('Testing sendNotification performance...', 'magenta');
    
    const url = 'http://malicious.com';
    const score = 0.75;
    
    const startTime = performance.now();
    backgroundScript.sendNotification(url, score);
    const duration = performance.now() - startTime;
    
    expect(mockNotifications.create.calledOnce).to.be.true;
    expect(duration).to.be.below(20);
    log(`Notification sent in ${duration.toFixed(2)}ms`, 'green');
    done();
  });

  it('should handle 1000 cache operations within 5000ms', (done) => {
    log('Testing bulk cache performance...', 'magenta');
    
    const startTime = performance.now();
    let completed = 0;
    const total = 1000;
    
    function cacheOne(i) {
      backgroundScript.cacheResult(`http://test${i}.com`, 0.5 + (i % 5) / 10, () => {
        completed++;
        if (completed === total) {
          const duration = performance.now() - startTime;
          expect(mockStorage.set.callCount).to.equal(total);
          expect(duration).to.be.below(5000);
          log(`Processed ${total} cache operations in ${duration.toFixed(2)}ms`, 'green');
          done();
        }
      });
    }
    
    for (let i = 0; i < total; i++) {
      cacheOne(i);
    }
  });
});
