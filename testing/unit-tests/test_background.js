const { expect } = require('chai');
const sinon = require('sinon');

const logStyles = {
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  reset: '\x1b[0m'
};

function log(message, style = 'cyan') {
  console.log(`${logStyles[style]}[PhishGuardAI Test Background] ${message}${logStyles.reset}`);
}

// Mock background/background.js functions for testing
const backgroundScript = {
  cacheResult: function(url, score, callback) {
    chrome.storage.local.get(['threatCache'], (data) => {
      const cache = data.threatCache || {};
      cache[url] = { score, timestamp: Date.now() };
      chrome.storage.local.set({ threatCache: cache }, callback);
    });
  },
  checkCache: function(url, callback) {
    chrome.storage.local.get(['threatCache'], (data) => {
      const cache = data.threatCache || {};
      const cached = cache[url];
      if (cached && Date.now() - cached.timestamp < 24 * 60 * 60 * 1000) {
        callback(cached.score);
      } else {
        callback(null);
      }
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

describe('PhishGuardAI Background Script Tests', () => {
  let sandbox;
  let mockStorage;
  let mockNotifications;
  let mockRuntime;

  beforeEach(() => {
    log('Setting up test environment...', 'cyan');
    sandbox = sinon.createSandbox();

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
      }
    };

    // Assign mocks to global chrome
    global.chrome = {
      storage: { local: mockStorage },
      notifications: mockNotifications,
      runtime: mockRuntime
    };
  });

  afterEach(() => {
    log('Cleaning up test environment...', 'cyan');
    sandbox.restore();
    global.chrome = undefined;
    mockStorage.data = {};
  });

  describe('cacheResult', () => {
    it('should cache a threat score for a URL', (done) => {
      log('Testing cacheResult...', 'magenta');
      const url = 'http://example.com';
      const score = 0.75;
      backgroundScript.cacheResult(url, score, () => {
        expect(mockStorage.set.calledOnce).to.be.true;
        expect(mockStorage.data.threatCache[url]).to.exist;
        expect(mockStorage.data.threatCache[url].score).to.equal(score);
        expect(mockStorage.data.threatCache[url].timestamp).to.be.a('number');
        log('cacheResult test passed', 'green');
        done();
      });
    });
  });

  describe('checkCache', () => {
    it('should retrieve a cached score within TTL', (done) => {
      log('Testing checkCache with valid cache...', 'magenta');
      const url = 'http://example.com';
      const score = 0.75;
      mockStorage.data.threatCache = {
        [url]: { score, timestamp: Date.now() - 12 * 60 * 60 * 1000 } // 12 hours ago
      };
      backgroundScript.checkCache(url, (cachedScore) => {
        expect(cachedScore).to.equal(score);
        expect(mockStorage.get.calledOnce).to.be.true;
        log('checkCache valid test passed', 'green');
        done();
      });
    });

    it('should return null for expired cache', (done) => {
      log('Testing checkCache with expired cache...', 'magenta');
      const url = 'http://example.com';
      mockStorage.data.threatCache = {
        [url]: { score: 0.75, timestamp: Date.now() - 25 * 60 * 60 * 1000 } // 25 hours ago
      };
      backgroundScript.checkCache(url, (cachedScore) => {
        expect(cachedScore).to.be.null;
        expect(mockStorage.get.calledOnce).to.be.true;
        log('checkCache expired test passed', 'green');
        done();
      });
    });

    it('should return null for uncached URL', (done) => {
      log('Testing checkCache with uncached URL...', 'magenta');
      const url = 'http://example.com';
      backgroundScript.checkCache(url, (cachedScore) => {
        expect(cachedScore).to.be.null;
        expect(mockStorage.get.calledOnce).to.be.true;
        log('checkCache uncached test passed', 'green');
        done();
      });
    });
  });

  describe('sendNotification', () => {
    it('should send a notification for high-risk score', () => {
      log('Testing sendNotification for high-risk...', 'magenta');
      const url = 'http://malicious.com';
      const score = 0.75;
      backgroundScript.sendNotification(url, score);
      expect(mockNotifications.create.calledOnce).to.be.true;
      const callArgs = mockNotifications.create.firstCall.args[0];
      expect(callArgs.title).to.equal('PhishGuardAI Alert');
      expect(callArgs.message).to.include('Warning: http://malicious.com');
      expect(callArgs.message).to.include('75/100');
      log('sendNotification high-risk test passed', 'green');
    });

    it('should not send a notification for low-risk score', () => {
      log('Testing sendNotification for low-risk...', 'magenta');
      const url = 'http://safe.com';
      const score = 0.25;
      backgroundScript.sendNotification(url, score);
      expect(mockNotifications.create.called).to.be.false;
      log('sendNotification low-risk test passed', 'green');
    });
  });

  describe('message handling', () => {
    it('should handle analysis message correctly', (done) => {
      log('Testing analysis message handling...', 'magenta');
      const mockMessage = { action: 'analysis', score: 0.75 };
      const mockSender = { tab: { url: 'http://example.com' } };
      const mockSendResponse = sinon.stub();
      
      // Simulate message listener
      const listener = mockRuntime.onMessage.addListener.firstCall.args[0];
      listener(mockMessage, mockSender, mockSendResponse);
      
      setTimeout(() => {
        expect(mockStorage.set.called).to.be.true;
        expect(mockNotifications.create.called).to.be.true;
        expect(mockSendResponse.calledWith({ success: true })).to.be.true;
        log('Analysis message test passed', 'green');
        done();
      }, 0);
    });

    it('should handle report message correctly', (done) => {
      log('Testing report message handling...', 'magenta');
      const mockMessage = {
        action: 'report',
        data: { url: 'http://example.com', timestamp: Date.now(), userComment: 'Suspicious' }
      };
      const mockSender = {};
      const mockSendResponse = sinon.stub();
      
      const listener = mockRuntime.onMessage.addListener.firstCall.args[0];
      listener(mockMessage, mockSender, mockSendResponse);
      
      setTimeout(() => {
        expect(mockStorage.set.called).to.be.true;
        expect(mockStorage.data.reports).to.have.length(1);
        expect(mockSendResponse.calledWith({ success: true })).to.be.true;
        log('Report message test passed', 'green');
        done();
      }, 0);
    });
  });
});
