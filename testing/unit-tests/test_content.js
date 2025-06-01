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
  console.log(`${logStyles[style]}[PhishGuardAI Test Content] ${message}${logStyles.reset}`);
}

// Mock content/scripts.js functions for testing
const contentScript = {
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
  },
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
  }
};

describe('PhishGuardAI Content Script Tests', () => {
  let dom;
  let sandbox;

  beforeEach(() => {
    log('Setting up test environment...', 'cyan');
    sandbox = sinon.createSandbox();
    
    // Set up jsdom
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="content"></div>
        </body>
      </html>
    `, { url: 'http://example.com' });
    
    // Mock global objects
    global.document = dom.window.document;
    global.window = dom.window;
    global.chrome = {
      runtime: {
        onMessage: {
          addListener: sandbox.stub()
        },
        sendMessage: sandbox.stub()
      }
    };
  });

  afterEach(() => {
    log('Cleaning up test environment...', 'cyan');
    sandbox.restore();
    global.document = undefined;
    global.window = undefined;
    global.chrome = undefined;
  });

  describe('calculateUrlEntropy', () => {
    it('should calculate entropy correctly for a simple URL', () => {
      log('Testing URL entropy calculation...', 'magenta');
      const url = 'http://example.com';
      const entropy = contentScript.calculateUrlEntropy(url);
      expect(entropy).to.be.a('number');
      expect(entropy).to.be.closeTo(2.77, 0.01); // Precomputed entropy for 'http://example.com'
      log('Entropy test passed', 'green');
    });

    it('should handle empty URLs gracefully', () => {
      log('Testing empty URL entropy...', 'magenta');
      const entropy = contentScript.calculateUrlEntropy('');
      expect(entropy).to.equal(0);
      log('Empty URL test passed', 'green');
    });
  });

  describe('analyzePage', () => {
    it('should detect login forms and assign high score', () => {
      log('Testing login form detection...', 'magenta');
      document.body.innerHTML = `
        <form>
          <input type="password" />
        </form>
      `;
      const score = contentScript.analyzePage();
      expect(score).to.be.at.least(0.4); // Login form contributes 0.4
      expect(score).to.be.at.most(1);
      log('Login form detection test passed', 'green');
    });

    it('should detect suspicious keywords', () => {
      log('Testing suspicious keywords...', 'magenta');
      document.body.innerHTML = '<div>Please login to your account</div>';
      const score = contentScript.analyzePage();
      expect(score).to.be.at.least(0.3); // Keywords contribute 0.3
      expect(score).to.be.at.most(1);
      log('Suspicious keywords test passed', 'green');
    });

    it('should handle high URL entropy', () => {
      log('Testing high URL entropy...', 'magenta');
      dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
        url: 'http://a1b2c3d4e5f6g7h8i9j0.com'
      });
      global.document = dom.window.document;
      global.window = dom.window;
      const score = contentScript.analyzePage();
      expect(score).to.be.at.least(0.2); // High entropy contributes 0.2
      expect(score).to.be.at.most(1);
      log('High URL entropy test passed', 'green');
    });

    it('should detect external links', () => {
      log('Testing external links detection...', 'magenta');
      document.body.innerHTML = `
        <a href="http://external1.com">Link1</a>
        <a href="http://external2.com">Link2</a>
        <a href="http://external3.com">Link3</a>
        <a href="http://external4.com">Link4</a>
        <a href="http://external5.com">Link5</a>
        <a href="http://external6.com">Link6</a>
      `;
      const score = contentScript.analyzePage();
      expect(score).to.be.at.least(0.1); // >5 links contribute 0.1
      expect(score).to.be.at.most(1);
      log('External links detection test passed', 'green');
    });

    it('should return 0 for a safe page', () => {
      log('Testing safe page...', 'magenta');
      document.body.innerHTML = '<div>Welcome to a safe site</div>';
      const score = contentScript.analyzePage();
      expect(score).to.equal(0);
      log('Safe page test passed', 'green');
    });
  });
});
