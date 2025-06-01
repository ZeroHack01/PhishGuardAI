import * as tf from 'https://cdn.jsdelivr.net/npm/@tensorflow/tfjs@4.20.0/dist/tf.min.js';
import loadModel from '../models/phishing_model.tjs';

async function analyzePage() {
  try {
    console.log('%cPhishGuardAI: %cLoading Model...', 'color: magenta', 'color: #0ff');
    const model = await loadModel();
    const features = [
      document.querySelectorAll('input[type="password"]').length > 0 ? 1 : 0,
      ['login', 'password', 'verify'].some(keyword => document.body.innerText.toLowerCase().includes(keyword)) ? 1 : 0,
      calculateEntropy(window.location.href),
      document.querySelectorAll('a[href^="http"]').length / 10
    ];
    const inputTensor = tf.tensor2d([features], [1, 4]);
    const score = await model.predict(inputTensor).dataSync()[0];
    const domain = new URL(window.location.href).hostname;
    const vulnerabilities = score > 0.7 ? ['Suspicious URL patterns', 'Potential phishing form'] : [];
    console.log(`%cPhishGuardAI: %cScore: ${score}`, 'color: magenta', 'color: #0ff');
    chrome.runtime.sendMessage({
      action: 'analysis',
      score,
      url: window.location.href,
      domain,
      vulnerabilities
    });
  } catch (error) {
    console.error('%cPhishGuardAI: %cError: ${error.message}', 'color: red', 'color: #f00');
  }
}

function calculateEntropy(url) {
  const charCount = {};
  for (const char of url) {
    charCount[char] = (charCount[char] || 0) + 1;
  }
  return -Object.values(charCount).reduce((sum, freq) => {
    const p = freq / url.length;
    return sum + (p * Math.log2(p));
  }, 0) || 0;
}

window.addEventListener('load', analyzePage);
