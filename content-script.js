// Log to verify the content script is loaded
console.log('ScamSniff: Content script loaded and monitoring messages');

// Scam detection patterns
const SCAM_PATTERNS = {
  keywords: [
    'crypto', 'blockchain', 'web3', 'wallet', 'metamask', 'dex',
    'bitcoin', 'ethereum', 'dogecoin', 'altcoin', 'nft', 'token',
    'airdrop', 'ico', 'bank details', 'credit card', 'debit card',
    'betting', 'casino', 'gambling',
    'install from',
    'install from github', 'run this script', 'npm install',
    'wallet connect', 'rainbow', 'wagmi', 'open this exe',
    'private key', 'seed phrase', 'passphrase',
    'steam gift', 'paypal link', 'gift card', 'coinbase',
    'free', 'winner', 'congratulations', 'urgent', 'guaranteed',
    'earn money', 'get rich', 'paypal', 'telegram', 'whatsapp',
    'login', 'verify', '2fa', 'prize', 'bonus', 'claim', 'exclusive', 'double your money',
    'exchange', 'lottery', 'run script'
  ],
  suspiciousPhrases: [
    'verify manually',
    'technical assessment',
    'run this for verification',
    'remote job opportunity',
    'high hourly rate',
    'we are hiring',
    'screen share your desktop',
    'connect your wallet',
    'confirm identity by running',
    'install dependencies to proceed',
    'log in to see details',
    'special reward for you',
    'claim your reward',
    'exclusive offer',
    'i hope this message finds you well',
    'dear sir/madam',
    'i saw your profile',
    "you're perfect for this job",
    'kindly contact our manager on telegram',
    'please respond me',
    'reply me kindly',
    'urgent message follows',
    'trust me this is not a scam',
    "i can't video call right now",
    "i've never felt this way before",
    "my bank account's frozen",
    'verify your account now',
    'your account will be closed',
    'earn from home',
    'exclusive offer just for you',
    'limited time airdrop',
    'check this video',
    'is this you in the video',
    'found this photo of you',
    'you appeared in this video',
    'you won a prize',
    'click here to win',
    'we are giving away',
    'urgent action required',
    'verify before account closure',
    'free gift just for you',
    'click to receive',
    'claim before it expires',
    'respond now to confirm'
  ],
  redFlags: [
    'wallet integration',
    'crypto payment required',
    'payment in cryptocurrency',
    'must connect metamask',
    'technical interview with script',
    'download and run to qualify',
    'provide private key',
    'enter your seed phrase',
    'fund your wallet to proceed',
    'no KYC required',
    'limited time airdrop',
    'unsolicited job offer',
    'account suspended',
    'move to telegram',
    'move to whatsapp',
    'unexpected verification',
    'login required to continue',
    'asking for personal information',
    'requesting 2fa code',
    'asking for seed phrase',
    'asking for gift cards',
    'wallet integration required',
    'must act immediately',
    'overly emotional language from stranger',
    'romantic interest wants money',
    'payment via crypto or gift cards',
    'no video call possible',
    'click here to claim',
    'payment upfront required',
    'claim your prize now',
    'verify or lose access',
    'unusual activity on your account',
    'your account will be disabled',
    'we have restricted your access',
    'you’ve won a facebook lottery',
    'share this to claim your reward',
    'requires verification via external link',
    'conversation must move to telegram',
    'asking for login details',
    'requesting bank transfer to unknown account'
  ]
};

// Platform configuration for scalability
const PLATFORM_CONFIGS = [
  {
    name: 'LinkedIn',
    match: () => window.location.hostname.includes('linkedin.com'),
    messageSelector: '.msg-s-event-listitem__body',
    bubbleSelector: '.msg-s-event-listitem__body',
    highlightClass: 'scamsniff-bubble-highlight-linkedin'
  },
  {
    name: 'Fiverr',
    match: () => window.location.hostname.includes('fiverr.com'),
    messageSelector: 'p.qem7ddk',
    bubbleSelector: 'p.qem7ddk',
    highlightClass: 'scamsniff-bubble-highlight-fiverr'
  },
  {
    name: 'Facebook',
    match: () => window.location.hostname.includes('facebook.com'),
    messageSelector: 'div.html-div',
    bubbleSelector: 'div.html-div',
    highlightClass: 'scamsniff-bubble-highlight-facebook'
  },
  // Add more platforms here (Facebook, etc.)
];

function getPlatformConfig() {
  return PLATFORM_CONFIGS.find(cfg => cfg.match()) || PLATFORM_CONFIGS[0];
}

// Function to safely get text content
function getSafeTextContent(element) {
  try {
    return element.textContent || '';
  } catch (error) {
    console.error('ScamSniff: Error getting text content:', error);
    return '';
  }
}

// Helper to normalize text: lowercase, trim, collapse whitespace, remove punctuation
function normalizeText(text) {
  return text
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/[.,!?;:()\[\]{}"'`~@#$%^&*_+=<>|\\/\\-]/g, '')
    .trim();
}

// Function to check if a message contains scam indicators
function detectScam(message) {
  try {
    const lowerMessage = normalizeText(message);
    let score = 0;
    let detectedPatterns = [];

    // Check for keywords
    SCAM_PATTERNS.keywords.forEach(keyword => {
      const normPattern = normalizeText(keyword);
      if (lowerMessage.includes(normPattern)) {
        score += 1;
        detectedPatterns.push(`Contains suspicious keyword: "${keyword}"`);
      }
    });

    // Check for suspicious phrases
    SCAM_PATTERNS.suspiciousPhrases.forEach(phrase => {
      if (lowerMessage.includes(normalizeText(phrase))) {
        score += 2;
        detectedPatterns.push(`Contains suspicious phrase: "${phrase}"`);
      }
    });

    // Check for red flags
    SCAM_PATTERNS.redFlags.forEach(flag => {
      if (lowerMessage.includes(normalizeText(flag))) {
        score += 3;
        detectedPatterns.push(`Contains major red flag: "${flag}"`);
      }
    });

    return {
      isScam: score >= 3,
      score,
      detectedPatterns
    };
  } catch (error) {
    console.error('ScamSniff: Error in scam detection:', error);
    return { isScam: false, score: 0, detectedPatterns: [] };
  }
}

// Function to add warning badge to messages
function addWarningBadge(element) {
  try {
    const config = getPlatformConfig();
    // Find the bubble/container for the badge and highlight
    let messageBubble = element.closest(config.bubbleSelector);
    if (!messageBubble) {
      // Fallback: use the element itself
      messageBubble = element;
    }

    if (!messageBubble) {
      console.log('ScamSniff: Could not find message bubble for element:', element);
      return;
    }

    // Check if badge already exists
    if (messageBubble.querySelector('.scamsniff-warning-badge')) {
      return;
    }

    // Create warning badge
    const badge = document.createElement('div');
    badge.className = 'scamsniff-warning-badge';
    badge.innerHTML = `
      <div class="scamsniff-warning-content">
        <span class="scamsniff-warning-icon">⚠️</span>
        <span class="scamsniff-warning-text">Potential Scam Detected</span>
      </div>
    `;

    // Add close button for Facebook
    if (config.name === 'Facebook') {
      const closeBtn = document.createElement('button');
      closeBtn.className = 'scamsniff-facebook-close-btn';
      closeBtn.innerHTML = '&times;';
      closeBtn.title = 'Dismiss warning';
      closeBtn.onclick = (e) => {
        e.stopPropagation();
        badge.remove();
      };
      badge.appendChild(closeBtn);
    }

    // Add styles (only once)
    if (!document.getElementById('scamsniff-style')) {
      const style = document.createElement('style');
      style.id = 'scamsniff-style';
      style.textContent = `
        .scamsniff-warning-badge {
          background-color: #fff3cd;
          border: 1px solid #ffeeba;
          border-radius: 4px 4px 0 0;
          font-size: 14px;
          color: #856404;
          display: flex;
          align-items: center;
          gap: 8px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.05);
          position: relative;
          top: 0;
          left: 0;
          width: 100%;
          z-index: 10;
        }
        /* Facebook: circular badge, centered content */
        .scamsniff-facebook-absolute-badge {
          position: absolute !important;
          top: 6px;
          left: -1px;
          z-index: 1000;
          display: flex;
          height: 98px;
          width: 98px;
          align-items: center;
          justify-content: center;
          flex-direction: column;
          border-radius: 100%;
          background-color: #fff3cd;
          border: 1px solid #ffeeba;
          box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .scamsniff-facebook-absolute-badge .scamsniff-warning-content {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          text-align: center;
          gap: 8px;
        }
        .scamsniff-facebook-absolute-badge .scamsniff-warning-text {
          font-weight: 500;
          font-size: 14px;
        }
        .scamsniff-facebook-absolute-badge .scamsniff-warning-icon {
          font-size: 32px;
        }
        .scamsniff-facebook-close-btn {
          position: absolute;
          top: 4px;
          right: 14px;
          background: transparent;
          border: none;
          color: #856404;
          font-size: 20px;
          font-weight: bold;
          cursor: pointer;
          z-index: 1010;
          padding: 0;
          line-height: 1;
        }
        .scamsniff-facebook-close-btn:hover {
          color: #b8860b;
        }
        /* Robust highlight for LinkedIn using :has() */
        .msg-s-event-listitem__body:has(.scamsniff-warning-badge) {
          border-left: 1px solid #ffc107 !important;
          padding-left: 8px !important;
          background: #fffbe6 !important;
          box-sizing: border-box !important;
        }
        /* Fiverr highlight */
        .scamsniff-bubble-highlight-fiverr {
          border-left: 1.5px solid #ffc107 !important;
          padding-left: 8px !important;
          background: #fffbe6 !important;
          box-sizing: border-box !important;
        }
      `;
      document.head.appendChild(style);
    }

    // Insert badge at the top of the message bubble
    if (config.name === 'Facebook') {
      // Only skip if inside the sidebar (role="navigation" or similar)
      if (messageBubble.closest('[role="navigation"]')) return;
      messageBubble.style.position = 'relative';
      badge.classList.add('scamsniff-facebook-absolute-badge');
      messageBubble.insertBefore(badge, messageBubble.firstChild);
    } else {
      messageBubble.insertBefore(badge, messageBubble.firstChild);
    }

    // No highlight for Facebook
    if (config.name !== 'LinkedIn' && config.name !== 'Facebook') {
      messageBubble.classList.add(config.highlightClass);
    }

  } catch (error) {
    console.error('ScamSniff: Error adding warning badge:', error);
  }
}

// Function to monitor messages
function monitorMessages() {
  try {
    const config = getPlatformConfig();
    // Create a MutationObserver to watch for new messages
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            let messages = Array.from(node.querySelectorAll(config.messageSelector));
            // For Facebook, only process outermost message bubbles
            if (config.name === 'Facebook') {
              messages = messages.filter(el => !el.closest(config.messageSelector + ' ' + config.messageSelector));
            }
            messages.forEach(message => {
              const text = getSafeTextContent(message);
              if (text) {
                const result = detectScam(text);
                if (result.isScam) {
                  console.log('ScamSniff: Flagging scam message:', text);
                  addWarningBadge(message);
                }
              }
            });
          }
        });
      });
    });

    // Start observing the document body for changes
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });

    // Also check existing messages on page load
    let messages = Array.from(document.querySelectorAll(config.messageSelector));
    // For Facebook, only process outermost message bubbles
    if (config.name === 'Facebook') {
      messages = messages.filter(el => !el.closest(config.messageSelector + ' ' + config.messageSelector));
    }
    messages.forEach(message => {
      const text = getSafeTextContent(message);
      if (text) {
        const result = detectScam(text);
        if (result.isScam) {
          console.log('ScamSniff: Flagging scam message:', text);
          addWarningBadge(message);
        }
      }
    });

  } catch (error) {
    console.error('ScamSniff: Error in message monitoring:', error);
  }
}

// Initialize when the page is fully loaded
if (document.readyState === 'complete') {
  const config = getPlatformConfig();
  // console.log(`ScamSniff: Content script loaded and monitoring messages on ${config.name}`);
  monitorMessages();
} else {
  window.addEventListener('load', () => {
    const config = getPlatformConfig();
    // console.log(`ScamSniff: Content script loaded and monitoring messages on ${config.name}`);
    monitorMessages();
  });
} 