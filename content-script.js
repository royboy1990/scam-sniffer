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
    'respond now to confirm',
    'is this you', 
    'check this video', 
    'is this you in this pic', 
    'this video of you', 
    'saw this video of you'
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
    "you've won a facebook lottery",
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

// Fuzzy matching function using Levenshtein distance
function levenshteinDistance(str1, str2) {
  const m = str1.length;
  const n = str2.length;
  const dp = Array(m + 1).fill().map(() => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (str1[i - 1] === str2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = Math.min(
          dp[i - 1][j - 1] + 1, // substitution
          dp[i - 1][j] + 1,     // deletion
          dp[i][j - 1] + 1      // insertion
        );
      }
    }
  }
  return dp[m][n];
}

// Function to check if two strings are similar using fuzzy matching
function isSimilar(str1, str2, threshold = 0.8) {
  const distance = levenshteinDistance(str1.toLowerCase(), str2.toLowerCase());
  const maxLength = Math.max(str1.length, str2.length);
  const similarity = 1 - (distance / maxLength);
  return similarity >= threshold;
}

// Function to find similar words in text
function findSimilarWords(text, wordList, threshold = 0.8) {
  const words = text.toLowerCase().split(/\s+/);
  const matches = [];
  
  for (const word of words) {
    for (const pattern of wordList) {
      if (isSimilar(word, pattern, threshold)) {
        matches.push({ word, pattern });
      }
    }
  }
  
  return matches;
}

// Critical patterns that should trigger immediate high scoring
const CRITICAL_PATTERNS = [
  /is\s*this\s*you/i,
  /steam\s*gift\s*card/i,
  /claim\s*(your)?\s*prize/i,
  /verify\s*(your)?\s*account/i,
  /you(?:'ve)?\s*won/i,
  /click\s*here/i,
  /send\s*(me)?\s*gift/i,
  /this\s*video\s*of\s*you/i,
  /found\s*this\s*(photo|video|image)/i
];

// Development mode flag
const IS_DEV_MODE = true; // Temporarily enable dev mode for debugging

// Function to normalize score to 1-10 scale
function normalizeScore(score) {
  // Base threshold is 3, so we'll scale from there
  const maxScore = 15; // Maximum possible score from all checks
  const normalizedScore = Math.min(10, Math.max(1, Math.round((score / maxScore) * 10)));
  return normalizedScore;
}

// Function to get risk level description
function getRiskLevel(score) {
  if (score >= 8) return { level: 'High', color: '#dc3545' };
  if (score >= 5) return { level: 'Medium', color: '#ffc107' };
  return { level: 'Low', color: '#28a745' };
}

// Low trust indicators for cold pitches and spam
const LOW_TRUST_INDICATORS = {
  buzzwords: [
    'extraordinarily',
    'credible',
    'professional',
    'high quality',
    'best',
    'top notch',
    'exclusive',
    'innovative',
    'cutting edge',
    'revolutionary',
    'groundbreaking',
    'premium',
    'elite',
    'prestigious',
    'world-class'
  ],
  formattingIssues: [
    /\.{2,}/,  // Multiple periods
    /,{2,}/,   // Multiple commas
    /!{2,}/,   // Multiple exclamation marks
    /[A-Z]{5,}/, // All caps words
    /\s{3,}/,  // Multiple spaces
    /\n{3,}/   // Multiple line breaks
  ],
  coldPitchPhrases: [
    'i would like to introduce',
    'i am reaching out',
    'i hope this message finds you well',
    'i came across your profile',
    'i noticed your experience',
    'i would be happy to discuss',
    'for your convenience',
    'attached you will find',
    'kindly review',
    'please find attached'
  ]
};

// Function to check for low trust indicators
function checkLowTrust(message) {
  const lowerMessage = message.toLowerCase();
  let score = 0;
  const indicators = [];

  // Check buzzwords
  LOW_TRUST_INDICATORS.buzzwords.forEach(word => {
    if (lowerMessage.includes(word.toLowerCase())) {
      score += 1;
      indicators.push(`Contains buzzword: "${word}"`);
    }
  });

  // Check formatting issues
  LOW_TRUST_INDICATORS.formattingIssues.forEach(pattern => {
    if (pattern.test(message)) {
      score += 1;
      indicators.push('Contains unusual formatting');
    }
  });

  // Check cold pitch phrases
  LOW_TRUST_INDICATORS.coldPitchPhrases.forEach(phrase => {
    if (lowerMessage.includes(phrase)) {
      score += 2; // Increased weight for cold pitch phrases
      indicators.push(`Contains cold pitch phrase: "${phrase}"`);
    }
  });

  // Log detection details in dev mode
  if (IS_DEV_MODE) {
    console.log('Low Trust Detection:', {
      message: message.substring(0, 100) + '...',
      score,
      indicators,
      isLowTrust: score >= 2 // Lowered threshold from 3 to 2
    });
  }

  return {
    isLowTrust: score >= 2, // Lowered threshold from 3 to 2
    score,
    indicators
  };
}

// Whitelist of official domains for major brands
const OFFICIAL_DOMAINS = [
  'facebook.com', 'google.com', 'gmail.com', 'youtube.com', 'twitter.com', 'x.com', 'linkedin.com', 'instagram.com',
  'whatsapp.com', 'microsoft.com', 'live.com', 'outlook.com', 'apple.com', 'icloud.com', 'amazon.com', 'paypal.com',
  'netflix.com', 'tiktok.com', 'snapchat.com', 'discord.com', 'github.com', 'dropbox.com', 'adobe.com', 'yahoo.com',
  'reddit.com', 'twitch.tv', 'steamcommunity.com', 'ebay.com', 'office.com', 'proton.me'
];

// Helper: extract all URLs from a string (now also matches protocol-less URLs)
function extractUrls(text) {
  const urlRegex = /((https?:\/\/)?([\w-]+\.)+[\w-]{2,}(\/[\w\-._~:/?#[\]@!$&'()*+,;=]*)?)/gi;
  return text.match(urlRegex) || [];
}

// Helper: get domain from URL (robust for protocol-less URLs)
function getDomain(url) {
  try {
    if (!/^https?:\/\//i.test(url)) {
      url = 'http://' + url;
    }
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return '';
  }
}

// Helper: check if a domain is official or a phishing attempt
function isPhishingDomain(domain) {
  // Check if domain is in the whitelist or a subdomain of one
  for (const official of OFFICIAL_DOMAINS) {
    if (domain === official || domain.endsWith('.' + official)) {
      return false;
    }
  }
  // Check if domain contains a brand name but is not official
  for (const official of OFFICIAL_DOMAINS) {
    const brand = official.split('.')[0];
    if (domain.includes(brand)) {
      return true;
    }
  }
  return false;
}

// Function to check if a message contains scam indicators
function detectScam(message) {
  try {
    console.log('ScamSniff: Analyzing message:', message.substring(0, 100) + '...');
    
    // PHISHING CHECK: Look for impersonation domains
    const urls = extractUrls(message);
    for (const url of urls) {
      const domain = getDomain(url);
      if (isPhishingDomain(domain)) {
        console.log('ScamSniff: Phishing domain detected:', domain);
        return {
          isScam: true,
          isLowTrust: false,
          score: 10,
          detectedPatterns: [`Phishing domain detected: ${domain}`]
        };
      }
    }

    const lowerMessage = normalizeText(message);
    let score = 0;
    let detectedPatterns = [];

    // First check for low trust indicators
    const lowTrustResult = checkLowTrust(message);
    console.log('ScamSniff: Low trust check result:', {
      isLowTrust: lowTrustResult.isLowTrust,
      score: lowTrustResult.score,
      indicators: lowTrustResult.indicators
    });

    if (lowTrustResult.isLowTrust) {
      return {
        isScam: false,
        isLowTrust: true,
        score: lowTrustResult.score,
        detectedPatterns: lowTrustResult.indicators
      };
    }

    // Check critical patterns first
    CRITICAL_PATTERNS.forEach(pattern => {
      if (pattern.test(message)) {
        score += 3;
        detectedPatterns.push(`Matched critical scam pattern: ${pattern}`);
      }
    });

    // Check for keywords with fuzzy matching
    const keywordMatches = findSimilarWords(lowerMessage, SCAM_PATTERNS.keywords);
    keywordMatches.forEach(({ word, pattern }) => {
      score += 1;
      detectedPatterns.push(`Contains suspicious keyword: "${pattern}" (matched with "${word}")`);
    });

    // Check for suspicious phrases with fuzzy matching
    SCAM_PATTERNS.suspiciousPhrases.forEach(phrase => {
      const normPhrase = normalizeText(phrase);
      if (isSimilar(lowerMessage, normPhrase, 0.65)) {
        score += 2;
        detectedPatterns.push(`Contains suspicious phrase: "${phrase}"`);
      }
    });

    // Check for red flags with fuzzy matching
    SCAM_PATTERNS.redFlags.forEach(flag => {
      const normFlag = normalizeText(flag);
      if (isSimilar(lowerMessage, normFlag, 0.65)) {
        score += 3;
        detectedPatterns.push(`Contains major red flag: "${flag}"`);
      }
    });

    // Additional context-based scoring
    const contextScore = analyzeContext(lowerMessage);
    score += contextScore.score;
    detectedPatterns.push(...contextScore.patterns);

    console.log('ScamSniff: Final detection result:', {
      isScam: score >= 3,
      score,
      detectedPatterns
    });

    return {
      isScam: score >= 3,
      isLowTrust: false,
      score,
      detectedPatterns
    };
  } catch (error) {
    console.error('ScamSniff: Error in scam detection:', error);
    return { isScam: false, isLowTrust: false, score: 0, detectedPatterns: [] };
  }
}

// Function to analyze message context and structure
function analyzeContext(message) {
  let score = 0;
  const patterns = [];

  // Check for urgency indicators
  const urgencyWords = [
    'urgent',
    'immediately',
    'now',
    'asap',
    'hurry',
    'quick'
  ];
  const urgencyMatches = findSimilarWords(message, urgencyWords);
  if (urgencyMatches.length > 0) {
    score += 1;
    patterns.push('Contains urgency indicators');
  }

  // Check for emotional manipulation
  const emotionalWords = [
    'trust',
    'promise',
    'guarantee',
    'secret',
    'exclusive'
  ];
  const emotionalMatches = findSimilarWords(message, emotionalWords);
  if (emotionalMatches.length > 0) {
    score += 1;
    patterns.push('Contains emotional manipulation');
  }

  // Check for unusual punctuation or formatting
  if (message.match(/[!]{2,}|[?]{2,}|[A-Z]{5,}/)) {
    score += 1;
    patterns.push('Contains unusual formatting');
  }

  // Check for common scam message structures
  const scamStructures = [
    /(?:hi|hello|dear).*(?:sir|madam|friend)/i,
    /(?:i|we).*(?:found|saw|noticed).*(?:your|profile|account)/i,
    /(?:please|kindly).*(?:verify|confirm|check)/i,
    /(?:click|visit).*(?:here|link|url)/i
  ];

  scamStructures.forEach(structure => {
    if (structure.test(message)) {
      score += 1;
      patterns.push('Matches common scam message structure');
    }
  });

  return { score, patterns };
}

// Function to add warning badge to messages
function addWarningBadge(element) {
  try {
    const config = getPlatformConfig();
    let messageBubble = element.closest(config.bubbleSelector);
    if (!messageBubble) {
      messageBubble = element;
    }

    if (!messageBubble) {
      console.log('ScamSniff: Could not find message bubble for element:', element);
      return;
    }

    // Remove any existing badge to avoid duplicates
    const existingBadge = messageBubble.querySelector('.scamsniff-warning-badge');
    if (existingBadge) {
      existingBadge.remove();
    }

    // Get the detection result
    const text = getSafeTextContent(messageBubble);
    const result = detectScam(text);

    // Create warning badge
    const badge = document.createElement('div');
    // Always add both classes for low trust
    if (result.isLowTrust) {
      badge.className = 'scamsniff-warning-badge low-trust';
      badge.innerHTML = `
        <div class="scamsniff-warning-content">
          <span class="scamsniff-warning-icon">ℹ️</span>
          <span class="scamsniff-warning-text">Low Trust Message</span>
        </div>
      `;
    } else if (result.isScam) {
      if (result.score >= 10) {
        badge.className = 'scamsniff-warning-badge high-scam';
        badge.innerHTML = `
          <div class="scamsniff-warning-content">
            <span class="scamsniff-warning-icon">🚨</span>
            <span class="scamsniff-warning-text">Highly Suspicious Message</span>
          </div>
        `;
      } else {
        badge.className = 'scamsniff-warning-badge scam';
        badge.innerHTML = `
          <div class="scamsniff-warning-content">
            <span class="scamsniff-warning-icon">⚠️</span>
            <span class="scamsniff-warning-text">Potential Scam Detected</span>
          </div>
        `;
      }
    } else {
      return; // Don't show badge for normal messages
    }

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
        .scamsniff-warning-badge.low-trust {
          background-color: #e2e3e5;
          border-color: #bfc2c5;
          color: #383d41;
        }
        .scamsniff-warning-badge.high-scam {
          background-color: #f8d7da;
          border-color: #f5c2c7;
          color: #842029;
        }
        .scamsniff-warning-badge.scam {
          background-color: #fff3cd;
          border-color: #ffeeba;
          color: #856404;
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
        /* LinkedIn: color the message bubble to match the badge type */
        .msg-s-event-listitem__body:has(.scamsniff-warning-badge.scam) {
          background: #fffbe6;
        }
        .msg-s-event-listitem__body:has(.scamsniff-warning-badge.low-trust) {
          background: #e2e3e5;
        }
        .msg-s-event-listitem__body:has(.scamsniff-warning-badge.high-scam) {
          background: #f8d7da;
        }
        /* Remove or override the generic yellow rule if present */
        .msg-s-event-listitem__body:has(.scamsniff-warning-badge) {
          /* background: unset; */
        }
        .scamsniff-bubble-scam {
          background: #fffbe6 !important;
        }
        .scamsniff-bubble-low-trust {
          background: #e2e3e5 !important;
        }
        .scamsniff-bubble-high-scam {
          background: #f8d7da !important;
        }
      `;
      document.head.appendChild(style);
    }

    // Insert badge at the top of the message bubble
    if (config.name === 'Facebook') {
      // Only skip if inside the sidebar (role="navigation" or similar)
      if (messageBubble.closest('[role="navigation"]')) return;
      // Remove absolute badge class if present
      badge.classList.remove('scamsniff-facebook-absolute-badge');
      // Remove any previous scam classes
      messageBubble.classList.remove('scamsniff-bubble-scam', 'scamsniff-bubble-high-scam', 'scamsniff-bubble-low-trust');
      // Add the correct class
      if (result.isLowTrust) {
        messageBubble.classList.add('scamsniff-bubble-low-trust');
      } else if (result.isScam && result.score >= 10) {
        messageBubble.classList.add('scamsniff-bubble-high-scam');
      } else if (result.isScam) {
        messageBubble.classList.add('scamsniff-bubble-scam');
      }
      // Insert badge as first child
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
    console.log('ScamSniff: Starting message monitoring on', config.name);
    
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
                console.log('ScamSniff: Processing new message:', text.substring(0, 100) + '...');
                const result = detectScam(text);
                if (result.isScam || result.isLowTrust) {
                  console.log('ScamSniff: Flagging message:', {
                    text: text.substring(0, 100) + '...',
                    isScam: result.isScam,
                    isLowTrust: result.isLowTrust,
                    score: result.score,
                    patterns: result.detectedPatterns
                  });
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