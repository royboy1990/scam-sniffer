// Log to verify the content script is loaded
console.log('ScamSniff: Content script loaded and monitoring messages');

// Scam detection patterns
const SCAM_PATTERNS = {
  keywords: [
    'blockchain', 'crypto', 'web3', 'wallet', 'metamask', 'dex',
    'betting', 'casino', 'gambling', 'bitcoin', 'ethereum',
    'wallet connect', 'verify manually', 'install from github',
    'rainbow', 'wagmi'
  ],
  suspiciousPhrases: [
    'high hourly rate',
    'remote position',
    'part-time available',
    'cryptocurrency payment',
    'direct bank transfer',
    'technical assessment',
    'code quality test',
    'screen sharing',
    'metamask integration'
  ],
  redFlags: [
    'blockchain-based',
    'crypto payment',
    'wallet integration',
    'technical interview',
    'assessment test'
  ]
};

// Platform configuration for scalability
const PLATFORM_CONFIGS = [
  {
    name: 'LinkedIn',
    match: () => window.location.hostname.includes('linkedin.com'),
    messageSelector: '.msg-s-event-listitem__body',
    bubbleSelector: '.msg-s-event-listitem__body', // For LinkedIn, highlight the <p> directly
    highlightClass: 'scamsniff-bubble-highlight-linkedin'
  },
  // Add more platforms here (Fiverr, Facebook, etc.)
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

// Function to check if a message contains scam indicators
function detectScam(message) {
  try {
    const lowerMessage = message.toLowerCase();
    let score = 0;
    let detectedPatterns = [];

    // Check for keywords
    SCAM_PATTERNS.keywords.forEach(keyword => {
      if (lowerMessage.includes(keyword.toLowerCase())) {
        score += 1;
        detectedPatterns.push(`Contains suspicious keyword: "${keyword}"`);
      }
    });

    // Check for suspicious phrases
    SCAM_PATTERNS.suspiciousPhrases.forEach(phrase => {
      if (lowerMessage.includes(phrase.toLowerCase())) {
        score += 2;
        detectedPatterns.push(`Contains suspicious phrase: "${phrase}"`);
      }
    });

    // Check for red flags
    SCAM_PATTERNS.redFlags.forEach(flag => {
      if (lowerMessage.includes(flag.toLowerCase())) {
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

    // Add styles (only once)
    if (!document.getElementById('scamsniff-style')) {
      const style = document.createElement('style');
      style.id = 'scamsniff-style';
      style.textContent = `
        .scamsniff-warning-badge {
          background-color: #fff3cd;
          border: 1px solid #ffeeba;
          border-radius: 4px 4px 0 0;
          padding: 8px 12px;
          margin: 0;
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
        .scamsniff-warning-content {
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .scamsniff-warning-icon {
          font-size: 16px;
        }
        .scamsniff-warning-text {
          font-weight: 500;
        }
        /* Robust highlight for LinkedIn using :has() */
        .msg-s-event-listitem__body:has(.scamsniff-warning-badge) {
          border-left: 1px solid #ffc107 !important;
          padding-left: 8px !important;
          background: #fffbe6 !important;
          box-sizing: border-box !important;
        }
        /* Add more platform highlight classes here */
      `;
      document.head.appendChild(style);
    }

    // Insert badge at the top of the message bubble
    messageBubble.insertBefore(badge, messageBubble.firstChild);

    // No need to add highlight class for LinkedIn anymore
    if (config.name !== 'LinkedIn') {
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
            const messages = node.querySelectorAll(config.messageSelector);
            messages.forEach(message => {
              const text = getSafeTextContent(message);
              if (text) {
                const result = detectScam(text);
                if (result.isScam) {
                  console.log('ScamSniff: Detected potential scam message:', {
                    score: result.score,
                    patterns: result.detectedPatterns,
                    text: text.substring(0, 100) + '...'
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
    const messages = document.querySelectorAll(config.messageSelector);
    messages.forEach(message => {
      const text = getSafeTextContent(message);
      if (text) {
        const result = detectScam(text);
        if (result.isScam) {
          console.log('ScamSniff: Found existing scam message:', {
            score: result.score,
            patterns: result.detectedPatterns,
            text: text.substring(0, 100) + '...'
          });
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
  console.log('ScamSniff: Content script loaded and monitoring messages');
  monitorMessages();
} else {
  window.addEventListener('load', () => {
    console.log('ScamSniff: Content script loaded and monitoring messages');
    monitorMessages();
  });
} 