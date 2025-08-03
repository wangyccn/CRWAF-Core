// Click challenge handler
class ClickChallenge {
    constructor(requiredClicks) {
        this.requiredClicks = requiredClicks;
        this.clickCount = 0;
        this.clickPositions = [];
        this.startTime = Date.now();
        this.behaviorTracker = new BehaviorTracker();
    }

    handleClick(event) {
        const clickArea = document.getElementById('clickArea');
        const counter = document.getElementById('clickCount');
        
        // Record click position
        const rect = clickArea.getBoundingClientRect();
        const x = event.clientX - rect.left;
        const y = event.clientY - rect.top;
        
        this.clickPositions.push({
            x: x / rect.width,
            y: y / rect.height,
            timestamp: Date.now() - this.startTime
        });
        
        this.clickCount++;
        counter.textContent = this.clickCount;
        
        // Visual feedback
        clickArea.classList.add('clicked');
        setTimeout(() => {
            clickArea.classList.remove('clicked');
        }, 300);
        
        // Create ripple effect
        this.createRipple(event, clickArea);
        
        // Check if challenge is complete
        if (this.clickCount >= this.requiredClicks) {
            this.completeChallenge();
        }
    }

    createRipple(event, container) {
        const ripple = document.createElement('div');
        ripple.className = 'ripple';
        
        const rect = container.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = event.clientX - rect.left - size / 2;
        const y = event.clientY - rect.top - size / 2;
        
        ripple.style.width = ripple.style.height = size + 'px';
        ripple.style.left = x + 'px';
        ripple.style.top = y + 'px';
        
        container.appendChild(ripple);
        
        ripple.addEventListener('animationend', () => {
            ripple.remove();
        });
    }

    async completeChallenge() {
        const clickArea = document.getElementById('clickArea');
        const challengeId = document.getElementById('challengeId').value;
        
        // Verify click pattern
        if (!this.verifyClickPattern()) {
            this.showError('点击模式异常，请重新验证');
            return;
        }
        
        // Verify behavior
        const behaviorEvents = this.behaviorTracker.getEvents();
        if (!this.behaviorTracker.isHumanBehavior()) {
            this.showError('行为验证失败，请重新验证');
            return;
        }
        
        clickArea.innerHTML = `
            <div class="click-icon">✓</div>
            <div class="click-text">验证成功！</div>
        `;
        clickArea.style.background = '#e8f5e9';
        clickArea.style.borderColor = '#4caf50';
        clickArea.style.cursor = 'default';
        clickArea.onclick = null;
        
        // Submit verification
        try {
            const response = await fetch('/waf/verify-click', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    challenge_id: challengeId,
                    clicks: this.clickPositions,
                    behavior: behaviorEvents
                })
            });
            
            if (response.ok) {
                setTimeout(() => {
                    location.reload();
                }, 1000);
            } else {
                this.showError('验证失败，请重试');
            }
        } catch (error) {
            this.showError('网络错误，请重试');
            console.error('Verification error:', error);
        }
    }

    verifyClickPattern() {
        // Check if clicks are too fast (bot-like)
        if (this.clickPositions.length < 2) return true;
        
        const intervals = [];
        for (let i = 1; i < this.clickPositions.length; i++) {
            intervals.push(
                this.clickPositions[i].timestamp - this.clickPositions[i - 1].timestamp
            );
        }
        
        // Minimum 200ms between clicks
        const tooFast = intervals.some(interval => interval < 200);
        if (tooFast) return false;
        
        // Check if all clicks are in exact same position (bot-like)
        const positions = this.clickPositions.map(p => `${p.x.toFixed(2)},${p.y.toFixed(2)}`);
        const uniquePositions = new Set(positions);
        if (uniquePositions.size === 1 && this.clickPositions.length > 1) {
            return false;
        }
        
        return true;
    }

    showError(message) {
        const container = document.querySelector('.container');
        const error = document.createElement('div');
        error.className = 'error-message';
        error.textContent = message;
        error.style.cssText = `
            background: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            border: 1px solid #f5c6cb;
        `;
        
        container.appendChild(error);
        
        setTimeout(() => {
            location.reload();
        }, 2000);
    }
}

// Behavior tracker (reuse from challenge.js if available)
if (typeof BehaviorTracker === 'undefined') {
    class BehaviorTracker {
        constructor() {
            this.events = [];
            this.startTime = Date.now();
            this.setupListeners();
        }

        setupListeners() {
            // Mouse movement tracking
            let lastMouseTime = 0;
            document.addEventListener('mousemove', (e) => {
                const now = Date.now();
                if (now - lastMouseTime > 100) {
                    this.recordEvent('mouseMove', { x: e.clientX, y: e.clientY });
                    lastMouseTime = now;
                }
            });

            // Click tracking
            document.addEventListener('click', (e) => {
                this.recordEvent('click', { x: e.clientX, y: e.clientY });
            });

            // Touch events
            document.addEventListener('touchstart', (e) => {
                if (e.touches.length > 0) {
                    const touch = e.touches[0];
                    this.recordEvent('touch', { x: touch.clientX, y: touch.clientY });
                }
            });
        }

        recordEvent(type, data = {}) {
            this.events.push({
                event_type: type,
                timestamp: Date.now() - this.startTime,
                ...data
            });
        }

        getEvents() {
            return this.events;
        }

        isHumanBehavior() {
            const eventTypes = new Set(this.events.map(e => e.event_type));
            return eventTypes.has('mouseMove') || eventTypes.has('touch');
        }
    }
}

// Initialize click challenge
let clickChallenge;

function handleClick() {
    if (!clickChallenge) {
        const requiredClicks = parseInt(
            document.querySelector('.counter').textContent.match(/\d+\s*$/)[0]
        );
        clickChallenge = new ClickChallenge(requiredClicks);
    }
    
    clickChallenge.handleClick(event);
}

// Add ripple animation styles
const style = document.createElement('style');
style.textContent = `
    .ripple {
        position: absolute;
        border-radius: 50%;
        background: rgba(102, 126, 234, 0.3);
        animation: ripple-animation 0.6s ease-out;
        pointer-events: none;
    }
    
    @keyframes ripple-animation {
        from {
            transform: scale(0);
            opacity: 1;
        }
        to {
            transform: scale(1);
            opacity: 0;
        }
    }
    
    .click-area {
        position: relative;
        overflow: hidden;
    }
`;
document.head.appendChild(style);