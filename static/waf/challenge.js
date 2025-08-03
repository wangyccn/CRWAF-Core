// SHA-256 implementation for challenge computation
const SHA256 = (() => {
    const K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    function rightRotate(value, amount) {
        return (value >>> amount) | (value << (32 - amount));
    }

    function hash(msg) {
        const msgLen = msg.length;
        const msgBitLen = msgLen * 8;
        const numBlocks = ((msgLen + 8) >>> 6) + 1;
        const message = new Uint8Array(numBlocks * 64);
        
        for (let i = 0; i < msgLen; i++) {
            message[i] = msg.charCodeAt(i);
        }
        
        message[msgLen] = 0x80;
        const lenOffset = numBlocks * 64 - 8;
        for (let i = 7; i >= 0; i--) {
            message[lenOffset + i] = msgBitLen & 0xff;
            msgBitLen >>>= 8;
        }

        const H = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ];

        const W = new Array(64);
        
        for (let i = 0; i < numBlocks; i++) {
            const offset = i * 64;
            
            for (let j = 0; j < 16; j++) {
                W[j] = (message[offset + j * 4] << 24) |
                       (message[offset + j * 4 + 1] << 16) |
                       (message[offset + j * 4 + 2] << 8) |
                       (message[offset + j * 4 + 3]);
            }
            
            for (let j = 16; j < 64; j++) {
                const s0 = rightRotate(W[j - 15], 7) ^ rightRotate(W[j - 15], 18) ^ (W[j - 15] >>> 3);
                const s1 = rightRotate(W[j - 2], 17) ^ rightRotate(W[j - 2], 19) ^ (W[j - 2] >>> 10);
                W[j] = (W[j - 16] + s0 + W[j - 7] + s1) >>> 0;
            }

            let [a, b, c, d, e, f, g, h] = H;
            
            for (let j = 0; j < 64; j++) {
                const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
                const ch = (e & f) ^ (~e & g);
                const temp1 = (h + S1 + ch + K[j] + W[j]) >>> 0;
                const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
                const maj = (a & b) ^ (a & c) ^ (b & c);
                const temp2 = (S0 + maj) >>> 0;
                
                h = g;
                g = f;
                f = e;
                e = (d + temp1) >>> 0;
                d = c;
                c = b;
                b = a;
                a = (temp1 + temp2) >>> 0;
            }
            
            H[0] = (H[0] + a) >>> 0;
            H[1] = (H[1] + b) >>> 0;
            H[2] = (H[2] + c) >>> 0;
            H[3] = (H[3] + d) >>> 0;
            H[4] = (H[4] + e) >>> 0;
            H[5] = (H[5] + f) >>> 0;
            H[6] = (H[6] + g) >>> 0;
            H[7] = (H[7] + h) >>> 0;
        }

        let result = '';
        for (let i = 0; i < 8; i++) {
            result += ('00000000' + H[i].toString(16)).slice(-8);
        }
        return result;
    }

    return hash;
})();

// Challenge solver
class ChallengeSolver {
    constructor(challenge) {
        this.challenge = challenge;
        this.isRunning = false;
        this.solution = null;
        this.iterations = 0;
        this.startTime = 0;
    }

    async solve() {
        this.isRunning = true;
        this.startTime = Date.now();
        this.iterations = 0;
        
        const solutionNonce = this.generateNonce();
        const target = '0'.repeat(this.challenge.difficulty);
        
        while (this.isRunning) {
            const solution = this.iterations.toString();
            const input = this.challenge.nonce + solutionNonce + solution;
            const hash = SHA256(input);
            
            if (hash.startsWith(target)) {
                this.solution = {
                    challenge_id: this.challenge.challenge_id,
                    nonce: solutionNonce,
                    solution: solution,
                    iterations: this.iterations
                };
                return this.solution;
            }
            
            this.iterations++;
            
            // Yield control periodically to prevent blocking
            if (this.iterations % 1000 === 0) {
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }
        
        return null;
    }

    stop() {
        this.isRunning = false;
    }

    generateNonce() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return Array.from(array, byte => ('0' + byte.toString(16)).slice(-2)).join('');
    }

    getProgress() {
        const elapsed = Date.now() - this.startTime;
        const hashRate = this.iterations / (elapsed / 1000);
        return {
            iterations: this.iterations,
            elapsed: elapsed,
            hashRate: Math.round(hashRate)
        };
    }
}

// Behavior tracker
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
            if (now - lastMouseTime > 100) { // Throttle to every 100ms
                this.recordEvent('mouseMove', { x: e.clientX, y: e.clientY });
                lastMouseTime = now;
            }
        });

        // Click tracking
        document.addEventListener('click', (e) => {
            this.recordEvent('click', { x: e.clientX, y: e.clientY });
        });

        // Keyboard tracking
        document.addEventListener('keypress', (e) => {
            this.recordEvent('keypress', { key: e.key });
        });

        // Touch events for mobile
        document.addEventListener('touchstart', (e) => {
            if (e.touches.length > 0) {
                const touch = e.touches[0];
                this.recordEvent('touch', { x: touch.clientX, y: touch.clientY });
            }
        });

        // Page visibility
        document.addEventListener('visibilitychange', () => {
            this.recordEvent('visibility', { hidden: document.hidden });
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
        // Check if we have minimum required events
        const eventTypes = new Set(this.events.map(e => e.event_type));
        const requiredEvents = ['mouseMove', 'click'];
        
        for (const required of requiredEvents) {
            if (!eventTypes.has(required)) {
                return false;
            }
        }

        // Check timing patterns
        if (this.events.length < 5) {
            return false;
        }

        // Calculate time intervals between events
        const intervals = [];
        for (let i = 1; i < this.events.length; i++) {
            intervals.push(this.events[i].timestamp - this.events[i - 1].timestamp);
        }

        // Check for too regular intervals (bot-like)
        const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const variance = intervals.reduce((sum, interval) => {
            return sum + Math.pow(interval - avgInterval, 2);
        }, 0) / intervals.length;

        // If variance is too low, it's likely a bot
        if (variance < 100) {
            return false;
        }

        return true;
    }
}

// Main challenge handler
async function startChallenge(challenge) {
    const progressBar = document.getElementById('progress');
    const statusElement = document.getElementById('status');
    const computingElement = document.getElementById('computing');
    
    // Start behavior tracking
    const behaviorTracker = new BehaviorTracker();
    
    // Start progress animation
    progressBar.style.width = '100%';
    
    // Wait for initial delay (2 seconds)
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Show computing status
    statusElement.textContent = '正在进行安全计算...';
    computingElement.style.display = 'block';
    
    // Start challenge solving
    const solver = new ChallengeSolver(challenge);
    const solutionPromise = solver.solve();
    
    // Update progress periodically
    const progressInterval = setInterval(() => {
        const progress = solver.getProgress();
        const hashRateText = progress.hashRate > 1000 
            ? `${(progress.hashRate / 1000).toFixed(1)}k` 
            : progress.hashRate;
        statusElement.textContent = `正在进行安全计算... (${hashRateText} 次/秒)`;
    }, 100);
    
    try {
        // Wait for solution
        const solution = await solutionPromise;
        clearInterval(progressInterval);
        
        if (solution) {
            // Verify behavior
            const behaviorEvents = behaviorTracker.getEvents();
            const isHuman = behaviorTracker.isHumanBehavior();
            
            if (!isHuman) {
                statusElement.textContent = '行为验证失败，请重试...';
                setTimeout(() => {
                    location.reload();
                }, 2000);
                return;
            }
            
            // Submit solution
            statusElement.textContent = '验证成功，正在跳转...';
            computingElement.style.display = 'none';
            
            const response = await fetch('/waf/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    solution: solution,
                    behavior: behaviorEvents
                })
            });
            
            if (response.ok) {
                // Reload page to continue
                setTimeout(() => {
                    location.reload();
                }, 1000);
            } else {
                statusElement.textContent = '验证失败，请重试...';
                setTimeout(() => {
                    location.reload();
                }, 2000);
            }
        }
    } catch (error) {
        clearInterval(progressInterval);
        statusElement.textContent = '验证过程出错，请刷新页面重试...';
        console.error('Challenge error:', error);
    }
}

// Cookie utilities
const CookieUtil = {
    set(name, value, days = 1) {
        const date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        const expires = `expires=${date.toUTCString()}`;
        document.cookie = `${name}=${value};${expires};path=/;SameSite=Strict`;
    },
    
    get(name) {
        const nameEQ = name + "=";
        const ca = document.cookie.split(';');
        for (let i = 0; i < ca.length; i++) {
            let c = ca[i];
            while (c.charAt(0) === ' ') c = c.substring(1, c.length);
            if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
        }
        return null;
    }
};

// Export for use in other scripts
window.ChallengeSolver = ChallengeSolver;
window.BehaviorTracker = BehaviorTracker;
window.CookieUtil = CookieUtil;