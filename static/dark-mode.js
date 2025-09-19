// Dark Mode Toggle Functionality
class DarkModeToggle {
    constructor() {
        this.isDarkMode = localStorage.getItem('darkMode') === 'true';
        this.isHighContrast = localStorage.getItem('highContrast') === 'true';
        this.init();
    }

    init() {
        this.applyTheme();
        this.createToggleButton();
        this.bindEvents();
    }

    applyTheme() {
        const body = document.body;
        const html = document.documentElement;
        
        // Remove existing theme classes
        body.classList.remove('dark-mode', 'high-contrast-mode');
        html.classList.remove('dark-mode', 'high-contrast-mode');
        
        // Apply current theme
        if (this.isHighContrast) {
            body.classList.add('high-contrast-mode');
            html.classList.add('high-contrast-mode');
        } else if (this.isDarkMode) {
            body.classList.add('dark-mode');
            html.classList.add('dark-mode');
        }
    }

    createToggleButton() {
        // Check if toggle already exists
        if (document.getElementById('theme-toggle')) {
            return;
        }

        const toggleButton = document.createElement('button');
        toggleButton.id = 'theme-toggle';
        toggleButton.className = 'theme-toggle-btn';
        toggleButton.innerHTML = this.getToggleIcon();
        toggleButton.setAttribute('aria-label', 'Toggle dark mode');
        toggleButton.setAttribute('title', this.getToggleTitle());

        // Add to header
        const header = document.querySelector('header');
        if (header) {
            const navContainer = header.querySelector('.flex.items-center.gap-9');
            if (navContainer) {
                navContainer.appendChild(toggleButton);
            }
        }
    }

    getToggleIcon() {
        if (this.isHighContrast) {
            return `
                <svg xmlns="http://www.w3.org/2000/svg" width="20px" height="20px" fill="currentColor" viewBox="0 0 256 256">
                    <path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm0,192a88,88,0,1,1,88-88A88.1,88.1,0,0,1,128,216ZM128,72a56,56,0,1,0,56,56A56.06,56.06,0,0,0,128,72Zm0,96a40,40,0,1,1,40-40A40,40,0,0,1,128,168Z"/>
                </svg>
            `;
        } else if (this.isDarkMode) {
            return `
                <svg xmlns="http://www.w3.org/2000/svg" width="20px" height="20px" fill="currentColor" viewBox="0 0 256 256">
                    <path d="M233.54,142.23a8,8,0,0,0-8-2,88.08,88.08,0,0,1-109.8-109.8,8,8,0,0,0-10-10,104.84,104.84,0,0,0-52.91,37A104,104,0,0,0,136,224a103.09,103.09,0,0,0,62.52-20.88,104.84,104.84,0,0,0,37-52.91A8,8,0,0,0,233.54,142.23ZM188.9,190.34A88,88,0,0,1,65.66,67.11a89,89,0,0,1,31.4-26.46,104,104,0,0,0,118.3,118.3A89,89,0,0,1,188.9,190.34Z"/>
                </svg>
            `;
        } else {
            return `
                <svg xmlns="http://www.w3.org/2000/svg" width="20px" height="20px" fill="currentColor" viewBox="0 0 256 256">
                    <path d="M120,40V16a8,8,0,0,1,16,0V40a8,8,0,0,1-16,0Zm72,88a64,64,0,1,1-64-64A64.07,64.07,0,0,1,192,128Zm-16,0a48,48,0,1,0-48,48A48.05,48.05,0,0,0,176,128ZM58.34,69.66A8,8,0,0,1,69.66,58.34l16,16a8,8,0,0,1-11.32,11.32Zm0,116.68-16-16a8,8,0,0,1,11.32-11.32l16,16a8,8,0,0,1-11.32,11.32ZM192,72a8,8,0,0,1,5.66-2.34l16-16a8,8,0,0,1,11.32,11.32l-16,16A8,8,0,0,1,192,72Zm5.66,114.34a8,8,0,0,1-11.32,11.32l-16-16a8,8,0,0,1,11.32-11.32ZM48,128a8,8,0,0,1-8-8H16a8,8,0,0,1,0-16H40A8,8,0,0,1,48,128Zm80,80a8,8,0,0,1-8,8v24a8,8,0,0,1-16,0V216A8,8,0,0,1,128,208Zm112-88a8,8,0,0,1-8,8H208a8,8,0,0,1,0-16h24A8,8,0,0,1,240,120Z"/>
                </svg>
            `;
        }
    }

    getToggleTitle() {
        if (this.isHighContrast) {
            return 'Switch to Light Mode';
        } else if (this.isDarkMode) {
            return 'Switch to High Contrast Mode';
        } else {
            return 'Switch to Dark Mode';
        }
    }

    bindEvents() {
        const toggleButton = document.getElementById('theme-toggle');
        if (toggleButton) {
            toggleButton.addEventListener('click', () => this.toggleTheme());
        }
    }

    toggleTheme() {
        if (this.isHighContrast) {
            // High contrast -> Light mode
            this.isHighContrast = false;
            this.isDarkMode = false;
        } else if (this.isDarkMode) {
            // Dark mode -> High contrast mode
            this.isDarkMode = false;
            this.isHighContrast = true;
        } else {
            // Light mode -> Dark mode
            this.isDarkMode = true;
            this.isHighContrast = false;
        }

        // Save to localStorage
        localStorage.setItem('darkMode', this.isDarkMode);
        localStorage.setItem('highContrast', this.isHighContrast);

        // Apply new theme
        this.applyTheme();
        
        // Update toggle button
        const toggleButton = document.getElementById('theme-toggle');
        if (toggleButton) {
            toggleButton.innerHTML = this.getToggleIcon();
            toggleButton.setAttribute('title', this.getToggleTitle());
        }
    }
}

// Initialize dark mode toggle when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new DarkModeToggle();
});

// CSS for the toggle button
const style = document.createElement('style');
style.textContent = `
    .theme-toggle-btn {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 40px;
        height: 40px;
        border: none;
        border-radius: 8px;
        background: #f1f5f9;
        color: #475569;
        cursor: pointer;
        transition: all 0.2s ease;
        margin-left: 8px;
    }

    .theme-toggle-btn:hover {
        background: #e2e8f0;
        color: #334155;
    }

    .theme-toggle-btn:focus {
        outline: 2px solid #3b82f6;
        outline-offset: 2px;
    }

    /* Dark mode styles */
    .dark-mode {
        --bg-primary: #0f172a;
        --bg-secondary: #1e293b;
        --bg-tertiary: #334155;
        --text-primary: #f8fafc;
        --text-secondary: #cbd5e1;
        --text-muted: #94a3b8;
        --border-color: #475569;
        --accent-color: #3b82f6;
        --accent-hover: #2563eb;
    }

    .dark-mode body {
        background-color: var(--bg-primary) !important;
        color: var(--text-primary) !important;
    }

    .dark-mode .bg-slate-50 {
        background-color: var(--bg-secondary) !important;
    }

    .dark-mode .bg-white {
        background-color: var(--bg-tertiary) !important;
    }

    .dark-mode .text-\\[\\#0d141c\\] {
        color: var(--text-primary) !important;
    }

    .dark-mode .text-\\[\\#101418\\] {
        color: var(--text-primary) !important;
    }

    .dark-mode .text-\\[\\#49719c\\] {
        color: var(--text-secondary) !important;
    }

    .dark-mode .text-\\[\\#5c728a\\] {
        color: var(--text-muted) !important;
    }

    .dark-mode .border-\\[\\#cedbe8\\] {
        border-color: var(--border-color) !important;
    }

    .dark-mode .border-\\[\\#e7edf4\\] {
        border-color: var(--border-color) !important;
    }

    .dark-mode .bg-\\[\\#e7edf4\\] {
        background-color: var(--bg-tertiary) !important;
    }

    .dark-mode .theme-toggle-btn {
        background: var(--bg-tertiary);
        color: var(--text-primary);
    }

    .dark-mode .theme-toggle-btn:hover {
        background: var(--bg-secondary);
    }

    /* High contrast mode styles */
    .high-contrast-mode {
        --bg-primary: #000000;
        --bg-secondary: #1a1a1a;
        --bg-tertiary: #333333;
        --text-primary: #ffffff;
        --text-secondary: #ffff00;
        --text-muted: #cccccc;
        --border-color: #ffffff;
        --accent-color: #00ff00;
        --accent-hover: #00cc00;
    }

    .high-contrast-mode body {
        background-color: var(--bg-primary) !important;
        color: var(--text-primary) !important;
    }

    .high-contrast-mode .bg-slate-50 {
        background-color: var(--bg-secondary) !important;
    }

    .high-contrast-mode .bg-white {
        background-color: var(--bg-tertiary) !important;
    }

    .high-contrast-mode .text-\\[\\#0d141c\\] {
        color: var(--text-primary) !important;
    }

    .high-contrast-mode .text-\\[\\#101418\\] {
        color: var(--text-primary) !important;
    }

    .high-contrast-mode .text-\\[\\#49719c\\] {
        color: var(--text-secondary) !important;
    }

    .high-contrast-mode .text-\\[\\#5c728a\\] {
        color: var(--text-muted) !important;
    }

    .high-contrast-mode .border-\\[\\#cedbe8\\] {
        border-color: var(--border-color) !important;
    }

    .high-contrast-mode .border-\\[\\#e7edf4\\] {
        border-color: var(--border-color) !important;
    }

    .high-contrast-mode .bg-\\[\\#e7edf4\\] {
        background-color: var(--bg-tertiary) !important;
    }

    .high-contrast-mode .theme-toggle-btn {
        background: var(--bg-tertiary);
        color: var(--text-primary);
        border: 2px solid var(--border-color);
    }

    .high-contrast-mode .theme-toggle-btn:hover {
        background: var(--accent-color);
        color: var(--bg-primary);
    }

    /* Enhanced contrast for links and buttons */
    .high-contrast-mode a {
        text-decoration: underline !important;
    }

    .high-contrast-mode button {
        border: 2px solid var(--border-color) !important;
    }

    .high-contrast-mode .bg-\\[\\#0b79ee\\] {
        background-color: var(--accent-color) !important;
        color: var(--bg-primary) !important;
    }

    .high-contrast-mode .bg-\\[\\#0b79ef\\] {
        background-color: var(--accent-color) !important;
        color: var(--bg-primary) !important;
    }
`;
document.head.appendChild(style);
