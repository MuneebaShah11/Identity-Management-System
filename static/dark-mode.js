// Dark Mode Toggle Functionality
class DarkModeToggle {
    constructor() {
        this.isDarkMode = localStorage.getItem('darkMode') === 'true';
        this.isHighContrast = localStorage.getItem('highContrast') === 'true';
        this.init();
    }

    init() {
        console.log('DarkModeToggle: Initializing...');
        console.log('DarkModeToggle: Current state - isDarkMode:', this.isDarkMode, 'isHighContrast:', this.isHighContrast);
        this.applyTheme();
        this.createToggleButton();
        this.bindEvents();
        console.log('DarkModeToggle: Initialization complete');
    }

    applyTheme() {
        const body = document.body;
        const html = document.documentElement;
        
        console.log('DarkModeToggle: Applying theme...');
        
        // Remove existing theme classes
        body.classList.remove('dark-mode', 'high-contrast-mode');
        html.classList.remove('dark-mode', 'high-contrast-mode');
        
        // Apply current theme
        if (this.isHighContrast) {
            body.classList.add('high-contrast-mode');
            html.classList.add('high-contrast-mode');
            console.log('DarkModeToggle: Applied high contrast mode');
        } else if (this.isDarkMode) {
            body.classList.add('dark-mode');
            html.classList.add('dark-mode');
            console.log('DarkModeToggle: Applied dark mode');
        } else {
            console.log('DarkModeToggle: Applied light mode');
        }
    }

    createToggleButton() {
        // Check if toggle already exists
        if (document.getElementById('theme-toggle')) {
            console.log('DarkModeToggle: Toggle button already exists');
            return;
        }

        console.log('DarkModeToggle: Creating toggle button...');

        const toggleButton = document.createElement('button');
        toggleButton.id = 'theme-toggle';
        toggleButton.className = 'theme-toggle-btn';
        toggleButton.innerHTML = this.getToggleIcon();
        toggleButton.setAttribute('aria-label', 'Toggle dark mode');
        toggleButton.setAttribute('title', this.getToggleTitle());

        // Add to header - try multiple selectors for different portal layouts
        const header = document.querySelector('header');
        if (header) {
            console.log('DarkModeToggle: Header found, looking for navigation container...');
            
            // Try different navigation container selectors
            let navContainer = header.querySelector('.flex.items-center.gap-9');
            if (!navContainer) {
                navContainer = header.querySelector('.flex.items-center.gap-8');
            }
            if (!navContainer) {
                navContainer = header.querySelector('.flex.items-center.gap-4');
            }
            if (!navContainer) {
                // Look for any flex container with items-center
                navContainer = header.querySelector('.flex.items-center');
            }
            if (!navContainer) {
                // Fallback: add to the header directly
                navContainer = header;
            }
            
            if (navContainer) {
                navContainer.appendChild(toggleButton);
                console.log('DarkModeToggle: Toggle button added to navigation container');
            } else {
                console.log('DarkModeToggle: No suitable navigation container found');
            }
        } else {
            console.log('DarkModeToggle: No header found');
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
        console.log('DarkModeToggle: Toggling theme...');
        console.log('DarkModeToggle: Current state - isDarkMode:', this.isDarkMode, 'isHighContrast:', this.isHighContrast);
        
        if (this.isHighContrast) {
            // High contrast -> Light mode
            this.isHighContrast = false;
            this.isDarkMode = false;
            console.log('DarkModeToggle: Switching from high contrast to light mode');
        } else if (this.isDarkMode) {
            // Dark mode -> High contrast mode
            this.isDarkMode = false;
            this.isHighContrast = true;
            console.log('DarkModeToggle: Switching from dark mode to high contrast mode');
        } else {
            // Light mode -> Dark mode
            this.isDarkMode = true;
            this.isHighContrast = false;
            console.log('DarkModeToggle: Switching from light mode to dark mode');
        }

        // Save to localStorage
        localStorage.setItem('darkMode', this.isDarkMode);
        localStorage.setItem('highContrast', this.isHighContrast);
        console.log('DarkModeToggle: Saved to localStorage');

        // Apply new theme
        this.applyTheme();
        
        // Update toggle button
        const toggleButton = document.getElementById('theme-toggle');
        if (toggleButton) {
            toggleButton.innerHTML = this.getToggleIcon();
            toggleButton.setAttribute('title', this.getToggleTitle());
            console.log('DarkModeToggle: Updated toggle button');
        } else {
            console.log('DarkModeToggle: Toggle button not found for update');
        }
    }
}

// Initialize dark mode toggle when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new DarkModeToggle();
});

// Also initialize if DOM is already loaded (for dynamic content)
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new DarkModeToggle();
    });
} else {
    new DarkModeToggle();
}

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

    /* Force dark mode styles with higher specificity */
    html.dark-mode,
    html.dark-mode body,
    html.dark-mode * {
        color-scheme: dark;
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

    .dark-mode .bg-gray-50 {
        background-color: var(--bg-secondary) !important;
    }

    .dark-mode .bg-slate-50 {
        background-color: var(--bg-secondary) !important;
    }

    .dark-mode .border-b-\\[\\#eaedf1\\] {
        border-color: var(--border-color) !important;
    }

    .dark-mode .border-b-\\[\\#e7edf4\\] {
        border-color: var(--border-color) !important;
    }

    .dark-mode .bg-\\[\\#10b981\\] {
        background-color: var(--accent-color) !important;
    }

    .dark-mode .bg-\\[\\#0b79ee\\] {
        background-color: var(--accent-color) !important;
    }

    .dark-mode .bg-\\[\\#0b79ef\\] {
        background-color: var(--accent-color) !important;
    }

    .dark-mode .bg-\\[\\#0c77f2\\] {
        background-color: var(--accent-color) !important;
    }

    .dark-mode .text-white {
        color: var(--text-primary) !important;
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

    /* Force high contrast mode styles with higher specificity */
    html.high-contrast-mode,
    html.high-contrast-mode body,
    html.high-contrast-mode * {
        color-scheme: dark;
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

    .high-contrast-mode .bg-gray-50 {
        background-color: var(--bg-secondary) !important;
    }

    .high-contrast-mode .bg-slate-50 {
        background-color: var(--bg-secondary) !important;
    }

    .high-contrast-mode .border-b-\\[\\#eaedf1\\] {
        border-color: var(--border-color) !important;
    }

    .high-contrast-mode .border-b-\\[\\#e7edf4\\] {
        border-color: var(--border-color) !important;
    }

    .high-contrast-mode .bg-\\[\\#10b981\\] {
        background-color: var(--accent-color) !important;
        color: var(--bg-primary) !important;
    }

    .high-contrast-mode .text-white {
        color: var(--text-primary) !important;
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

    .high-contrast-mode .bg-\\[\\#0c77f2\\] {
        background-color: var(--accent-color) !important;
        color: var(--bg-primary) !important;
    }

    /* Additional styles for better coverage */
    .dark-mode .bg-gray-100 {
        background-color: var(--bg-tertiary) !important;
    }

    .dark-mode .bg-gray-200 {
        background-color: var(--bg-tertiary) !important;
    }

    .dark-mode .border-gray-200 {
        border-color: var(--border-color) !important;
    }

    .dark-mode .border-gray-300 {
        border-color: var(--border-color) !important;
    }

    .dark-mode .text-gray-600 {
        color: var(--text-secondary) !important;
    }

    .dark-mode .text-gray-700 {
        color: var(--text-primary) !important;
    }

    .dark-mode .text-gray-800 {
        color: var(--text-primary) !important;
    }

    .dark-mode .text-gray-900 {
        color: var(--text-primary) !important;
    }

    .high-contrast-mode .bg-gray-100 {
        background-color: var(--bg-tertiary) !important;
    }

    .high-contrast-mode .bg-gray-200 {
        background-color: var(--bg-tertiary) !important;
    }

    .high-contrast-mode .border-gray-200 {
        border-color: var(--border-color) !important;
    }

    .high-contrast-mode .border-gray-300 {
        border-color: var(--border-color) !important;
    }

    .high-contrast-mode .text-gray-600 {
        color: var(--text-secondary) !important;
    }

    .high-contrast-mode .text-gray-700 {
        color: var(--text-primary) !important;
    }

    .high-contrast-mode .text-gray-800 {
        color: var(--text-primary) !important;
    }

    .high-contrast-mode .text-gray-900 {
        color: var(--text-primary) !important;
    }

    /* Form elements and input styling */
    .dark-mode input[type="text"],
    .dark-mode input[type="email"],
    .dark-mode input[type="password"],
    .dark-mode input[type="number"],
    .dark-mode input[type="date"],
    .dark-mode select,
    .dark-mode textarea {
        background-color: var(--bg-tertiary) !important;
        color: var(--text-primary) !important;
        border-color: var(--border-color) !important;
    }

    .dark-mode input[type="text"]:focus,
    .dark-mode input[type="email"]:focus,
    .dark-mode input[type="password"]:focus,
    .dark-mode input[type="number"]:focus,
    .dark-mode input[type="date"]:focus,
    .dark-mode select:focus,
    .dark-mode textarea:focus {
        border-color: var(--accent-color) !important;
        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1) !important;
    }

    .high-contrast-mode input[type="text"],
    .high-contrast-mode input[type="email"],
    .high-contrast-mode input[type="password"],
    .high-contrast-mode input[type="number"],
    .high-contrast-mode input[type="date"],
    .high-contrast-mode select,
    .high-contrast-mode textarea {
        background-color: var(--bg-tertiary) !important;
        color: var(--text-primary) !important;
        border: 2px solid var(--border-color) !important;
    }

    .high-contrast-mode input[type="text"]:focus,
    .high-contrast-mode input[type="email"]:focus,
    .high-contrast-mode input[type="password"]:focus,
    .high-contrast-mode input[type="number"]:focus,
    .high-contrast-mode input[type="date"]:focus,
    .high-contrast-mode select:focus,
    .high-contrast-mode textarea:focus {
        border-color: var(--accent-color) !important;
        box-shadow: 0 0 0 3px rgba(0, 255, 0, 0.3) !important;
    }

    /* Card and container styling */
    .dark-mode .bg-white {
        background-color: var(--bg-tertiary) !important;
    }

    .dark-mode .shadow-sm,
    .dark-mode .shadow-md,
    .dark-mode .shadow-lg {
        box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.3), 0 1px 2px 0 rgba(0, 0, 0, 0.2) !important;
    }

    .high-contrast-mode .bg-white {
        background-color: var(--bg-tertiary) !important;
        border: 2px solid var(--border-color) !important;
    }

    .high-contrast-mode .shadow-sm,
    .high-contrast-mode .shadow-md,
    .high-contrast-mode .shadow-lg {
        box-shadow: 0 0 0 2px var(--border-color) !important;
    }
`;
document.head.appendChild(style);
