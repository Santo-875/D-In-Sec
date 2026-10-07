/**
 * D-In-Sec Mock Corporate Portal — Client-Side Interactions
 * Handles password toggle, file upload preview, sidebar navigation,
 * flash message auto-dismiss, and form animations.
 */

document.addEventListener('DOMContentLoaded', () => {
    initFlashAutoDismiss();
    initFileUpload();
    initSidebarNav();
    initFormAnimations();
    initThemeToggle();
});


/* ── Password Toggle ───────────────────────────────────── */
function togglePassword(fieldId) {
    const input = document.getElementById(fieldId);
    if (!input) return;

    const btn = input.parentElement.querySelector('.password-toggle');
    if (input.type === 'password') {
        input.type = 'text';
        if (btn) {
            btn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;
        }
    } else {
        input.type = 'password';
        if (btn) {
            btn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
        }
    }
}


/* ── Flash Message Auto-Dismiss ────────────────────────── */
function initFlashAutoDismiss() {
    const flashMessages = document.querySelectorAll('.flash-msg');
    flashMessages.forEach((msg, index) => {
        setTimeout(() => {
            msg.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
            msg.style.opacity = '0';
            msg.style.transform = 'translateX(30px)';
            setTimeout(() => msg.remove(), 400);
        }, 4000 + (index * 500));
    });
}


/* ── File Upload Preview ───────────────────────────────── */
function initFileUpload() {
    const fileInput = document.getElementById('document');
    const dropZone = document.getElementById('file-drop-zone');
    const fileSelected = document.getElementById('file-selected');
    const fileNameDisplay = document.getElementById('file-name-display');
    const uploadContent = dropZone?.querySelector('.file-upload-content');

    if (!fileInput || !dropZone) return;

    // File input change
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            const file = fileInput.files[0];
            showSelectedFile(file.name);
        }
    });

    // Drag and drop
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            fileInput.files = e.dataTransfer.files;
            showSelectedFile(e.dataTransfer.files[0].name);
        }
    });

    function showSelectedFile(name) {
        if (uploadContent) uploadContent.style.display = 'none';
        if (fileSelected) {
            fileSelected.style.display = 'flex';
            if (fileNameDisplay) fileNameDisplay.textContent = name;
        }
    }
}


/* ── Sidebar Navigation ───────────────────────────────── */
function initSidebarNav() {
    const sidebarLinks = document.querySelectorAll('.sidebar-link');
    if (sidebarLinks.length === 0) return;

    sidebarLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            // Remove active from all
            sidebarLinks.forEach(l => l.classList.remove('active'));
            // Add active to clicked
            link.classList.add('active');

            // Smooth scroll to section
            const targetId = link.getAttribute('href');
            if (targetId && targetId.startsWith('#')) {
                e.preventDefault();
                const target = document.querySelector(targetId);
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            }
        });
    });
}


/* ── Form Input Animations ─────────────────────────────── */
function initFormAnimations() {
    const inputs = document.querySelectorAll('.input-wrapper input, .input-wrapper select, .input-wrapper textarea');

    inputs.forEach(input => {
        // Add filled class if input has value
        if (input.value) {
            input.classList.add('filled');
        }

        input.addEventListener('focus', () => {
            input.parentElement.classList.add('focused');
        });

        input.addEventListener('blur', () => {
            input.parentElement.classList.remove('focused');
            if (input.value) {
                input.classList.add('filled');
            } else {
                input.classList.remove('filled');
        });
    });
}

/* ── Theme Toggle ─────────────────────────────────────── */
function initThemeToggle() {
    const btn = document.getElementById('theme-toggle');
    
    const setIcon = (isDark) => {
        if (!btn) return;
        if (isDark) {
            btn.innerHTML = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="sun-icon"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>`;
            btn.setAttribute('title', 'Switch to Light Mode');
            btn.setAttribute('aria-label', 'Switch to Light Mode');
        } else {
            btn.innerHTML = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="moon-icon"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>`;
            btn.setAttribute('title', 'Switch to Dark Mode');
            btn.setAttribute('aria-label', 'Switch to Dark Mode');
        }
    };

    // Check saved theme or system preference
    const savedTheme = localStorage.getItem('theme');
    const isDark = savedTheme === 'dark' || (!savedTheme && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
    
    if (isDark) {
        document.documentElement.setAttribute('data-theme', 'dark');
        document.documentElement.setAttribute('data-bs-theme', 'dark');
    } else {
        document.documentElement.removeAttribute('data-theme');
        document.documentElement.setAttribute('data-bs-theme', 'light');
    }
    setIcon(isDark);
    
    if (btn) {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const current = document.documentElement.getAttribute('data-theme');
            if (current === 'dark') {
                document.documentElement.removeAttribute('data-theme');
                document.documentElement.setAttribute('data-bs-theme', 'light');
                localStorage.setItem('theme', 'light');
                setIcon(false);
            } else {
                document.documentElement.setAttribute('data-theme', 'dark');
                document.documentElement.setAttribute('data-bs-theme', 'dark');
                localStorage.setItem('theme', 'dark');
                setIcon(true);
            }
        });
    }
}
