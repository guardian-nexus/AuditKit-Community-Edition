/* ==========================================================================
   AuditKit — Shared UI enhancements
   Active nav, scroll progress, code copy buttons, footer logo
   ========================================================================== */
(function() {
    'use strict';

    // -- Active Nav State --
    // Highlights the current page's nav link
    var path = window.location.pathname;
    var navLinks = document.querySelectorAll('.nav-links a:not(.nav-cta)');
    navLinks.forEach(function(link) {
        var href = link.getAttribute('href');
        if (!href || href.charAt(0) === '#' || href.indexOf('://') !== -1) return;
        // Skip hash-only links like /#features
        if (href.indexOf('#') !== -1 && href.indexOf('#') === href.indexOf('/') + 1) return;

        try {
            var linkPath = new URL(href, window.location.href).pathname;
            // Exact match
            if (linkPath === path) {
                link.classList.add('nav-active');
            }
            // Prefix match for sections (e.g., /docs/ matches /docs/faq.html)
            else if (linkPath.charAt(linkPath.length - 1) === '/' && path.indexOf(linkPath) === 0) {
                link.classList.add('nav-active');
            }
        } catch (e) {
            // Ignore malformed URLs
        }
    });

    // -- Scroll Progress Bar --
    var progressBar = document.createElement('div');
    progressBar.className = 'scroll-progress';
    progressBar.setAttribute('aria-hidden', 'true');
    document.body.appendChild(progressBar);

    function updateProgress() {
        var scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        var docHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
        var percent = docHeight > 0 ? (scrollTop / docHeight) * 100 : 0;
        progressBar.style.width = percent + '%';
    }

    window.addEventListener('scroll', updateProgress, { passive: true });
    updateProgress();

    // -- Code Copy Buttons --
    // Adds a "Copy" button to all code blocks
    var codeBlocks = document.querySelectorAll('pre, .code-block');
    codeBlocks.forEach(function(block) {
        // Skip nested pre inside .code-block to avoid duplicate buttons
        if (block.tagName === 'PRE' && block.closest('.code-block')) return;
        // Skip blocks that already have a wrapper (e.g., from duplicate script load)
        if (block.parentNode && block.parentNode.classList &&
            block.parentNode.classList.contains('code-block-wrap')) return;

        var wrapper = document.createElement('div');
        wrapper.className = 'code-block-wrap';
        block.parentNode.insertBefore(wrapper, block);
        wrapper.appendChild(block);

        var btn = document.createElement('button');
        btn.className = 'code-copy-btn';
        btn.textContent = 'Copy';
        btn.setAttribute('aria-label', 'Copy code to clipboard');
        btn.type = 'button';

        btn.addEventListener('click', function() {
            var text = (block.textContent || '').trim();

            // Modern clipboard API (requires secure context)
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(function() {
                    showCopied(btn);
                }, function() {
                    fallbackCopy(text, btn);
                });
            } else {
                fallbackCopy(text, btn);
            }
        });

        wrapper.appendChild(btn);
    });

    function showCopied(btn) {
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(function() {
            btn.textContent = 'Copy';
            btn.classList.remove('copied');
        }, 2000);
    }

    function fallbackCopy(text, btn) {
        var textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.left = '-9999px';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            showCopied(btn);
        } catch (e) {
            btn.textContent = 'Error';
            setTimeout(function() { btn.textContent = 'Copy'; }, 2000);
        }
        document.body.removeChild(textarea);
    }

    // -- Footer Logo Injection --
    // Injects the logo at the top of the footer without modifying HTML files
    var footer = document.querySelector('.footer-inner');
    if (footer) {
        var logoLink = document.createElement('a');
        logoLink.href = '/';
        logoLink.style.textDecoration = 'none';

        var logoImg = document.createElement('img');
        logoImg.className = 'footer-logo';
        logoImg.alt = 'AuditKit';

        // Determine correct relative path for logo based on page depth
        var depth = (path.match(/\//g) || []).length - 1;
        var prefix = '';
        for (var i = 0; i < depth; i++) { prefix += '../'; }
        if (prefix === '') prefix = './';
        logoImg.src = prefix + 'auditkit-logo-dark.svg';

        logoLink.appendChild(logoImg);
        footer.insertBefore(logoLink, footer.firstChild);
    }
})();
