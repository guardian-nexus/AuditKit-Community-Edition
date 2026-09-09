/**
 * AuditKit Cookie Consent Manager
 * Manages cookie preferences and gates the marketing pixels (Google Ads, Reddit).
 */
(function () {
  'use strict';

  var STORAGE_KEY = 'auditkit_cookie_consent';

  // Bump when the vendors behind a category change. A stored choice from an
  // earlier version is not consent for the new vendor, so the banner is shown
  // again rather than silently reused. v2 added the Reddit Ads pixel.
  var CONSENT_VERSION = 2;

  // Google Ads. Both the tag and its conversion event are marketing, not analytics.
  var GTAG_ID = 'AW-17730440946';
  var GTAG_TRIAL_CONVERSION = 'AW-17730440946/SbTxCICVs_IcEPKdxIZC';

  // Reddit Ads pixel. Advertiser ID from Reddit Ads Manager > Events Manager.
  var REDDIT_PIXEL_ID = 'a2_jn2kx21yst59';

  // Trial CTAs all point at the same Stripe checkout.
  var TRIAL_LINK_MATCH = 'buy.stripe.com';
  var TRIAL_VALUE = 297.0;
  var TRIAL_CURRENCY = 'USD';

  // Expose global consent state
  window.auditKitConsent = { necessary: true, analytics: false, marketing: false };

  function getConsent() {
    try {
      var raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      var saved = JSON.parse(raw);
      // Anything stored before the current vendor list is treated as no answer.
      if (!saved || saved.v !== CONSENT_VERSION) return null;
      return saved;
    } catch (e) {}
    return null;
  }

  function setConsent(prefs) {
    prefs.v = CONSENT_VERSION;
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
    } catch (e) {}
    window.auditKitConsent = prefs;
    applyConsent(prefs);
  }

  function applyConsent(prefs) {
    if (prefs.marketing) {
      loadGtag();
      loadRdt();
    }
  }

  function loadGtag() {
    if (document.getElementById('auditkit-gtag')) return;
    var s = document.createElement('script');
    s.id = 'auditkit-gtag';
    s.async = true;
    s.src = 'https://www.googletagmanager.com/gtag/js?id=' + GTAG_ID;
    document.head.appendChild(s);
    window.dataLayer = window.dataLayer || [];
    function gtag() { dataLayer.push(arguments); }
    window.gtag = gtag;
    gtag('js', new Date());
    gtag('config', GTAG_ID);
  }

  function loadRdt() {
    if (REDDIT_PIXEL_ID.indexOf('a2_') !== 0) return;
    if (window.rdt) return;

    // Queueing stub, so events fired before pixel.js lands are not dropped.
    var rdt = function () {
      if (rdt.sendEvent) rdt.sendEvent.apply(rdt, arguments);
      else rdt.callQueue.push(arguments);
    };
    rdt.callQueue = [];
    window.rdt = rdt;

    var s = document.createElement('script');
    s.id = 'auditkit-rdt';
    s.async = true;
    s.src = 'https://www.redditstatic.com/ads/pixel.js?pixel_id=' + REDDIT_PIXEL_ID;
    document.head.appendChild(s);

    rdt('init', REDDIT_PIXEL_ID, { optOut: false, useDecimalCurrencyValues: true });
    rdt('track', 'PageVisit');
  }

  // ---------- Conversion tracking ----------

  // Two distinct moments, deliberately weighted differently.
  //
  //   checkoutReached()  a CTA click. The visitor reached Stripe; they have not
  //                      signed up for anything. Secondary signal only, so
  //                      campaigns do not optimise toward checkout bounces.
  //
  //   trialStarted(id)   the post-checkout redirect landed on trial-started.html,
  //                      which only happens when a trial actually began. This is
  //                      the conversion worth bidding on.

  function marketingAllowed() {
    var prefs = window.auditKitConsent;
    return !!(prefs && prefs.marketing);
  }

  function checkoutReached() {
    if (!marketingAllowed()) return;

    // Reddit records this as a funnel step, not a conversion event. Google gets
    // nothing here: its conversion action belongs to the trial start below, and
    // firing the same label twice would double-count one funnel.
    if (typeof window.rdt === 'function') {
      window.rdt('track', 'ViewContent');
    }
  }

  // id is the Stripe checkout session id. It doubles as the deduplication key:
  // the same id appears on the webhook's session object, so a server-side
  // Conversions API call can later be matched to this event rather than
  // counting the same trial twice.
  function trialStarted(id) {
    if (!id || !marketingAllowed()) return false;

    if (typeof window.gtag === 'function') {
      window.gtag('event', 'conversion', {
        send_to: GTAG_TRIAL_CONVERSION,
        value: TRIAL_VALUE,
        currency: TRIAL_CURRENCY,
        transaction_id: id
      });
    }

    if (typeof window.rdt === 'function') {
      window.rdt('track', 'SignUp', {
        value: TRIAL_VALUE,
        currency: TRIAL_CURRENCY,
        conversionId: id
      });
    }

    return true;
  }

  // Delegated so the trial CTAs stay plain links on every page. Capture phase
  // means it still fires if a handler downstream stops propagation.
  function bindTrialLinks() {
    document.addEventListener('click', function (e) {
      var el = e.target;
      if (!el || typeof el.closest !== 'function') return;
      if (el.closest('a[href*="' + TRIAL_LINK_MATCH + '"]')) checkoutReached();
    }, true);
  }

  window.auditKitTrack = { checkoutReached: checkoutReached, trialStarted: trialStarted };

  // Reopening the preference centre. Consent has to be as easy to withdraw as
  // it was to give, and until now a stored choice was final: the banner never
  // returned and nothing else opened the modal.
  window.auditKitCookies = { open: function () { showModal(); } };

  function bindPreferenceLinks() {
    document.addEventListener('click', function (e) {
      var el = e.target;
      if (!el || typeof el.closest !== 'function') return;
      var link = el.closest('[data-cookie-preferences]');
      if (!link) return;
      e.preventDefault();
      showModal();
    });
  }

  // ---------- UI ----------

  function injectStyles() {
    var css = document.createElement('style');
    css.textContent =
      '.cc-banner{position:fixed;bottom:0;left:0;right:0;background:#0f172a;color:#e2e8f0;padding:1.25rem 1.5rem;z-index:10000;display:flex;align-items:center;justify-content:space-between;gap:1.5rem;font-family:Inter,-apple-system,BlinkMacSystemFont,sans-serif;font-size:.9rem;box-shadow:0 -2px 12px rgba(0,0,0,.3)}' +
      '.cc-banner p{margin:0;line-height:1.5;flex:1}' +
      '.cc-banner-actions{display:flex;gap:.75rem;flex-shrink:0}' +
      '.cc-btn{padding:.5rem 1.25rem;border-radius:6px;font-weight:600;font-size:.85rem;cursor:pointer;border:none;transition:background .15s}' +
      '.cc-btn-accept{background:#10b981;color:#fff}' +
      '.cc-btn-accept:hover{background:#059669}' +
      '.cc-btn-manage{background:transparent;color:#94a3b8;border:1px solid #334155}' +
      '.cc-btn-manage:hover{color:#e2e8f0;border-color:#475569}' +
      '.cc-btn-reject{background:transparent;color:#94a3b8;border:1px solid #334155}' +
      '.cc-btn-reject:hover{color:#e2e8f0;border-color:#475569}' +
      '.cc-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.6);z-index:10001;display:flex;align-items:center;justify-content:center;font-family:Inter,-apple-system,BlinkMacSystemFont,sans-serif}' +
      '.cc-modal{background:#fff;border-radius:8px;padding:2rem;max-width:480px;width:90%;max-height:90vh;overflow-y:auto;color:#334155}' +
      '.cc-modal h2{color:#0f172a;font-size:1.25rem;margin-bottom:1rem}' +
      '.cc-modal p{font-size:.9rem;line-height:1.6;color:#475569;margin-bottom:1.5rem}' +
      '.cc-category{display:flex;align-items:center;justify-content:space-between;padding:1rem 0;border-top:1px solid #e2e8f0}' +
      '.cc-category-info h4{font-size:.95rem;color:#0f172a;margin:0 0 .25rem}' +
      '.cc-category-info p{font-size:.8rem;color:#64748b;margin:0}' +
      '.cc-toggle{position:relative;width:44px;height:24px;flex-shrink:0;margin-left:1rem}' +
      '.cc-toggle input{opacity:0;width:0;height:0}' +
      '.cc-toggle-slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:#cbd5e1;border-radius:24px;transition:background .2s}' +
      '.cc-toggle-slider::before{content:"";position:absolute;height:18px;width:18px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:transform .2s}' +
      '.cc-toggle input:checked+.cc-toggle-slider{background:#10b981}' +
      '.cc-toggle input:checked+.cc-toggle-slider::before{transform:translateX(20px)}' +
      '.cc-toggle input:disabled+.cc-toggle-slider{background:#10b981;opacity:.6;cursor:default}' +
      '.cc-modal-actions{display:flex;gap:.75rem;margin-top:1.5rem}' +
      '.cc-btn-save{background:#0f172a;color:#fff;padding:.6rem 1.5rem;border-radius:6px;font-weight:600;font-size:.9rem;cursor:pointer;border:none}' +
      '.cc-btn-save:hover{background:#1e293b}' +
      '.cc-btn-accept-all{background:#10b981;color:#fff;padding:.6rem 1.5rem;border-radius:6px;font-weight:600;font-size:.9rem;cursor:pointer;border:none}' +
      '.cc-btn-accept-all:hover{background:#059669}' +
      '@media(max-width:640px){.cc-banner{flex-direction:column;text-align:center}.cc-banner-actions{width:100%;justify-content:center}}';
    document.head.appendChild(css);
  }

  function showBanner() {
    var banner = document.createElement('div');
    banner.className = 'cc-banner';
    banner.id = 'cc-banner';
    banner.innerHTML =
      '<p>We use cookies to measure site usage and improve your experience. You can manage your preferences at any time.</p>' +
      '<div class="cc-banner-actions">' +
      '<button class="cc-btn cc-btn-reject" id="cc-reject-all">Reject All</button>' +
      '<button class="cc-btn cc-btn-manage" id="cc-manage">Manage Preferences</button>' +
      '<button class="cc-btn cc-btn-accept" id="cc-accept-all">Accept All</button>' +
      '</div>';
    document.body.appendChild(banner);

    document.getElementById('cc-accept-all').addEventListener('click', function () {
      setConsent({ necessary: true, analytics: true, marketing: true });
      closeBanner();
    });

    document.getElementById('cc-reject-all').addEventListener('click', function () {
      setConsent({ necessary: true, analytics: false, marketing: false });
      closeBanner();
    });

    document.getElementById('cc-manage').addEventListener('click', function () {
      closeBanner();
      showModal();
    });
  }

  function closeBanner() {
    var b = document.getElementById('cc-banner');
    if (b) b.remove();
  }

  function showModal() {
    var current = getConsent() || { necessary: true, analytics: false, marketing: false };

    var overlay = document.createElement('div');
    overlay.className = 'cc-overlay';
    overlay.id = 'cc-overlay';
    overlay.innerHTML =
      '<div class="cc-modal">' +
      '<h2>Cookie Preferences</h2>' +
      '<p>Choose which cookies you want to allow. Necessary cookies are required for the site to function and cannot be disabled.</p>' +
      '<div class="cc-category">' +
      '<div class="cc-category-info"><h4>Necessary</h4><p>Required for core site functionality.</p></div>' +
      '<label class="cc-toggle"><input type="checkbox" checked disabled><span class="cc-toggle-slider"></span></label>' +
      '</div>' +
      '<div class="cc-category">' +
      '<div class="cc-category-info"><h4>Analytics</h4><p>Helps us understand how visitors use the site.</p></div>' +
      '<label class="cc-toggle"><input type="checkbox" id="cc-analytics" ' + (current.analytics ? 'checked' : '') + '><span class="cc-toggle-slider"></span></label>' +
      '</div>' +
      '<div class="cc-category">' +
      '<div class="cc-category-info"><h4>Marketing</h4><p>Used to measure the effectiveness of our advertising (Google Ads, Reddit).</p></div>' +
      '<label class="cc-toggle"><input type="checkbox" id="cc-marketing" ' + (current.marketing ? 'checked' : '') + '><span class="cc-toggle-slider"></span></label>' +
      '</div>' +
      '<div class="cc-modal-actions">' +
      '<button class="cc-btn-save" id="cc-save">Save Preferences</button>' +
      '<button class="cc-btn-accept-all" id="cc-modal-accept">Accept All</button>' +
      '</div>' +
      '</div>';

    document.body.appendChild(overlay);

    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) closeModal();
    });

    document.getElementById('cc-save').addEventListener('click', function () {
      setConsent({
        necessary: true,
        analytics: document.getElementById('cc-analytics').checked,
        marketing: document.getElementById('cc-marketing').checked
      });
      closeModal();
    });

    document.getElementById('cc-modal-accept').addEventListener('click', function () {
      setConsent({ necessary: true, analytics: true, marketing: true });
      closeModal();
    });
  }

  function closeModal() {
    var o = document.getElementById('cc-overlay');
    if (o) o.remove();
  }

  // ---------- Init ----------

  function init() {
    injectStyles();
    bindTrialLinks();
    bindPreferenceLinks();
    var saved = getConsent();
    if (saved) {
      window.auditKitConsent = saved;
      applyConsent(saved);
    } else {
      showBanner();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
