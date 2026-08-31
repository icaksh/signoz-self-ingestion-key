// OTLP Proxy Admin — progressive enhancement (no HTMX, no framework).
// Handles the sidebar drawer, destructive-action confirmation dialog,
// clipboard copy, and a small toast.

(function () {
  'use strict';

  // --- sidebar drawer (persistent on desktop; off-canvas below 1024px) ---
  var sidebar = document.getElementById('sidebar');
  var sidebarToggle = document.getElementById('sidebar-toggle');
  var sidebarScrim = document.getElementById('sidebar-scrim');
  var narrowMQ = window.matchMedia('(max-width: 1023.98px)');

  if (sidebar && sidebarToggle && sidebarScrim) {
    function syncInert() {
      // On narrow screens the closed drawer must be removed from the tab
      // order; on desktop the persistent sidebar is always interactive.
      sidebar.inert = narrowMQ.matches && !sidebar.classList.contains('is-open');
    }

    function openSidebar() {
      sidebar.classList.add('is-open');
      sidebarScrim.hidden = false;
      sidebarToggle.setAttribute('aria-expanded', 'true');
      sidebarToggle.setAttribute('aria-label', 'Close navigation');
      syncInert();
      var first = sidebar.querySelector('a, button');
      if (first) first.focus();
    }

    function closeSidebar() {
      sidebar.classList.remove('is-open');
      sidebarScrim.hidden = true;
      sidebarToggle.setAttribute('aria-expanded', 'false');
      sidebarToggle.setAttribute('aria-label', 'Open navigation');
      syncInert();
      sidebarToggle.focus();
    }

    sidebarToggle.addEventListener('click', function () {
      if (sidebar.classList.contains('is-open')) {
        closeSidebar();
      } else {
        openSidebar();
      }
    });

    sidebarScrim.addEventListener('click', closeSidebar);

    // Selecting a destination closes the drawer on narrow layouts only.
    sidebar.addEventListener('click', function (e) {
      if (e.target.closest('a, button') && sidebar.classList.contains('is-open')) {
        closeSidebar();
      }
    });

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && sidebar.classList.contains('is-open')) {
        closeSidebar();
      }
    });

    narrowMQ.addEventListener('change', function () {
      if (!narrowMQ.matches) {
        sidebar.classList.remove('is-open');
        sidebarScrim.hidden = true;
        sidebarToggle.setAttribute('aria-expanded', 'false');
      }
      syncInert();
    });

    syncInert();
  }

  // --- toast ---
  function showToast(message) {
    var toast = document.createElement('div');
    toast.className = 'toast';
    toast.setAttribute('role', 'status');
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(function () { toast.remove(); }, 2500);
  }

  // --- clipboard copy ---
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).catch(function () {
        return legacyCopy(text);
      });
    }
    return Promise.resolve(legacyCopy(text));
  }

  function legacyCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
    } finally {
      ta.remove();
    }
  }

  document.querySelectorAll('[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      copyText(btn.getAttribute('data-copy')).then(function () {
        showToast('Copied to clipboard');
      });
    });
  });

  // --- usage charts (dynamic import, no inline scripts) ---
  var usageEl = document.querySelector('[data-tenant-id]');
  if (usageEl) {
    import('/static/chart.js').then(function (m) {
      m.loadUsage(parseInt(usageEl.getAttribute('data-tenant-id'), 10));
    });
  }

  // --- confirmation dialog (native <dialog>, explicit data contract) ---
  var dialog = document.getElementById('confirm-dialog');
  var confirmTitle = document.getElementById('confirm-title');
  var confirmMessage = document.getElementById('confirm-message');
  var confirmCancel = document.getElementById('confirm-cancel');
  var confirmSubmit = document.getElementById('confirm-submit');
  var pendingForm = null;

  if (dialog && confirmTitle && confirmMessage && confirmSubmit) {
    document.addEventListener('submit', function (e) {
      var form = e.target;
      var action = form.getAttribute('data-confirm-action');
      if (!action || pendingForm) return;
      e.preventDefault();
      pendingForm = form;

      confirmTitle.textContent = form.getAttribute('data-confirm-title') || 'Confirm action';
      confirmMessage.textContent = form.getAttribute('data-confirm-message') || '';
      confirmSubmit.textContent = action;

      var variant = form.getAttribute('data-confirm-variant') || 'default';
      confirmSubmit.className = 'btn ' + (variant === 'destructive' ? 'btn-danger' : 'btn-tinted');

      dialog.showModal();
      confirmCancel.focus();
    });

    confirmCancel.addEventListener('click', function () {
      dialog.close();
    });

    dialog.addEventListener('close', function () {
      var form = pendingForm;
      pendingForm = null;
      if (form && dialog.returnValue === 'confirm') {
        form.removeAttribute('data-confirm-action');
        form.submit();
      }
    });
  }
})();
