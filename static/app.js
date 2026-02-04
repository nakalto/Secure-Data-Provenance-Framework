function copyText(text) {
  if (!text) return;
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text);
  } else {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
  }
}

function getParam(name) {
  const url = new URL(window.location.href);
  return url.searchParams.get(name);
}

document.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-copy]');
  if (btn) {
    copyText(btn.getAttribute('data-copy'));
    btn.classList.add('copied');
    setTimeout(() => btn.classList.remove('copied'), 900);
  }
});

document.addEventListener('DOMContentLoaded', () => {
  // Prefill case_id from URL: /verify?case_id=123
  const caseId = getParam('case_id');
  const caseInput = document.querySelector('input[name="case_id"]');
  if (caseInput && caseId && caseInput.value.trim() === '') {
    caseInput.value = caseId;
  }

  // History filters
  const filterAction = document.querySelector('[data-filter-action]');
  const filterText = document.querySelector('[data-filter-text]');
  const items = Array.from(document.querySelectorAll('[data-event]'));

  function applyFilters() {
    const action = filterAction ? filterAction.value.trim().toUpperCase() : '';
    const q = filterText ? filterText.value.trim().toLowerCase() : '';

    for (const el of items) {
      const elAction = (el.getAttribute('data-action') || '').toUpperCase();
      const hay = (el.getAttribute('data-search') || '').toLowerCase();

      const okAction = !action || elAction === action;
      const okText = !q || hay.includes(q);

      el.style.display = (okAction && okText) ? '' : 'none';
    }
  }

  if (filterAction) filterAction.addEventListener('change', applyFilters);
  if (filterText) filterText.addEventListener('input', applyFilters);
  if (items.length) applyFilters();
});
