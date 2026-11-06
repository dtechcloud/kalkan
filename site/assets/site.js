(() => {
  const root = document.documentElement;
  const KEY = 'kalkan-site-v2';
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem(KEY) || '{}') || {}; } catch (e) { saved = {}; }
  const save = () => { try { localStorage.setItem(KEY, JSON.stringify(saved)); } catch (e) { /* no storage */ } };

  // Language: #tr or #en in the address wins, then the stored choice, then English.
  const setLang = (lang) => {
    root.setAttribute('data-lang', lang);
    root.setAttribute('lang', lang);
    const title = root.getAttribute(lang === 'en' ? 'data-title-en' : 'data-title-tr');
    if (title) document.title = title;
    document.querySelectorAll('[data-lang-set]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.langSet === lang)));
    // Carry the language to the other pages, also where browser storage is off (file://).
    document.querySelectorAll('a[href]').forEach((a) => {
      const match = a.getAttribute('href').match(/^([\w-]+\.html)(#(?:en|tr))?$/);
      if (match) a.setAttribute('href', match[1] + (lang === 'tr' ? '#tr' : ''));
    });
  };
  const hashLang = location.hash === '#en' ? 'en' : location.hash === '#tr' ? 'tr' : '';
  setLang(hashLang || (saved.lang === 'tr' ? 'tr' : 'en'));

  // Theme: the stored choice, else the system setting.
  const lightQuery = matchMedia('(prefers-color-scheme: light)');
  const theme = () => root.getAttribute('data-theme') || (lightQuery.matches ? 'light' : 'dark');
  const paintThemeIcon = () => {
    const use = document.querySelector('[data-theme-toggle] use');
    if (use) use.setAttribute('href', theme() === 'dark' ? '#i-sun' : '#i-moon');
  };
  if (saved.theme === 'dark' || saved.theme === 'light') root.setAttribute('data-theme', saved.theme);
  paintThemeIcon();
  if (lightQuery.addEventListener) lightQuery.addEventListener('change', paintThemeIcon);

  const copyText = (text, onDone, onFail) => {
    try { navigator.clipboard.writeText(text).then(onDone, onFail); } catch (e) { onFail(); }
  };
  const selectNode = (node) => {
    const range = document.createRange();
    range.selectNodeContents(node);
    const selection = getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
  };

  document.addEventListener('click', (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;
    // An open header popover (contact, menu) closes on a click outside it.
    document.querySelectorAll('.top details[open]').forEach((d) => { if (!d.contains(target)) d.open = false; });
    const lang = target.closest('[data-lang-set]');
    if (lang) { saved.lang = lang.dataset.langSet; setLang(saved.lang); save(); return; }
    if (target.closest('[data-theme-toggle]')) {
      saved.theme = theme() === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', saved.theme);
      paintThemeIcon(); save(); return;
    }
    const tab = target.closest('[data-tab]');
    if (tab) {
      // A [data-tabs] group switches every [data-tabs] group of the page that has the same tab.
      const choice = tab.dataset.tab;
      const boxes = tab.closest('[data-tabs]') ? document.querySelectorAll('[data-tabs]') : [tab.closest('.use')];
      boxes.forEach((box) => {
        if (!box || !box.querySelector(`[data-tab="${choice}"]`)) return;
        box.querySelectorAll('[data-tab]').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === choice)));
        box.querySelectorAll('[data-pane]').forEach((p) => { p.hidden = p.dataset.pane !== choice; });
      });
      return;
    }
    const plain = target.closest('[data-copy-text]');
    if (plain) {
      copyText(plain.dataset.copyText,
        () => { plain.classList.add('done'); setTimeout(() => plain.classList.remove('done'), 1600); },
        () => { const link = plain.parentElement.querySelector('.big'); if (link) selectNode(link); });
      return;
    }
    const copy = target.closest('.copy');
    if (copy) {
      const code = copy.parentElement.querySelector('code');
      const text = code.textContent.replace(/^❯ /gm, '').replace(/^# .*\n/gm, '').trim();
      copyText(text, () => {
        copy.classList.add('done');
        copy.querySelector('use').setAttribute('href', '#i-check');
        setTimeout(() => { copy.classList.remove('done'); copy.querySelector('use').setAttribute('href', '#i-copy'); }, 1600);
      }, () => selectNode(code));
    }
  });

  // Docs: the side table of contents marks the last section that starts above a reading line.
  // The line sits just below the anchor offset (scroll-padding-top), so a jump from a link marks its own section.
  const tocLinks = Array.from(document.querySelectorAll('.toc-side a[href^="#"]'));
  const tocSections = tocLinks.map((a) => document.getElementById(a.getAttribute('href').slice(1)));
  if (tocLinks.length && tocSections.every(Boolean)) {
    let queued = false;
    const markSection = () => {
      queued = false;
      const line = (parseFloat(getComputedStyle(root).scrollPaddingTop) || 88) + 24;
      let current = -1;
      tocSections.forEach((section, i) => { if (section.getBoundingClientRect().top <= line) current = i; });
      tocLinks.forEach((a, i) => { if (i === current) a.setAttribute('aria-current', 'location'); else a.removeAttribute('aria-current'); });
    };
    const queue = () => { if (!queued) { queued = true; requestAnimationFrame(markSection); } };
    addEventListener('scroll', queue, { passive: true });
    addEventListener('resize', queue);
    markSection();
  }
})();
