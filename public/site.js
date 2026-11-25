(function () {
  var root = document.documentElement, KEY = 'sl_theme';                    // same key as the app, so the choice carries over
  function get() { try { var t = localStorage.getItem(KEY); if (t === 'light' || t === 'dark') return t; } catch (e) {} return matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'; }
  function apply(t) { root.dataset.theme = t; var m = document.querySelector('meta[name="theme-color"]'); if (m) m.content = t === 'dark' ? '#06100C' : '#F6F9F7'; var b = document.getElementById('themeBtn'); if (b) b.setAttribute('aria-label', t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'); }
  apply(get());
  document.addEventListener('click', function (e) {
    if (e.target.closest('#themeBtn')) { var t = root.dataset.theme === 'dark' ? 'light' : 'dark'; try { localStorage.setItem(KEY, t); } catch (x) {} apply(t); }
    var mb = e.target.closest('#menuBtn'); if (mb) { var n = document.getElementById('nav'), o = n.classList.toggle('open'); mb.setAttribute('aria-expanded', o); }
    else if (e.target.closest('#nav a')) { document.getElementById('nav').classList.remove('open'); }
  });
  var y = document.getElementById('yr'); if (y) y.textContent = new Date().getFullYear();
})();
