// Loaded in <head> on every page so a saved choice applies before first paint.
(function () {
    var root = document.documentElement;
    var KEY = 'theme';
    var saved = null;
    try { saved = localStorage.getItem(KEY); } catch (e) { /* storage blocked */ }
    if (saved === 'light' || saved === 'dark') root.setAttribute('data-theme', saved);

    function current() {
        var chosen = root.getAttribute('data-theme');
        if (chosen) return chosen;
        var mq = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)');
        return mq && mq.matches ? 'light' : 'dark';
    }

    function relabel(btn) {
        var next = current() === 'dark' ? 'light' : 'dark';
        btn.setAttribute('aria-label', 'Switch to ' + next + ' theme');
        btn.title = 'Switch to ' + next + ' theme';
    }

    function init() {
        var btn = document.getElementById('theme-toggle');
        if (!btn) return;
        relabel(btn);
        btn.addEventListener('click', function () {
            var next = current() === 'dark' ? 'light' : 'dark';
            root.setAttribute('data-theme', next);
            try { localStorage.setItem(KEY, next); } catch (e) { /* storage blocked */ }
            relabel(btn);
        });
        var mq = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)');
        if (mq && mq.addEventListener) {
            mq.addEventListener('change', function () {
                if (!root.getAttribute('data-theme')) relabel(btn);
            });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
