(function () {
    var pills = document.querySelectorAll('.articles-tag-pill');
    var cards = document.querySelectorAll('.article-card');
    var emptyState = document.querySelector('.articles-empty');
    if (!pills.length || !cards.length) return;

    var FADE_MS = 200;
    var emptyShowTimer = null;

    function applyFilter(filter) {
        var visibleCount = 0;
        cards.forEach(function (card) {
            var tags = (card.getAttribute('data-tags') || '').split(/\s+/);
            var match = filter === 'all' || tags.indexOf(filter) !== -1;
            if (match) {
                visibleCount++;
                card.classList.remove('is-hidden');
                card.style.display = '';
                requestAnimationFrame(function () { card.classList.remove('is-fading'); });
            } else {
                card.classList.add('is-fading');
                setTimeout(function () {
                    if (card.classList.contains('is-fading')) {
                        card.classList.add('is-hidden');
                        card.style.display = 'none';
                    }
                }, FADE_MS);
            }
        });

        if (emptyState) {
            if (emptyShowTimer) { clearTimeout(emptyShowTimer); emptyShowTimer = null; }
            if (visibleCount === 0) {
                emptyShowTimer = setTimeout(function () {
                    emptyState.classList.add('is-visible');
                }, FADE_MS);
            } else {
                emptyState.classList.remove('is-visible');
            }
        }
    }

    function setActivePill(filter) {
        var found = false;
        pills.forEach(function (p) {
            var match = p.getAttribute('data-filter') === filter;
            p.classList.toggle('is-active', match);
            p.setAttribute('aria-pressed', match ? 'true' : 'false');
            if (match) found = true;
        });
        return found;
    }

    function updateUrl(filter) {
        if (!window.history || !window.history.replaceState) return;
        try {
            var url = new URL(window.location.href);
            if (filter === 'all') url.searchParams.delete('tag');
            else url.searchParams.set('tag', filter);
            window.history.replaceState(null, '', url);
        } catch (e) { /* old browser, skip */ }
    }

    pills.forEach(function (pill) {
        pill.addEventListener('click', function () {
            var filter = pill.getAttribute('data-filter');
            setActivePill(filter);
            applyFilter(filter);
            updateUrl(filter);
        });
    });

    var params = new URLSearchParams(window.location.search);
    var initial = params.get('tag');
    if (initial && setActivePill(initial)) {
        applyFilter(initial);
    }
})();
