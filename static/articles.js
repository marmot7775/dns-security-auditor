(function () {
    var pills = document.querySelectorAll('.articles-tag-pill');
    var cards = document.querySelectorAll('.article-card');
    if (!pills.length || !cards.length) return;

    function applyFilter(filter) {
        cards.forEach(function (card) {
            var tags = (card.getAttribute('data-tags') || '').split(/\s+/);
            var match = filter === 'all' || tags.indexOf(filter) !== -1;
            if (match) {
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
                }, 200);
            }
        });
    }

    pills.forEach(function (pill) {
        pill.addEventListener('click', function () {
            pills.forEach(function (p) {
                p.classList.remove('is-active');
                p.setAttribute('aria-pressed', 'false');
            });
            pill.classList.add('is-active');
            pill.setAttribute('aria-pressed', 'true');
            applyFilter(pill.getAttribute('data-filter'));
        });
    });
})();
