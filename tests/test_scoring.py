"""Tests for the email security scoring system."""
import pytest
from security_scoring import EmailSecurityScorer


@pytest.fixture
def scorer():
    return EmailSecurityScorer()


class TestGradeThresholds:
    """Verify grade boundaries match the documented thresholds."""

    def test_a_plus(self, scorer):
        assert scorer._calculate_grade(90) == 'A+'
        assert scorer._calculate_grade(100) == 'A+'

    def test_a(self, scorer):
        assert scorer._calculate_grade(80) == 'A'
        assert scorer._calculate_grade(89) == 'A'

    def test_b(self, scorer):
        assert scorer._calculate_grade(65) == 'B'
        assert scorer._calculate_grade(79) == 'B'

    def test_c(self, scorer):
        assert scorer._calculate_grade(50) == 'C'
        assert scorer._calculate_grade(64) == 'C'

    def test_d(self, scorer):
        assert scorer._calculate_grade(35) == 'D'
        assert scorer._calculate_grade(49) == 'D'

    def test_f(self, scorer):
        assert scorer._calculate_grade(0) == 'F'
        assert scorer._calculate_grade(34) == 'F'

    def test_boundary_values(self, scorer):
        """Test exact boundary values."""
        assert scorer._calculate_grade(89.9) == 'A'
        assert scorer._calculate_grade(90.0) == 'A+'
        assert scorer._calculate_grade(79.9) == 'B'
        assert scorer._calculate_grade(80.0) == 'A'


class TestCategoryWeights:
    """Verify category weights sum to 100."""

    def test_weights_sum_to_100(self, scorer):
        assert sum(scorer.category_weights.values()) == 100

    def test_all_categories_present(self, scorer):
        expected = {'dmarc', 'spf', 'dkim', 'best_practices', 'key_security', 'vendor_intelligence'}
        assert set(scorer.category_weights.keys()) == expected


class TestDKIMFullCredit:
    """DKIM awards full credit when no selectors are found."""

    def test_no_selectors_full_credit(self, scorer):
        score, details = scorer._score_dkim({'found_selectors': []})
        assert score == 15  # Full credit
        assert 'UNKNOWN' in str(details.get('impact', ''))

    def test_no_selectors_key_security_full_credit(self, scorer):
        score, details = scorer._score_key_security({'found_selectors': []}, {})
        assert score == 10  # Full credit


class TestSPFPermerror:
    """SPF records exceeding 10 lookups should score 0."""

    def test_over_10_lookups_scores_zero(self, scorer):
        spf = {'record': 'v=spf1 ...', 'lookup_count': 11}
        score, details = scorer._score_spf(spf)
        assert score == 0
        assert 'CRITICAL' in str(details.get('impact', ''))

    def test_exactly_10_lookups_not_zero(self, scorer):
        spf = {'record': 'v=spf1 ...', 'all': '-all', 'lookup_count': 10}
        score, details = scorer._score_spf(spf)
        assert score > 0


class TestNoMXDomain:
    """Non-mail domains should score generously."""

    def test_no_mx_with_inherited_reject(self, scorer):
        audit = {
            'has_mx': False,
            'dmarc_results': {'inherited_policy': 'reject'},
            'spf_results': {},
            'dkim_results': {},
            'key_age_analysis': {},
            'vendor_fingerprint': {},
        }
        result = scorer.calculate_score(audit)
        assert result['total_score'] >= 70
