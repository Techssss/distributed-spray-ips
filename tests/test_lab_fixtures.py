import unittest
from collections import Counter

from fixtures.loader import (
    ALLOWED_RECORD_KEYS,
    load_expected_outcomes,
    load_fixture,
    replay_fixture,
)


class LabFixtureTests(unittest.TestCase):
    def test_fixture_schema_contains_no_secrets(self):
        for name in ('single_source', 'distributed_spray', 'control_disjoint'):
            records = load_fixture(name)
            self.assertGreater(len(records), 0)
            for rec in records:
                self.assertEqual(set(rec.keys()), ALLOWED_RECORD_KEYS)
                self.assertEqual(rec['event'], 'login_failed')
                self.assertIn(rec['surface'], ('web', 'api'))

    def test_control_matches_spray_marginal_counts(self):
        spray = load_fixture('distributed_spray')
        control = load_fixture('control_disjoint')
        self.assertEqual(len(spray), len(control))
        self.assertEqual(
            Counter(rec['ip'] for rec in spray),
            Counter(rec['ip'] for rec in control),
        )
        self.assertEqual(
            Counter(rec['account'] for rec in spray),
            Counter(rec['account'] for rec in control),
        )

    def test_fixtures_match_expected_detector_outcomes(self):
        expected = load_expected_outcomes()
        for name, exp in expected.items():
            actual = replay_fixture(name)
            self.assertEqual(actual['events'], exp['events'])
            self.assertEqual(actual['ip_alert'], exp['ip_alert'])
            self.assertEqual(actual['account_alert'], exp['account_alert'])
            self.assertEqual(actual['ip_threshold'], exp['ip_threshold'])
            self.assertEqual(actual['account_threshold'], exp['account_threshold'])
            self.assertEqual(actual['campaign_count'], exp['campaign_count'])
            if exp['campaign_count'] > 0:
                campaign = actual['campaigns'][0]
                self.assertEqual(list(campaign['sources']), exp['expected_sources'])
                self.assertEqual(list(campaign['targets']), exp['expected_targets'])
                self.assertEqual(list(campaign['surfaces']), exp['expected_surfaces'])


if __name__ == '__main__':
    unittest.main()
