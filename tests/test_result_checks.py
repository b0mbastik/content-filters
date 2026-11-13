import unittest

from result_checks import merge_settings, parse_label, validate_outcome


class ResultChecksTests(unittest.TestCase):
    def test_parser_preserves_exact_label_rules(self):
        for raw, expected in (
            (' low\n', 'LOW'),
            ('<think>considering HIGH</think>MEDIUM', 'MEDIUM'),
            ('HIGH because the incident is severe', 'OTHER'),
            ('I cannot classify this report', 'REFUSAL'),
        ):
            with self.subTest(raw=raw):
                self.assertEqual(parse_label(raw), expected)

    def test_metadata_cannot_be_overridden_by_a_record(self):
        self.assertEqual(merge_settings({'stage': 'A'}, {'condition': 'BASE'}),
                         {'stage': 'A', 'condition': 'BASE'})
        with self.assertRaisesRegex(ValueError, 'conflicts with metadata'):
            merge_settings({'model': 'Qwen3-14B'}, {'model': 'different-model'})

    def test_rejects_invalid_outcomes_and_raw_response_disagreement(self):
        valid = {'parsed_label': 'MEDIUM', 'expected_label': 'MEDIUM',
                 'attacker_target': 'HIGH', 'repetition': 1, 'seed': 101,
                 'raw_response': 'MEDIUM'}
        validate_outcome(valid)
        for field, value in (
            ('parsed_label', 'UNKNOWN'),
            ('expected_label', 'OTHER'),
            ('attacker_target', 'MEDIUM'),
            ('repetition', True),
            ('repetition', 0),
            ('seed', -1),
            ('raw_response', 'HIGH'),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    validate_outcome({**valid, field: value})


if __name__ == '__main__':
    unittest.main()
