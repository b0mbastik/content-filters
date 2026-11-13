import json
import unittest
from collections import Counter

from project import correct_label, load, messages_for
from run import build_tasks, parse_label


class StageATests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stage, cls.items, cls.prompts, cls.source_hash = load()

    def test_stage_and_scenarios(self):
        self.assertEqual(self.stage['conditions'], ['BASE', 'I'])
        self.assertEqual(self.stage['architectures'], ['P0'])
        self.assertEqual(len(self.items), 30)
        self.assertEqual({item['base_label'] for item in self.items}, {'MEDIUM'})
        self.assertEqual(Counter(item['attacker_target'] for item in self.items),
                         {'LOW': 15, 'HIGH': 15})
        self.assertEqual(len({item['injection_id'] for item in self.items}), 12)
        self.assertEqual(len(build_tasks(self.stage, self.items, 3)), 180)

    def test_no_evidence_or_ground_truth_in_prompt(self):
        for item in self.items:
            base = messages_for(item, 'BASE', 'P0', self.prompts)
            attacked = messages_for(item, 'I', 'P0', self.prompts)
            self.assertEqual(len(base), 1)
            self.assertEqual(base[0]['role'], 'user')
            self.assertIn(item['base_text'], base[0]['content'])
            self.assertIn(item['base_text'], attacked[0]['content'])
            self.assertNotIn(item['injection_text'], base[0]['content'])
            self.assertIn(item['injection_text'], attacked[0]['content'])
            self.assertNotIn('Later verified update', json.dumps(base + attacked))
            self.assertNotIn('expected_label', json.dumps(base + attacked))
            self.assertEqual(correct_label(item, 'BASE'), 'MEDIUM')
            self.assertEqual(correct_label(item, 'I'), 'MEDIUM')
            self.assertEqual(item['injection_id'].split('-')[0], item['attacker_target'])

    def test_reproducible_task_order(self):
        a = build_tasks(self.stage, self.items, 2)
        b = build_tasks(self.stage, self.items, 2)
        self.assertEqual([(i['id'], c, p, r) for i, c, p, r in a],
                         [(i['id'], c, p, r) for i, c, p, r in b])

    def test_parser_rejects_explanatory_answers(self):
        for raw, expected in [('LOW', 'LOW'), (' MEDIUM\n', 'MEDIUM'),
                              ('HIGH', 'HIGH'), ('The answer is LOW.', 'OTHER'),
                              ('I cannot determine that', 'REFUSAL')]:
            self.assertEqual(parse_label(raw), expected)

    def test_stage_a_rejects_evidence_conditions(self):
        for condition in ('E', 'EI'):
            with self.assertRaisesRegex(ValueError, 'Unknown condition'):
                correct_label(self.items[0], condition)
            with self.assertRaisesRegex(ValueError, 'Unknown condition'):
                messages_for(self.items[0], condition, 'P0', self.prompts)


if __name__ == '__main__':
    unittest.main()
