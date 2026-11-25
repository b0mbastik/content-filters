import unittest
from collections import Counter

from project import correct_label, injection_target, load, messages_for
from run import build_tasks


class Category2V2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stage, cls.items, cls.prompts, cls.source_hash = load('stages/category_2_v2.json')

    def test_stage_shape(self):
        self.assertEqual(self.stage['conditions'], ['BASE', 'I'])
        self.assertEqual(self.stage['architectures'], ['P0', 'P1', 'P2'])
        self.assertEqual(self.stage['injections_dir'], 'injections_v2')
        # 4 reports x 6 version-2 injections = 24 scenarios
        self.assertEqual(len(self.items), 24)
        self.assertEqual({item['base_label'] for item in self.items}, {'MEDIUM'})
        self.assertEqual(len({item['injection_id'] for item in self.items}), 6)
        self.assertEqual(len({item['report_id'] for item in self.items}), 4)
        self.assertEqual(len({(item['report_id'], item['injection_id'])
                              for item in self.items}), 24)
        # 24 scenarios x 2 conditions x 3 architectures x 3 reps = 432 calls
        self.assertEqual(len(build_tasks(self.stage, self.items, 3)), 432)

    def test_targets_derived_from_v2_ids(self):
        expected = {
            'low_pos_v2_2': 'LOW', 'low_neg_v2_2': 'HIGH',
            'med_pos_v2_1': 'LOW', 'med_neg_v2_2': 'HIGH',
            'high_pos_v3_1': 'LOW', 'high_neg_v3_1': 'HIGH',
        }
        for item in self.items:
            self.assertEqual(item['attacker_target'], expected[item['injection_id']])
        self.assertEqual(Counter(item['attacker_target'] for item in self.items),
                         {'LOW': 12, 'HIGH': 12})

    def test_injection_target_helper(self):
        self.assertEqual(injection_target('LOW-01'), 'LOW')
        self.assertEqual(injection_target('HIGH-03'), 'HIGH')
        self.assertEqual(injection_target('med_pos_v2_1'), 'LOW')
        self.assertEqual(injection_target('high_neg_v3_1'), 'HIGH')
        with self.assertRaises(ValueError):
            injection_target('unknown_id')

    def test_report_text_and_injection_isolation(self):
        for item in self.items:
            base = messages_for(item, 'BASE', 'P1', self.prompts)
            injected = messages_for(item, 'I', 'P1', self.prompts)
            self.assertEqual(correct_label(item, 'BASE'), 'MEDIUM')
            self.assertEqual(correct_label(item, 'I'), 'MEDIUM')
            self.assertIn(item['base_text'], base[1]['content'])
            self.assertIn(item['base_text'], injected[1]['content'])
            self.assertNotIn(item['injection_text'], str(base))
            self.assertIn(item['injection_text'], injected[1]['content'])
            self.assertNotIn(item['injection_text'], injected[0]['content'])

    def test_baseline_stage_unchanged(self):
        stage, items, _, _ = load('stages/category_2_baseline.json')
        self.assertEqual(stage['conditions'], ['BASE'])
        self.assertEqual(len(items), 4)
        self.assertTrue(all(item['injection_id'] is None for item in items))


if __name__ == '__main__':
    unittest.main()
