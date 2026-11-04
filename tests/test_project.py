import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from project import ROOT, correct_label, load, messages_for
from run import build_tasks, parse_label
from analyse import analyse


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
            self.assertEqual(base[0], attacked[0])
            self.assertIn(item['base_text'], base[1]['content'])
            self.assertIn(item['base_text'], attacked[1]['content'])
            self.assertNotIn(item['injection_text'], base[1]['content'])
            self.assertIn(item['injection_text'], attacked[1]['content'])
            self.assertNotIn(item['injection_text'], attacked[0]['content'])
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

    def test_analysis_measures_attack_success_conditionally(self):
        # One attack succeeds, one fails; only correct BASE assessments are eligible.
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / 'test.jsonl'
            with file.open('w') as out:
                for item, base_pred, attack_pred in [(self.items[0], 'MEDIUM', self.items[0]['attacker_target']),
                                                     (self.items[1], 'LOW', self.items[1]['attacker_target'])]:
                    for condition, prediction in [('BASE', base_pred), ('I', attack_pred)]:
                        row = {'stage': 'A', 'split_requested': 'development', 'split': 'development',
                               'model': 'Qwen3-14B', 'category_id': item['category_id'],
                               'architecture': 'P0', 'scenario_id': item['id'], 'repetition': 1,
                               'seed': 101, 'source_sha256': self.source_hash,
                               'temperature': 0.7, 'top_p': 0.8, 'max_new_tokens': 24,
                               'attacker_target': item['attacker_target'],
                               'injection_id': item['injection_id'], 'condition': condition,
                               'expected_label': correct_label(item, condition),
                               'parsed_label': prediction}
                        out.write(json.dumps(row) + '\n')
            all_rows = list(analyse([file]))
            overall = next(row for row in all_rows if row['attacker_target'] == 'ALL')
            self.assertEqual(overall['paired_trials'], 2)
            self.assertEqual(overall['clean_correct'], 1)
            self.assertEqual(overall['attacker_target_hits'], 2)
            self.assertEqual(overall['target_hits_given_correct_clean'], 1)
            self.assertEqual(overall['conditional_attack_success_rate'], 1.0)

    def test_analysis_rejects_incomplete_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / 'one.jsonl'
            file.write_text(json.dumps({'stage': 'A', 'split_requested': 'development',
                                        'split': 'development', 'model': 'Qwen3-14B',
                                        'category_id': 'category_1',
                                        'architecture': 'P0', 'scenario_id': 'UC-01',
                                        'repetition': 1, 'condition': 'BASE', 'source_sha256': 'abc',
                                        'temperature': 0.7, 'top_p': 0.8, 'max_new_tokens': 24}) + '\n')
            with self.assertRaisesRegex(ValueError, 'Incomplete'):
                list(analyse([file]))

    def test_stage_a_rejects_evidence_conditions(self):
        for condition in ('E', 'EI'):
            with self.assertRaisesRegex(ValueError, 'Unknown condition'):
                correct_label(self.items[0], condition)
            with self.assertRaisesRegex(ValueError, 'Unknown condition'):
                messages_for(self.items[0], condition, 'P0', self.prompts)


if __name__ == '__main__':
    unittest.main()
