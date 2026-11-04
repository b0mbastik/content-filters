import json
import tempfile
import unittest
from pathlib import Path

from analyse import analyse
from compare import compare
from project import load, messages_for


class StageBTests(unittest.TestCase):
    def write_run(self, directory, stage_name):
        stage, items, prompts, digest = load(f'stages/{stage_name}.json')
        path = Path(directory) / f'{stage_name}.jsonl'
        settings = {'design': 'protection-layers-v2', 'stage': stage_name, 'source_sha256': digest, 'model': 'Qwen3-14B',
                    'temperature': 0.7, 'top_p': 0.8, 'max_new_tokens': 24}
        snapshots = {}
        nonces = {}
        rows = []
        for item in items:
            for arch in stage['architectures']:
                for condition in stage['conditions']:
                    for rep in (1, 2, 3):
                        key = f"{item['category_id']}/{item['id']}/{condition}/{arch}/{rep}"
                        nonce_key = f"{item['category_id']}/{item['id']}/{rep}"
                        if arch == 'P2':
                            nonces[nonce_key] = f'{len(item["id"]):032x}'
                        snapshots[key] = messages_for(item, condition, arch, prompts, nonces.get(nonce_key) if arch == 'P2' else None)
                        label = 'MEDIUM' if condition == 'BASE' or rep != 1 else item['attacker_target']
                        rows.append({'category_id': item['category_id'], 'scenario_id': item['id'],
                                     'repetition': rep, 'architecture': arch, 'condition': condition,
                                     'expected_label': 'MEDIUM', 'injection_id': item['injection_id'],
                                     'attacker_target': item['attacker_target'], 'seed': rep,
                                     'parsed_label': label})
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        Path(str(path) + '.meta.json').write_text(json.dumps({'settings': settings, 'nonces': nonces, 'prompts': snapshots}))
        return path, rows

    def test_architecture_boundaries(self):
        _, a_items, a_prompts, _ = load('stages/A.json')
        _, b_items, b_prompts, _ = load('stages/B.json')
        item = b_items[0]
        p0 = messages_for(a_items[0], 'I', 'P0', a_prompts)
        self.assertEqual([msg['role'] for msg in p0], ['user'])
        self.assertIn(item['rubric'], p0[0]['content'])
        self.assertIn(item['injection_text'], p0[0]['content'])
        p1 = messages_for(item, 'I', 'P1', b_prompts)
        self.assertEqual([msg['role'] for msg in p1], ['system', 'user'])
        self.assertIn('<untrusted_document>', p1[1]['content'])
        self.assertIn('</untrusted_document>', p1[1]['content'])
        token = 'ab' * 16
        p2 = messages_for(item, 'I', 'P2', b_prompts, token)
        self.assertIn(token, p2[0]['content'])
        self.assertEqual(p2[1]['content'].count(token), 2)
        self.assertLess(p2[1]['content'].index(item['injection_text']), p2[1]['content'].index('<<<END'))
        self.assertIn('Output exactly one label', p2[1]['content'].split('<<<END')[1])
        with self.assertRaises(ValueError):
            messages_for(item, 'I', 'P2', b_prompts)

    def test_means_and_complete_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, _ = self.write_run(tmp, 'A')
            b, _ = self.write_run(tmp, 'B')
            rows = list(compare([a, b]))
            self.assertEqual(len(rows), 9)
            row = next(r for r in rows if r['architecture'] == 'P1' and r['attacker_target'] == 'ALL')
            self.assertEqual(row['base_mean_medium_cases'], 30)
            self.assertEqual(row['i_mean_low_cases'], 5)
            self.assertEqual(row['i_mean_medium_cases'], 20)
            self.assertEqual(row['i_mean_high_cases'], 5)
            self.assertEqual(row['mean_conditional_success_cases'], 10)
            self.assertEqual(row['conditional_attack_success_rate'], 0.3333)

    def test_comparison_rejects_missing_trial_and_seed_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, _ = self.write_run(tmp, 'A')
            b, rows = self.write_run(tmp, 'B')
            b.write_text(''.join(json.dumps(row) + '\n' for row in rows[:-1]))
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                list(compare([a, b]))
            rows[0]['seed'] = 999
            b.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            with self.assertRaisesRegex(ValueError, 'Mismatched seeds'):
                list(compare([a, b]))

    def test_real_stage_a_mean_if_available(self):
        # This assertion is covered above with generated data; no GPU is required.
        with tempfile.TemporaryDirectory() as tmp:
            a, _ = self.write_run(tmp, 'A')
            row = next(r for r in analyse([a]) if r['attacker_target'] == 'ALL')
            self.assertEqual(row['mean_conditional_success_cases'], 10)


if __name__ == '__main__':
    unittest.main()
