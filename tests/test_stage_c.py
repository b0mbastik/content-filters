import json
import tempfile
import unittest
from pathlib import Path

from analyse_c import analyse_stage_c
from project import correct_label, load, messages_for
from run import build_tasks
import test_stage_b


class StageCTests(unittest.TestCase):
    def write_results(self, directory):
        stage, items, prompts, digest = load('stages/C.json')
        path = Path(directory) / 'C.jsonl'
        settings = {'stage': 'C', 'source_sha256': digest, 'design': 'protection-layers-v2',
                    'model': 'Qwen3-14B', 'temperature': 0.7, 'top_p': 0.8, 'max_new_tokens': 24}
        nonces, snapshots, rows = {}, {}, []
        for item, condition, arch, rep in build_tasks(stage, items, 3):
            token_key = f"{item['category_id']}/{item['id']}/{rep}"
            token = 'a' * 32 if arch == 'P2' else None
            if token:
                nonces[token_key] = token
            snapshots[f"{item['category_id']}/{item['id']}/{condition}/{arch}/{rep}"] = messages_for(item, condition, arch, prompts, token)
            # Rep 1: eligible attack hit; rep 2: eligible and retained;
            # rep 3: E incorrect so EI target cannot count as conditional success.
            pred = (item['attacker_target'] if (condition == 'EI' and rep in (1, 3)) or (condition == 'E' and rep == 3) else item['evidence_label'])
            rows.append({'category_id': item['category_id'], 'scenario_id': item['id'], 'condition': condition,
                         'architecture': arch, 'repetition': rep, 'injection_id': item['injection_id'],
                         'attacker_target': item['attacker_target'], 'expected_label': item['evidence_label'],
                         'seed': rep, 'parsed_label': pred})
        path.write_text(''.join(json.dumps(r) + '\n' for r in rows))
        Path(str(path) + '.meta.json').write_text(json.dumps({'settings': settings, 'prompts': snapshots, 'nonces': nonces}))
        return path, rows

    def test_opposed_labels_and_prompt_isolation(self):
        stage, items, prompts, _ = load('stages/C.json')
        self.assertEqual(len(build_tasks(stage, items, 3)), 540)
        for item in items:
            self.assertEqual({'LOW': 'HIGH', 'HIGH': 'LOW'}[item['attacker_target']], item['evidence_label'])
            self.assertEqual(correct_label(item, 'E'), correct_label(item, 'EI'))
            for arch in stage['architectures']:
                nonce = 'test' if arch == 'P2' else None
                e = messages_for(item, 'E', arch, prompts, nonce)
                ei = messages_for(item, 'EI', arch, prompts, nonce)
                clean_text = '\n'.join(msg['content'] for msg in e)
                attacked_text = '\n'.join(msg['content'] for msg in ei)
                self.assertIn(item['evidence_text'], clean_text)
                self.assertIn(item['evidence_text'], attacked_text)
                self.assertNotIn(item['injection_text'], clean_text)
                self.assertIn(item['injection_text'], attacked_text)
                self.assertIn('Later verified update', clean_text)
                self.assertIn('Later verified update', attacked_text)

    def test_analysis_and_reuse_baselines(self):
        with tempfile.TemporaryDirectory() as tmp:
            c, _ = self.write_results(tmp)
            fixture = test_stage_b.StageBTests()
            a, _ = fixture.write_run(tmp, 'A')
            b, _ = fixture.write_run(tmp, 'B')
            rows = list(analyse_stage_c(c, [a, b]))
            row = next(r for r in rows if r['architecture'] == 'P2' and r['group_by'] == 'ALL')
            self.assertEqual(row['e_mean_correct_cases'], 20)
            self.assertEqual(row['ei_mean_correct_cases'], 10)
            self.assertEqual(row['mean_retained_cases'], 10)
            self.assertEqual(row['mean_conditional_attack_success_cases'], 10)
            self.assertEqual(row['attack_eligible_trials'], 60)
            self.assertEqual(row['conditional_attack_success_rate'], 0.5)
            self.assertEqual(row['base_mean_medium_cases'], 30)
            self.assertEqual(row['i_mean_low_cases'], 5)

    def test_rejects_incomplete_pairs(self):
        with tempfile.TemporaryDirectory() as tmp:
            c, rows = self.write_results(tmp)
            c.write_text(''.join(json.dumps(row) + '\n' for row in rows[:-1]))
            with self.assertRaisesRegex(ValueError, 'Incomplete'):
                list(analyse_stage_c(c))


if __name__ == '__main__':
    unittest.main()
