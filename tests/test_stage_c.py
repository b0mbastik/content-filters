import unittest

from project import correct_label, load, messages_for
from run import build_tasks


class StageCTests(unittest.TestCase):
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

if __name__ == '__main__':
    unittest.main()
