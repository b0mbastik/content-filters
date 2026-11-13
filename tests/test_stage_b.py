import unittest

from project import load, messages_for


class StageBTests(unittest.TestCase):
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

if __name__ == '__main__':
    unittest.main()
