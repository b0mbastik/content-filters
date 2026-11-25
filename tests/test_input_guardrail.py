import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from importlib.util import find_spec
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import run
from project import ROOT, load, messages_for


@unittest.skipUnless(find_spec('nemoguardrails'), 'requires requirements-guardrail.txt')
class InputGuardrailTests(unittest.TestCase):
    def test_rail_checks_the_full_user_message_and_requires_an_allow_verdict(self):
        from input_guardrail import build_input_guardrail

        _, items, prompts, _ = load('stages/C.json')
        messages = messages_for(items[0], 'E', 'P2', prompts, 'testnonce')
        judge = MagicMock(side_effect=['ALLOW', 'BLOCK', 'ALLOW with explanation', ''])
        check = build_input_guardrail((ROOT / run.INPUT_POLICY).read_text(), judge)

        self.assertEqual([check(messages) for _ in range(4)],
                         ['passed', 'blocked', 'blocked', 'blocked'])
        self.assertEqual(judge.call_count, 4)
        for call in judge.call_args_list:
            judge_messages, max_tokens = call.args
            self.assertEqual([msg['role'] for msg in judge_messages], ['system', 'user'])
            self.assertEqual(json.loads(judge_messages[1]['content']), messages[-1]['content'])
            self.assertNotIn('<', judge_messages[1]['content'])
            self.assertEqual(max_tokens, 16)

    def test_rail_pass_without_a_parsed_verdict_stops_the_run(self):
        from input_guardrail import LLMRails, RailStatus, build_input_guardrail

        messages = [{'role': 'user', 'content': 'An incident report'}]
        check = build_input_guardrail((ROOT / run.INPUT_POLICY).read_text(), lambda *_: 'ALLOW')
        self.assertEqual(check(messages), 'passed')
        with patch.object(LLMRails, 'check', return_value=SimpleNamespace(status=RailStatus.PASSED)):
            with self.assertRaisesRegex(RuntimeError, 'did not return a validated decision'):
                check(messages)

    def test_guarded_runner_classifies_only_passing_input_and_records_both_trials(self):
        stage, items, prompts, _ = load()
        expected = messages_for(items[0], 'BASE', 'P0', prompts)
        injected = messages_for(items[0], 'I', 'P0', prompts)
        policy = (ROOT / run.INPUT_POLICY).read_bytes()
        model, tokenizer, torch = MagicMock(), MagicMock(), MagicMock()
        model.eval.return_value = model
        tokenizer.eos_token_id = 151645
        transformers = SimpleNamespace(
            AutoModelForCausalLM=SimpleNamespace(from_pretrained=lambda *args, **kwargs: model),
            AutoTokenizer=SimpleNamespace(from_pretrained=lambda *args, **kwargs: tokenizer),
        )

        def generate(model, tokenizer, torch, messages, config, **arguments):
            if arguments['do_sample']:
                self.assertEqual(messages, expected)
                return 'MEDIUM'
            checked_input = json.loads(messages[-1]['content'])
            self.assertIn(checked_input, [expected[0]['content'], injected[0]['content']])
            return 'ALLOW' if checked_input == expected[0]['content'] else 'BLOCK'

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model_dir = root / 'models' / 'Qwen3-14B'
            model_dir.mkdir(parents=True)
            (model_dir / 'config.json').write_text('{}')
            policy_path = root / run.INPUT_POLICY
            policy_path.parent.mkdir()
            policy_path.write_bytes(policy)
            (root / 'input_guardrail.py').write_bytes((ROOT / 'input_guardrail.py').read_bytes())
            argv = ['run.py', '--input-guardrail', '--reps', '3', '--limit', '1']
            with patch.object(sys, 'argv', argv), patch.object(run, 'ROOT', root), \
                    patch.dict(sys.modules, {'torch': torch, 'transformers': transformers}), \
                    patch.object(run, 'generate_text', side_effect=generate) as inference, \
                    patch.object(run, 'capture_run_provenance', return_value={'identity': {}}), \
                    contextlib.redirect_stdout(io.StringIO()):
                run.main()
                run.main()
                judges = [call for call in inference.call_args_list if not call.kwargs['do_sample']]
                classifiers = [call for call in inference.call_args_list if call.kwargs['do_sample']]
                self.assertEqual(len(judges), 2)
                self.assertEqual(len(classifiers), 3)
                self.assertEqual(torch.manual_seed.call_count, 3)
                policy_path.write_bytes(policy + b'\n')
                with self.assertRaisesRegex(SystemExit, 'different settings or prompts'):
                    run.main()

            output = root / 'results' / f"stage-{stage['stage'].lower()}-nemo-input.jsonl"
            rows = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual(len(rows), 6)
            for condition, verdict, label in (('BASE', 'passed', 'MEDIUM'), ('I', 'blocked', 'REFUSAL')):
                trials = [row for row in rows if row['condition'] == condition]
                self.assertEqual({row['repetition'] for row in trials}, {1, 2, 3})
                self.assertEqual({(row['input_guardrail'], row['parsed_label']) for row in trials}, {(verdict, label)})
            metadata = json.loads(output.with_suffix('.jsonl.meta.json').read_text())
            self.assertEqual(metadata['input_guardrail_policy'].encode(), policy)
            self.assertEqual(metadata['settings']['input_guardrail_policy_sha256'],
                             hashlib.sha256(policy).hexdigest())
            provenance = json.loads(output.with_suffix('.jsonl.provenance.json').read_text())
            self.assertTrue(provenance['identity']['input_guardrail']['reuse_identical_messages_within_process'])
