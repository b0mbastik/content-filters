import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import run
from project import load, messages_for


class RunnerTests(unittest.TestCase):
    def write_completed_run(self, directory):
        stage, items, prompts, digest = load()
        path = Path(directory) / 'completed.jsonl'
        snapshots, rows = {}, []
        for item, condition, arch, rep in run.build_tasks(stage, items, 1, 1):
            key = f"{item['category_id']}/{item['id']}/{condition}/{arch}/{rep}"
            snapshots[key] = messages_for(item, condition, arch, prompts)
            rows.append({
                'category_id': item['category_id'], 'scenario_id': item['id'],
                'condition': condition, 'architecture': arch, 'repetition': rep,
                'injection_id': item['injection_id'],
                'attacker_target': item['attacker_target'], 'expected_label': 'MEDIUM',
                'seed': run.trial_seed(item, rep), 'raw_response': 'MEDIUM',
                'parsed_label': 'MEDIUM',
            })
        settings = {'stage': 'A', 'source_sha256': digest,
                    'design': 'protection-layers-v2', 'model': 'Qwen3-14B',
                    'temperature': 0.7, 'top_p': 0.8, 'max_new_tokens': 24}
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        Path(str(path) + '.meta.json').write_text(json.dumps({
            'settings': settings, 'nonces': {}, 'prompts': snapshots,
        }), encoding='utf-8')
        return path, rows

    def resume(self, path):
        argv = ['run.py', '--out', str(path), '--reps', '1', '--limit', '1']
        # A completed run must be verifiable without importing inference dependencies.
        with patch.object(sys, 'argv', argv), patch.dict(sys.modules, {'torch': None}):
            run.main()

    def test_completed_resume_skips_gpu_and_preserves_results(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _ = self.write_completed_run(directory)
            original = path.read_bytes()
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.resume(path)
            self.assertIn('All 2 tasks already completed', output.getvalue())
            self.assertEqual(path.read_bytes(), original)

    def test_resume_rejects_wrong_trial_seed(self):
        with tempfile.TemporaryDirectory() as directory:
            path, rows = self.write_completed_run(directory)
            rows[0]['seed'] += 1
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
            with self.assertRaisesRegex(SystemExit, 'does not match the configured trial'):
                self.resume(path)

    def test_partial_legacy_resume_is_rejected_before_gpu_import(self):
        with tempfile.TemporaryDirectory() as directory:
            path, rows = self.write_completed_run(directory)
            path.write_text(json.dumps(rows[0]) + '\n')
            with self.assertRaisesRegex(SystemExit, 'Partial legacy run'):
                self.resume(path)

    def test_inference_records_effective_config_and_refuses_changed_resume(self):
        class Config:
            def __init__(self):
                self.values = {'top_k': 20, 'temperature': 0.6, 'do_sample': True}

            def update(self, **kwargs):
                self.values.update(kwargs)

            def to_dict(self):
                return self.values.copy()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'new.jsonl'
            model_dir = root / 'models' / 'Qwen3-14B'
            model_dir.mkdir(parents=True)
            (model_dir / 'config.json').write_text('{}')
            model, tokenizer, torch = MagicMock(), MagicMock(), MagicMock()
            model.generation_config = Config()
            model.eval.return_value = model
            encoded = {'input_ids': SimpleNamespace(shape=(1, 10))}
            tokenizer.apply_chat_template.return_value.to.return_value = encoded
            tokenizer.eos_token_id = 151645
            tokenizer.decode.return_value = 'MEDIUM'
            transformers = SimpleNamespace(
                AutoModelForCausalLM=SimpleNamespace(from_pretrained=lambda *a, **k: model),
                AutoTokenizer=SimpleNamespace(from_pretrained=lambda *a, **k: tokenizer))
            def provenance(*args):
                return {'schema_version': 1, 'identity': {'generation_config': args[-1].to_dict()}}
            argv = ['run.py', '--out', str(path), '--reps', '1', '--limit', '1']
            with patch.object(sys, 'argv', argv), patch.object(run, 'ROOT', root), \
                    patch.dict(sys.modules, {'torch': torch, 'transformers': transformers}), \
                    patch.object(run, 'capture_run_provenance', side_effect=provenance), \
                    contextlib.redirect_stdout(io.StringIO()):
                run.main()
                recorded = json.loads(Path(str(path) + '.provenance.json').read_text())
                config = recorded['identity']['generation_config']
                self.assertEqual(config['temperature'], 0.7)
                self.assertEqual(config['top_p'], 0.8)
                self.assertEqual(config['top_k'], 20)
                self.assertEqual(config['max_new_tokens'], 24)
                self.assertEqual(model.generate.call_count, 2)
                self.assertEqual(model.generate.call_args.kwargs['generation_config'].to_dict(), config)
                rows = path.read_text().splitlines()
                path.write_text(rows[0] + '\n')
                original = path.read_bytes()
                model.generation_config.values['top_k'] = 50
                with self.assertRaisesRegex(SystemExit, 'provenance differs'):
                    run.main()
                self.assertEqual(path.read_bytes(), original)
                self.assertEqual(model.generate.call_count, 2)
                # Greedy mode must remain explicit even if model defaults enable sampling.
                argv[2] = str(root / 'greedy.jsonl')
                argv.extend(['--temperature', '0'])
                run.main()
                self.assertFalse(model.generate.call_args.kwargs['do_sample'])
                self.assertFalse(model.generate.call_args.kwargs['generation_config'].to_dict()['do_sample'])

    def test_non_finite_temperature_is_rejected_before_loading_inputs(self):
        for temperature in ('nan', 'inf'):
            with self.subTest(temperature=temperature):
                argv = ['run.py', '--temperature', temperature, '--dry-run']
                with patch.object(sys, 'argv', argv), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        run.main()
                self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
