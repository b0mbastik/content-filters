import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from provenance import (EXECUTION_SOURCES, capture_run_provenance, model_snapshot,
                        preserve_run_provenance)


class ProvenanceTests(unittest.TestCase):
    def test_collector_records_sources_hardware_and_generation_config_without_gpu(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in EXECUTION_SOURCES:
                (root / name).write_text(name)
            model_dir = root / 'model'
            model_dir.mkdir()
            (model_dir / 'config.json').write_text('{}')
            (model_dir / 'model.safetensors').write_bytes(b'weights')
            cuda = SimpleNamespace(device_count=lambda: 1, get_device_name=lambda i: 'test GPU',
                                   get_device_capability=lambda i: (8, 9),
                                   get_device_properties=lambda i: SimpleNamespace(total_memory=1234))
            torch = SimpleNamespace(cuda=cuda, version=SimpleNamespace(cuda='12.8'),
                                    backends=SimpleNamespace(cudnn=SimpleNamespace(version=lambda: 9000)))
            config = SimpleNamespace(to_dict=lambda: {'max_new_tokens': 24, 'top_k': 20})
            with patch('provenance.environment_snapshot', return_value={'packages': {'torch': 'test'}}):
                record = capture_run_provenance(root, model_dir, torch, config)
            identity = record['identity']
            self.assertEqual(set(identity['execution_sources']), set(EXECUTION_SOURCES))
            self.assertEqual(identity['hardware']['devices'][0]['name'], 'test GPU')
            self.assertEqual(identity['generation_config']['top_k'], 20)
            self.assertIn('model.safetensors', identity['model']['files'])
            self.assertFalse(identity['inference']['enable_thinking'])

    def test_model_hashes_detect_changed_weights_and_tokenizer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in (('config.json', '{}'), ('tokenizer.json', '{}'),
                                  ('model.safetensors', 'original weights')):
                (root / name).write_text(content)
            cache = root / '.cache' / 'huggingface' / 'download'
            cache.mkdir(parents=True)
            (cache / 'config.json.metadata').write_text('a' * 40 + '\netag\n123\n')
            original = model_snapshot(root)
            self.assertEqual(original['download_metadata']['config.json']['revision'], 'a' * 40)
            (root / 'model.safetensors').write_text('changed weights')
            (root / 'tokenizer.json').write_text('{"changed": true}')
            changed = model_snapshot(root)
            for name in ('model.safetensors', 'tokenizer.json'):
                self.assertNotEqual(original['files'][name]['sha256'], changed['files'][name]['sha256'])

    def test_resume_preserves_record_and_rejects_different_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'run.provenance.json'
            first = {'schema_version': 1, 'recorded_at_utc': 'original',
                     'identity': {'model': 'original', 'generation_config': {'top_k': 20}}}
            preserve_run_provenance(path, first)
            original = path.read_bytes()
            preserve_run_provenance(path, {**first, 'recorded_at_utc': 'later'}, has_results=True)
            self.assertEqual(path.read_bytes(), original)
            with self.assertRaisesRegex(ValueError, 'provenance differs'):
                preserve_run_provenance(path, {**first, 'identity': {'model': 'changed'}}, has_results=True)
            self.assertEqual(path.read_bytes(), original)
            with self.assertRaisesRegex(ValueError, 'Partial legacy'):
                preserve_run_provenance(path.with_name('missing.json'), first, has_results=True)

if __name__ == '__main__':
    unittest.main()
