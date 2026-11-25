"""Record model bytes, execution sources and environment without changing old metadata."""
import hashlib
import importlib.metadata
import json
import platform
import re
from datetime import datetime, timezone
from pathlib import Path


EXECUTION_SOURCES = ('run.py', 'project.py', 'result_checks.py', 'provenance.py')


def sha256_file(path):
    digest = hashlib.sha256()
    buffer = memoryview(bytearray(1024 * 1024))
    with Path(path).open('rb', buffering=0) as stream:
        while size := stream.readinto(buffer):
            digest.update(buffer[:size])
    return digest.hexdigest()


def file_record(path):
    return {'bytes': Path(path).stat().st_size, 'sha256': sha256_file(path)}


def environment_snapshot():
    packages = []
    for distribution in importlib.metadata.distributions():
        metadata = distribution.metadata
        name = metadata['Name']
        if name:
            packages.append((name, metadata['Version']))
    return {
        'python': platform.python_version(),
        'platform': platform.platform(),
        'machine': platform.machine(),
        'packages': dict(sorted(packages)),
    }


def model_snapshot(model_dir):
    """Hash actual local assets; cache revision claims are recorded separately."""
    model_dir = Path(model_dir)
    assets = [p for p in sorted(model_dir.rglob('*')) if p.is_file()
              and not any(part.startswith('.') for part in p.relative_to(model_dir).parts)
              and p.suffix in ('.json', '.txt', '.model', '.safetensors', '.bin')]
    if not (model_dir / 'config.json').is_file() or not any(
            p.suffix in ('.safetensors', '.bin') for p in assets):
        raise ValueError('Model configuration and weights are required for provenance')
    downloads = {}
    for path in sorted((model_dir / '.cache' / 'huggingface' / 'download').rglob('*.metadata')):
        lines = path.read_text(encoding='utf-8').splitlines()
        if len(lines) >= 2 and re.fullmatch('[0-9a-f]{40}', lines[0]):
            name = path.relative_to(model_dir / '.cache' / 'huggingface' / 'download').as_posix()
            downloads[name.removesuffix('.metadata')] = {'revision': lines[0], 'etag': lines[1]}
    return {
        'files': {p.relative_to(model_dir).as_posix(): file_record(p) for p in assets},
        'download_metadata': downloads,
    }


def capture_run_provenance(root, model_dir, torch, generation_config):
    hardware = {
        'cuda_runtime': torch.version.cuda,
        'cudnn': torch.backends.cudnn.version(),
        'devices': [
            {'name': torch.cuda.get_device_name(i),
             'capability': list(torch.cuda.get_device_capability(i)),
             'total_memory': torch.cuda.get_device_properties(i).total_memory}
            for i in range(torch.cuda.device_count())
        ],
    }
    return {
        'schema_version': 1,
        'recorded_at_utc': datetime.now(timezone.utc).isoformat(),
        'identity': {
            'model': model_snapshot(model_dir),
            'environment': environment_snapshot(),
            'hardware': hardware,
            'execution_sources': {name: file_record(Path(root) / name) for name in EXECUTION_SOURCES},
            'generation_config': generation_config.to_dict(),
            'inference': {'enable_thinking': False, 'dtype': 'bfloat16', 'device': 'cuda:0'},
        },
    }


def write_json_atomically(path, record):
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(record, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    temporary.replace(path)


def preserve_run_provenance(path, current, has_results=False):
    """Refuse incompatible resumes and never rewrite an existing provenance record."""
    path = Path(path)
    if path.exists():
        previous = json.loads(path.read_text(encoding='utf-8'))
        if previous['schema_version'] != current['schema_version'] or previous['identity'] != current['identity']:
            raise ValueError('Run provenance differs; choose a new --out')
    elif has_results:
        raise ValueError('Partial legacy run has no inference provenance; choose a new --out')
    else:
        write_json_atomically(path, current)
