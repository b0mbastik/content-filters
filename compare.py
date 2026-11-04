#!/usr/bin/env python3
"""Compare complete Stage A and B runs after checking matched inputs and settings."""
import csv
import json
import sys
from pathlib import Path

from analyse import analyse
from project import load, messages_for


def compare(paths):
    if len(paths) != 2:
        raise ValueError('Provide one Stage A file followed by one Stage B file')
    all_records = []
    settings_list = []
    for path, stage_file, expected_stage in zip(paths, ('stages/A.json', 'stages/B.json'), ('A', 'B')):
        path = Path(path)
        metadata = json.loads(Path(str(path) + '.meta.json').read_text(encoding='utf-8'))
        settings = metadata['settings']
        stage, items, prompts, digest = load(stage_file)
        if settings['stage'] != expected_stage or settings['source_sha256'] != digest:
            raise ValueError(f'{path}: stage or source fingerprint differs from current inputs')
        records = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]
        item_map = {(item['category_id'], item['id']): item for item in items}
        seen = {}
        for row in records:
            key = (row['category_id'], row['scenario_id'], row['repetition'], row['architecture'], row['condition'])
            if key in seen or key[:2] not in item_map or row['architecture'] not in stage['architectures'] or row['condition'] not in stage['conditions'] or not isinstance(row['repetition'], int) or row['repetition'] < 1:
                raise ValueError(f'{path}: duplicate or unexpected trial {key}')
            item = item_map[key[:2]]
            if (row['expected_label'], row['injection_id'], row['attacker_target']) != (item['base_label'], item['injection_id'], item['attacker_target']):
                raise ValueError(f'{path}: labels or injection differ from dataset for {key}')
            seen[key] = row
        reps = {key[2] for key in seen}
        if not reps or reps != set(range(1, max(reps) + 1)):
            raise ValueError(f'{path}: repetitions must start at 1 and be consecutive')
        nonces = metadata.get('nonces', {})
        nonce_keys = {f"{item['category_id']}/{item['id']}/{rep}"
                      for item in items for rep in reps if 'P2' in stage['architectures']}
        if set(nonces) != nonce_keys or any(len(token) != 32 or any(c not in '0123456789abcdef' for c in token) for token in nonces.values()):
            raise ValueError(f'{path}: invalid or missing session tokens')
        expected_prompts = {
            f"{item['category_id']}/{item['id']}/{condition}/{arch}/{rep}":
                messages_for(item, condition, arch, prompts,
                             nonces.get(f"{item['category_id']}/{item['id']}/{rep}") if arch == 'P2' else None)
            for item in items for condition in stage['conditions'] for arch in stage['architectures'] for rep in reps
        }
        if settings.get('design') != 'protection-layers-v2' or metadata['prompts'] != expected_prompts:
            raise ValueError(f'{path}: prompt design or snapshots do not match current inputs')
        expected = {(item['category_id'], item['id'], rep, arch, condition)
                    for item in items for rep in reps for arch in stage['architectures']
                    for condition in stage['conditions']}
        if set(seen) != expected:
            raise ValueError(f'{path}: incomplete or unexpected trials')
        all_records.append(seen)
        settings_list.append(settings)
    if any(settings_list[0][key] != settings_list[1][key] for key in ('design', 'model', 'temperature', 'top_p', 'max_new_tokens')):
        raise ValueError('Model or sampling settings differ between stages')
    a, b = all_records
    a_keys = {(cat, case, rep) for cat, case, rep, arch, cond in a}
    b_keys = {(cat, case, rep) for cat, case, rep, arch, cond in b}
    if a_keys != b_keys:
        raise ValueError('Stages have different cases or repetitions')
    for cat, case, rep in a_keys:
        seed = a[(cat, case, rep, 'P0', 'BASE')]['seed']
        if any(row['seed'] != seed for records in (a, b) for key, row in records.items() if key[:3] == (cat, case, rep)):
            raise ValueError(f'Mismatched seeds for {cat}/{case}/{rep}')
    for path in paths:
        yield from analyse([path])


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('Usage: python compare.py results/stage-a.jsonl results/stage-b.jsonl > results/stage-b-comparison.csv')
    try:
        rows = list(compare(sys.argv[1:]))
        writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    except (ValueError, KeyError, FileNotFoundError) as exc:
        raise SystemExit(str(exc))
