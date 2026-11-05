#!/usr/bin/env python3
"""One-GPU Qwen3-14B runner; labels are recorded but never sent to the model."""
import argparse
import hashlib
import json
import random
import re
import secrets

from project import ROOT, correct_label, load, messages_for


def parse_label(raw):
    value = raw.split('</think>')[-1].strip().upper()
    if value in {'LOW', 'MEDIUM', 'HIGH'}:
        return value
    if re.search(r"\b(REFUSE|UNABLE|CANNOT|CAN'T)\b", value):
        return 'REFUSAL'
    return 'OTHER'


def build_tasks(stage, scenarios, repetitions, limit=0):
    selected = scenarios[:limit or None]
    tasks = [(s, condition, arch, repetition)
             for s in selected for condition in stage['conditions']
             for arch in stage['architectures'] for repetition in range(1, repetitions + 1)]
    random.Random(2026).shuffle(tasks)
    return tasks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--stage', default='stages/A.json')
    parser.add_argument('--out', help='Output JSONL (defaults to results/stage-<stage>.jsonl)')
    parser.add_argument('--reps', type=int, default=3)
    parser.add_argument('--limit', type=int, default=0, help='Maximum number of scenarios')
    parser.add_argument('--temperature', type=float, default=0.7)
    parser.add_argument('--top-p', type=float, default=0.8)
    parser.add_argument('--dry-run', action='store_true', help='Print all configured conditions and architectures for one case without using GPU')
    args = parser.parse_args()
    if args.reps < 1 or args.limit < 0 or args.temperature < 0 or not 0 < args.top_p <= 1:
        parser.error('Invalid sampling or count argument')
    stage, scenarios, prompts, digest = load(args.stage)
    tasks = build_tasks(stage, scenarios, args.reps, args.limit)
    if not tasks:
        raise SystemExit('No tasks found')
    if args.dry_run:
        first = tasks[0][0]
        preview = [(first, cond, arch, 1) for arch in stage['architectures']
                   for cond in stage['conditions']]
        for item, condition, arch, rep in preview:
            print(json.dumps({'scenario_id': item['id'], 'condition': condition,
                              'architecture': arch, 'messages': messages_for(item, condition, arch, prompts, 'preview' if arch == 'P2' else None)},
                             indent=2))
        print(f'Total tasks: {len(tasks)}')
        return

    output = ROOT / (args.out or f"results/stage-{stage['stage'].lower()}.jsonl")
    output.parent.mkdir(parents=True, exist_ok=True)
    settings = {'stage': stage['stage'], 'source_sha256': digest,
                'design': 'protection-layers-v2', 'model': 'Qwen3-14B', 'temperature': args.temperature,
                'top_p': args.top_p, 'max_new_tokens': 24}
    # Persist a random token per case/repetition, shared across the matched conditions.
    metadata_path = output.with_suffix(output.suffix + '.meta.json')
    existing_metadata = json.loads(metadata_path.read_text(encoding='utf-8')) if metadata_path.exists() else None
    nonce_keys = {f"{item['category_id']}/{item['id']}/{rep}"
                  for item, _, arch, rep in tasks if arch == 'P2'}
    nonces = existing_metadata.get('nonces', {}) if existing_metadata else {
        key: secrets.token_hex(16) for key in sorted(nonce_keys)}
    if set(nonces) != nonce_keys:
        raise SystemExit('Existing metadata has different session tokens or tasks; change --out')
    prompt_snapshot = {}
    for item, condition, arch, rep in tasks:
        prompt_key = f"{item['category_id']}/{item['id']}/{condition}/{arch}/{rep}"
        nonce = nonces.get(f"{item['category_id']}/{item['id']}/{rep}") if arch == 'P2' else None
        prompt_snapshot[prompt_key] = messages_for(item, condition, arch, prompts, nonce)
    metadata = {'settings': settings, 'nonces': nonces, 'prompts': prompt_snapshot}
    already = {}
    if output.exists() and output.stat().st_size:
        if not metadata_path.exists():
            raise SystemExit('Existing result has no matching metadata; choose a new --out')
        if json.loads(metadata_path.read_text(encoding='utf-8')) != metadata:
            raise SystemExit('Existing result has different settings or prompts; change --out')
        with output.open(encoding='utf-8') as stream:
            for line in stream:
                row = json.loads(line)
                key = (row['category_id'], row['scenario_id'], row['condition'],
                       row['architecture'], row['repetition'])
                if key in already:
                    raise SystemExit(f'Duplicate result: {key}')
                already[key] = row
    else:
        if metadata_path.exists() and json.loads(metadata_path.read_text(encoding='utf-8')) != metadata:
            raise SystemExit('Existing metadata has different settings or prompts; change --out')
        metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    model_dir = ROOT / 'models' / 'Qwen3-14B'
    if not (model_dir / 'config.json').exists():
        raise SystemExit(f'Qwen3-14B not found: {model_dir}')
    tokenizer = AutoTokenizer.from_pretrained(str(model_dir), local_files_only=True)
    model = AutoModelForCausalLM.from_pretrained(
        str(model_dir), torch_dtype=torch.bfloat16, device_map={'': 0}, local_files_only=True).eval()
    with output.open('a', encoding='utf-8') as stream:
        for index, (item, condition, arch, rep) in enumerate(tasks, start=1):
            key = (item['category_id'], item['id'], condition, arch, rep)
            nonce = nonces.get(f"{item['category_id']}/{item['id']}/{rep}") if arch == 'P2' else None
            messages = messages_for(item, condition, arch, prompts, nonce)
            if key in already:
                continue
            # Matched conditions and architectures share a reproducible repetition seed.
            seed_text = f"{item['category_id']}/{item['id']}/{rep}"
            seed = int.from_bytes(hashlib.sha256(seed_text.encode()).digest()[:4], 'big')
            torch.manual_seed(seed)
            torch.cuda.manual_seed_all(seed)
            encoded = tokenizer.apply_chat_template(
                messages, tokenize=True, add_generation_prompt=True, return_tensors='pt',
                return_dict=True, enable_thinking=False).to('cuda:0')
            arguments = {'max_new_tokens': 24, 'pad_token_id': tokenizer.eos_token_id,
                         'do_sample': args.temperature > 0}
            if args.temperature > 0:
                arguments.update(temperature=args.temperature, top_p=args.top_p)
            with torch.inference_mode():
                result = model.generate(**encoded, **arguments)
            raw = tokenizer.decode(result[0, encoded['input_ids'].shape[-1]:], skip_special_tokens=True)
            row = {'category_id': item['category_id'], 'scenario_id': item['id'],
                   'condition': condition, 'architecture': arch,
                   'repetition': rep, 'injection_id': item['injection_id'],
                   'attacker_target': item['attacker_target'],
                   'expected_label': correct_label(item, condition),
                   'seed': seed,
                   'raw_response': raw, 'parsed_label': parse_label(raw)}
            stream.write(json.dumps(row, ensure_ascii=False) + '\n')
            stream.flush()
            if index % 10 == 0 or index == len(tasks):
                print(f'{index}/{len(tasks)} tasks processed', flush=True)


if __name__ == '__main__':
    main()
