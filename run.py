#!/usr/bin/env python3
"""One-GPU Qwen3-14B runner; labels are recorded but never sent to the model."""
import argparse
import copy
import errno
import fcntl
import hashlib
import json
import math
import random
import secrets
from functools import partial

from project import ROOT, correct_label, load, messages_for
from provenance import (capture_run_provenance, file_record, preserve_run_provenance,
                        write_json_atomically)
from result_checks import merge_settings, parse_label, trial_seed, validate_outcome


INPUT_POLICY = 'guardrails/input.yml'
CLASSIFIER_MAX_TOKENS = 24


def build_tasks(stage, scenarios, repetitions, limit=0):
    selected = scenarios[:limit or None]
    tasks = [(s, condition, arch, repetition)
             for s in selected for condition in stage['conditions']
             for arch in stage['architectures'] for repetition in range(1, repetitions + 1)]
    random.Random(2026).shuffle(tasks)
    return tasks


def generate_text(model, tokenizer, torch, messages, generation_config, **arguments):
    encoded = tokenizer.apply_chat_template(
        messages, tokenize=True, add_generation_prompt=True, return_tensors='pt',
        return_dict=True, enable_thinking=False).to('cuda:0')
    with torch.inference_mode():
        # Explicit overrides preserve greedy decoding and sampling settings.
        result = model.generate(**encoded, generation_config=generation_config, **arguments)
    return tokenizer.decode(result[0, encoded['input_ids'].shape[-1]:], skip_special_tokens=True)


def build_prompt_snapshot(tasks, prompts, nonces):
    """Compose each distinct prompt once while keeping an entry for every trial."""
    snapshot = {}
    by_prompt = {}
    for key, item in tasks.items():
        category, scenario, condition, architecture, repetition = key
        nonce = nonces[f'{category}/{scenario}/{repetition}'] if architecture == 'P2' else None
        prompt = (category, scenario, condition, architecture, nonce)
        if prompt not in by_prompt:
            by_prompt[prompt] = messages_for(item, condition, architecture, prompts, nonce)
        snapshot['/'.join(map(str, key))] = by_prompt[prompt]
    return snapshot


def read_completed_trials(stream, tasks, settings, guarded):
    """Validate saved rows before opening the model or appending results."""
    completed = set()
    needs_newline = False
    for line_number, line in enumerate(stream, start=1):
        try:
            row = json.loads(line)
            key = (row['category_id'], row['scenario_id'], row['condition'],
                   row['architecture'], row['repetition'])
            if key in completed:
                raise ValueError(f'Duplicate result: {key}')
            if key not in tasks:
                raise ValueError(f'Unexpected result: {key}')
            item = tasks[key]
            merge_settings(settings, row)
            validate_outcome(row)
            if guarded != ('input_guardrail' in row):
                raise ValueError(f'Existing result has inconsistent input guardrail metadata: {key}')
            expected = (correct_label(item, row['condition']), item['attacker_target'],
                        item['injection_id'], trial_seed(item, row['repetition']))
            if (row['expected_label'], row['attacker_target'], row['injection_id'], row['seed']) != expected:
                raise ValueError(f'Existing result does not match the configured trial: {key}')
        except (KeyError, TypeError, ValueError) as exc:
            raise SystemExit(f'Invalid result at {stream.name}:{line_number}: {exc}') from exc
        completed.add(key)
        needs_newline = not line.endswith('\n')
    return completed, needs_newline


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--stage', default='stages/A.json')
    parser.add_argument('--out', help='Output JSONL (defaults to results/stage-<stage>[-nemo-input].jsonl)')
    parser.add_argument('--reps', type=int, default=3)
    parser.add_argument('--limit', type=int, default=0, help='Maximum number of scenarios')
    parser.add_argument('--temperature', type=float, default=0.7)
    parser.add_argument('--top-p', type=float, default=0.8)
    parser.add_argument('--input-guardrail', action='store_true', help='Screen input for jailbreaks with NeMo before classification')
    parser.add_argument('--dry-run', action='store_true', help='Print all configured conditions and architectures for one case without using GPU')
    args = parser.parse_args()
    if (args.reps < 1 or args.limit < 0 or not math.isfinite(args.temperature)
            or args.temperature < 0 or not 0 < args.top_p <= 1):
        parser.error('Invalid sampling or count argument')
    stage, scenarios, prompts, digest = load(args.stage)
    tasks = build_tasks(stage, scenarios, args.reps, args.limit)
    if not tasks:
        raise SystemExit('No tasks found')
    if args.dry_run:
        first = tasks[0][0]
        for arch in stage['architectures']:
            for condition in stage['conditions']:
                messages = messages_for(first, condition, arch, prompts, 'preview' if arch == 'P2' else None)
                print(json.dumps({'scenario_id': first['id'], 'condition': condition,
                                  'architecture': arch, 'messages': messages}, indent=2))
        print(f'Total tasks: {len(tasks)}')
        return

    suffix = '-nemo-input' if args.input_guardrail else ''
    output = ROOT / (args.out or f"results/stage-{stage['stage'].lower()}{suffix}.jsonl")
    output.parent.mkdir(parents=True, exist_ok=True)
    settings = {'stage': stage['stage'], 'source_sha256': digest,
                'design': 'protection-layers-v2', 'model': 'Qwen3-14B', 'temperature': args.temperature,
                'top_p': args.top_p, 'max_new_tokens': CLASSIFIER_MAX_TOKENS}
    policy_text = None
    if args.input_guardrail:
        policy = (ROOT / INPUT_POLICY).read_bytes()
        settings['input_guardrail_policy_sha256'] = hashlib.sha256(policy).hexdigest()
        policy_text = policy.decode('utf-8')
    expected_tasks = {
        (item['category_id'], item['id'], condition, arch, rep): item
        for item, condition, arch, rep in tasks
    }
    if len(expected_tasks) != len(tasks):
        raise SystemExit('Stage configuration contains duplicate trials')

    try:
        stream = output.open('a+', encoding='utf-8')
    except PermissionError:
        stream = output.open(encoding='utf-8')
    with stream:
        lock = fcntl.LOCK_EX if stream.writable() else fcntl.LOCK_SH
        try:
            fcntl.lockf(stream, lock | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                raise SystemExit(f'Another runner is using {output}; choose a different --out') from exc
            raise
        run_trials(stream, output, expected_tasks, settings, prompts, policy_text)


def prepare_metadata(metadata_path, tasks, settings, prompts, policy_text, has_results):
    try:
        existing_metadata = json.loads(metadata_path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        if has_results:
            raise SystemExit('Existing result has no matching metadata; choose a new --out')
        existing_metadata = None
    except ValueError as exc:
        raise SystemExit(f'Invalid run metadata at {metadata_path}: {exc}') from exc
    else:
        if not isinstance(existing_metadata, dict) or not isinstance(existing_metadata.get('nonces', {}), dict):
            raise SystemExit(f'Invalid run metadata at {metadata_path}')

    # Each P2 trial shares a nonce across its matched conditions.
    nonce_keys = {f'{category}/{scenario}/{rep}' for category, scenario, _, arch, rep in tasks if arch == 'P2'}
    nonces = (existing_metadata.get('nonces', {}) if existing_metadata is not None else
              {key: secrets.token_hex(16) for key in sorted(nonce_keys)})
    if set(nonces) != nonce_keys:
        raise SystemExit('Existing metadata has different session tokens or tasks; change --out')
    snapshot = build_prompt_snapshot(tasks, prompts, nonces)
    metadata = {'settings': settings, 'nonces': nonces, 'prompts': snapshot}
    if policy_text is not None:
        metadata['input_guardrail_policy'] = policy_text
    if existing_metadata is None:
        return snapshot, metadata
    if existing_metadata != metadata:
        raise SystemExit('Existing result has different settings or prompts; change --out')
    return snapshot, None


def run_trials(stream, output, tasks, settings, prompts, policy_text):
    guarded = policy_text is not None
    metadata_path = output.with_suffix(output.suffix + '.meta.json')
    has_results = stream.seek(0, 2) > 0
    stream.seek(0)
    snapshot, new_metadata = prepare_metadata(metadata_path, tasks, settings, prompts, policy_text, has_results)
    completed, needs_newline = read_completed_trials(stream, tasks, settings, guarded)
    if len(completed) == len(tasks):
        print(f'All {len(tasks)} tasks already completed')
        return
    if not stream.writable():
        raise SystemExit(f'Output is read-only: {output}')
    if new_metadata is not None:
        write_json_atomically(metadata_path, new_metadata)

    provenance_path = output.with_suffix(output.suffix + '.provenance.json')
    if completed and not provenance_path.exists():
        raise SystemExit('Partial legacy run has no inference provenance; choose a new --out')

    if guarded:
        try:
            from input_guardrail import build_input_guardrail
        except ModuleNotFoundError as exc:
            if exc.name != 'nemoguardrails':
                raise
            raise SystemExit('Install requirements-guardrail.txt with Python 3.10–3.13 to use --input-guardrail') from exc

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    model_dir = ROOT / 'models' / 'Qwen3-14B'
    if not (model_dir / 'config.json').exists():
        raise SystemExit(f'Qwen3-14B not found: {model_dir}')
    tokenizer = AutoTokenizer.from_pretrained(str(model_dir), local_files_only=True)
    model = AutoModelForCausalLM.from_pretrained(
        str(model_dir), torch_dtype=torch.bfloat16, device_map={'': 0}, local_files_only=True).eval()
    generation_config = copy.deepcopy(model.generation_config)
    arguments = {'max_new_tokens': settings['max_new_tokens'], 'pad_token_id': tokenizer.eos_token_id,
                 'do_sample': settings['temperature'] > 0}
    if arguments['do_sample']:
        arguments.update(temperature=settings['temperature'], top_p=settings['top_p'])
    generation_config.update(**arguments)
    generate = partial(generate_text, model, tokenizer, torch)
    check_input = None
    if guarded:
        def judge(messages, max_tokens):
            return generate(messages, model.generation_config, max_new_tokens=max_tokens,
                            pad_token_id=tokenizer.eos_token_id, do_sample=False)

        check_input = build_input_guardrail(policy_text, judge)

    print('Recording model hashes and inference provenance', flush=True)
    provenance = capture_run_provenance(ROOT, model_dir, torch, generation_config)
    if guarded:
        provenance['identity']['input_guardrail'] = {
            'policy_sha256': settings['input_guardrail_policy_sha256'],
            'adapter': file_record(ROOT / 'input_guardrail.py'),
            'reuse_identical_messages_within_process': True,
            'generation_overrides': {'do_sample': False, 'pad_token_id': tokenizer.eos_token_id},
        }
    try:
        preserve_run_provenance(provenance_path, provenance, has_results=bool(completed))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    stream.seek(0, 2)
    verdicts = {}
    count = len(completed)
    for key, item in tasks.items():
        if key in completed:
            continue
        category, scenario, condition, arch, rep = key
        messages = snapshot['/'.join(map(str, key))]
        verdict = None
        if guarded:
            # Include every message, so a change of system text or nonce requires a fresh check.
            message_key = tuple((message['role'], message['content']) for message in messages)
            if message_key not in verdicts:
                verdicts[message_key] = check_input(messages)
            verdict = verdicts[message_key]
        # Matched conditions and architectures share a reproducible repetition seed.
        seed = trial_seed(item, rep)
        if verdict == 'blocked':
            raw = 'I cannot classify this input.'
        else:
            torch.manual_seed(seed)
            raw = generate(messages, generation_config, **arguments)
        row = {'category_id': category, 'scenario_id': scenario,
               'condition': condition, 'architecture': arch,
               'repetition': rep, 'injection_id': item['injection_id'],
               'attacker_target': item['attacker_target'],
               'expected_label': correct_label(item, condition),
               'seed': seed,
               'raw_response': raw, 'parsed_label': parse_label(raw)}
        if guarded:
            row['input_guardrail'] = verdict
        prefix = '\n' if needs_newline else ''
        stream.write(prefix + json.dumps(row, ensure_ascii=False) + '\n')
        stream.flush()
        needs_newline = False
        count += 1
        if count % 10 == 0 or count == len(tasks):
            print(f'{count}/{len(tasks)} tasks processed', flush=True)


if __name__ == '__main__':
    main()
