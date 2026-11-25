#!/usr/bin/env python3
"""Export Category 2 report and fixture pairs as offline JSONL review records."""
import argparse
import json

from project import ROOT, load, messages_for


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--architecture', choices=('P0', 'P1', 'P2'), default='P1')
    args = parser.parse_args()

    _, scenarios, prompts, _ = load('stages/category_2_baseline.json')
    fixture_paths = sorted((ROOT / 'injections_v2').glob('*.txt'))
    if not fixture_paths:
        parser.error('No fixture text files found in injections_v2/')
    fixtures = {path.stem: path.read_text(encoding='utf-8').strip() for path in fixture_paths}

    nonce = 'preview' if args.architecture == 'P2' else None
    for scenario in scenarios:
        clean_messages = messages_for(scenario, 'BASE', args.architecture, prompts, nonce)
        system_prompt = next((message['content'] for message in clean_messages
                              if message['role'] == 'system'), None)
        for fixture_id, fixture_text in fixtures.items():
            record = {
                'scenario_id': scenario['id'],
                'architecture': args.architecture,
                'system_prompt': system_prompt,
                'baseline_text': scenario['base_text'],
                'fixture_id': fixture_id,
                'untrusted_fixture_text': fixture_text,
            }
            if args.architecture == 'P0':
                record['rubric'] = scenario['rubric']
                record['prompt_template'] = prompts['P0']
            print(json.dumps(record, ensure_ascii=False))


if __name__ == '__main__':
    main()
