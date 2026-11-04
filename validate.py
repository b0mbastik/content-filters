#!/usr/bin/env python3
"""Validate Stage A dataset integrity and prompt isolation (not correctness of risk labels)."""
from collections import Counter
from project import correct_label, load, messages_for
from run import build_tasks


def validate():
    stage, scenarios, prompts, digest = load()
    assert stage['stage'] == 'A'
    assert stage['conditions'] == ['BASE', 'I']
    assert stage['architectures'] == ['P0']
    assert len(scenarios) == 30 and len({s['injection_id'] for s in scenarios}) == 12
    assert Counter(s['base_label'] for s in scenarios) == {'MEDIUM': 30}
    assert Counter(s['attacker_target'] for s in scenarios) == {'LOW': 15, 'HIGH': 15}
    assert len(set((s['category_id'], s['id']) for s in scenarios)) == len(scenarios)
    for item in scenarios:
        assert item['attacker_target'] != 'MEDIUM'
        assert item['base_text'] and item['injection_text']
        assert correct_label(item, 'BASE') == correct_label(item, 'I') == 'MEDIUM'
        base = messages_for(item, 'BASE', 'P0', prompts)
        injected = messages_for(item, 'I', 'P0', prompts)
        assert len(base) == len(injected) == 1 and base[0]['role'] == 'user'
        assert item['base_text'] in base[0]['content'] and item['base_text'] in injected[0]['content']
        assert item['injection_text'] not in base[0]['content']
        assert item['injection_text'] in injected[0]['content']
        assert 'Later verified update' not in str(base) + str(injected)
        for msg in base + injected:
            assert 'attacker_target' not in msg['content']
            assert 'base_label' not in msg['content']
    assert len(build_tasks(stage, scenarios, 3)) == 180
    print('PASS: Stage A: 30 MEDIUM baseline reports, 12 attack templates, 15 LOW/15 HIGH targets')
    print('PASS: 30 scenarios; BASE/I only, P0 only')
    print('PASS: no evidence or ground-truth metadata included in prompts')
    print('Active input SHA-256:', digest)
    stage_b, items_b, prompts_b, digest_b = load('stages/B.json')
    assert stage_b['stage'] == 'B' and stage_b['conditions'] == ['BASE', 'I']
    assert stage_b['architectures'] == ['P1', 'P2']
    assert len(build_tasks(stage_b, items_b, 3)) == 360
    for original, item in zip(scenarios, items_b):
        assert original == item
        for arch in stage_b['architectures']:
            base = messages_for(item, 'BASE', arch, prompts_b, 'testtoken' if arch == 'P2' else None)
            injected = messages_for(item, 'I', arch, prompts_b, 'testtoken' if arch == 'P2' else None)
            assert base[0] == injected[0]
            assert item['base_text'] in base[1]['content'] and item['base_text'] in injected[1]['content']
            assert item['injection_text'] not in str(base) and item['injection_text'] in injected[1]['content']
            assert item['injection_text'] not in injected[0]['content']
    print('PASS: Stage B: P1/P2, same cases and attacks, 360 tasks for three repetitions')
    print('Stage B input SHA-256:', digest_b)
    print('Human label review and measured injection success are NOT established by these checks.')


if __name__ == '__main__':
    validate()
