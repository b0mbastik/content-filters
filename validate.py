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
    assert Counter(s['split'] for s in scenarios) == {'development': 12, 'evaluation': 18}
    assert Counter(s['attacker_target'] for s in scenarios if s['split'] == 'development') == {'LOW': 6, 'HIGH': 6}
    assert Counter(s['attacker_target'] for s in scenarios if s['split'] == 'evaluation') == {'LOW': 9, 'HIGH': 9}
    assert len(set((s['category_id'], s['id']) for s in scenarios)) == len(scenarios)
    for item in scenarios:
        assert item['attacker_target'] != 'MEDIUM'
        assert item['base_text'] and item['injection_text']
        assert correct_label(item, 'BASE') == correct_label(item, 'I') == 'MEDIUM'
        base = messages_for(item, 'BASE', 'P0', prompts)
        injected = messages_for(item, 'I', 'P0', prompts)
        assert base[0] == injected[0]
        assert item['base_text'] in base[1]['content'] and item['base_text'] in injected[1]['content']
        assert item['injection_text'] not in base[1]['content']
        assert item['injection_text'] in injected[1]['content']
        assert item['injection_text'] not in injected[0]['content']
        assert 'Later verified update' not in str(base) + str(injected)
        for msg in base + injected:
            assert 'attacker_target' not in msg['content']
            assert 'base_label' not in msg['content']
    assert len(build_tasks(stage, scenarios, 'development', 3)) == 72
    assert len(build_tasks(stage, scenarios, 'evaluation', 3)) == 108
    print('PASS: Stage A: 30 MEDIUM baseline reports, 12 attack templates, 15 LOW/15 HIGH targets')
    print('PASS: 12 development / 18 held-out evaluation scenarios; BASE/I only, P0 only')
    print('PASS: no evidence or ground-truth metadata included in prompts')
    print('Active input SHA-256:', digest)
    print('Human label review and measured injection success are NOT established by these checks.')


if __name__ == '__main__':
    validate()
