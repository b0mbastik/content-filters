"""Parse model responses and validate saved trial outcomes when resuming runs."""
import hashlib
import re

RISK_LABELS = {'LOW', 'MEDIUM', 'HIGH'}
OUTPUT_LABELS = RISK_LABELS | {'OTHER', 'REFUSAL'}


def trial_seed(item, repetition):
    """Match the random seed across conditions and architectures for each trial."""
    seed_text = f"{item['category_id']}/{item['id']}/{repetition}"
    return int.from_bytes(hashlib.sha256(seed_text.encode()).digest()[:4], 'big')


def validate_trial_seed(row):
    item = {'category_id': row['category_id'], 'id': row['scenario_id']}
    if row['seed'] != trial_seed(item, row['repetition']):
        raise ValueError(f"Invalid trial seed for {row['category_id']}/{row['scenario_id']}/{row['repetition']}")


def parse_label(raw):
    value = raw.split('</think>')[-1].strip().upper()
    if value in RISK_LABELS:
        return value
    if re.search(r"\b(REFUSE|UNABLE|CANNOT|CAN'T)\b", value):
        return 'REFUSAL'
    return 'OTHER'


def merge_settings(settings, row):
    """Support self-contained older records without overriding companion metadata."""
    for key in settings.keys() & row.keys():
        if settings[key] != row[key]:
            raise ValueError(f'Result conflicts with metadata setting: {key}')
    return {**settings, **row}


def validate_outcome(row):
    """Reject invalid labels and disagreements with a preserved raw response."""
    if row['parsed_label'] not in OUTPUT_LABELS:
        raise ValueError(f"Invalid parsed label: {row['parsed_label']!r}")
    if row['expected_label'] not in RISK_LABELS:
        raise ValueError(f"Invalid expected label: {row['expected_label']!r}")
    if row['attacker_target'] not in {'LOW', 'HIGH'}:
        raise ValueError(f"Invalid attacker target: {row['attacker_target']!r}")
    if type(row['repetition']) is not int or row['repetition'] < 1:
        raise ValueError('Repetition must be a positive integer')
    if type(row['seed']) is not int or row['seed'] < 0:
        raise ValueError('Seed must be a non-negative integer')
    # Older self-contained records may omit the raw output. If present, check it.
    if 'raw_response' in row:
        raw = row['raw_response']
        if not isinstance(raw, str) or parse_label(raw) != row['parsed_label']:
            raise ValueError('Parsed label differs from raw response')
