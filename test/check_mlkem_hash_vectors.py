#!/usr/bin/env python3
"""Verify pinned NIST hash responses, optionally compare a native test driver.

The native driver uses the bundled implementation. This oracle uses Python's
separate hashlib provider. It neither implements nor replaces production crypto.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'test/data/mlkem_hash_sources.json'
MODES = {
    'SHA3_256': ('sha3-256', hashlib.sha3_256, 32),
    'SHA3_512': ('sha3-512', hashlib.sha3_512, 64),
    'SHAKE128': ('shake128', hashlib.shake_128, None),
    'SHAKE256': ('shake256', hashlib.shake_256, None),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def octets(text):
    require(re.fullmatch('[0-9a-f]+', text) is not None and len(text) % 2 == 0,
            'noncanonical hex')
    return bytes.fromhex(text)


def bit_count(text):
    require(re.fullmatch('[0-9]+', text) is not None, 'nondecimal length')
    value = int(text)
    require(value % 8 == 0, 'non-byte input/output')
    return value // 8


def reference(mode, message, length):
    for name, constructor, fixed in MODES.values():
        if name == mode:
            require(fixed is None or length == fixed, 'fixed output extent')
            return constructor(message).digest() if fixed else constructor(message).digest(length)
    raise ValueError('unknown mode: ' + mode)


def verify_file(row):
    raw = (ROOT / row['path']).read_bytes()
    require(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'],
            'checksum: ' + row['path'])
    prefix = row['member'].split('Short')[0].split('Long')[0].split('Variable')[0]
    mode, _, fixed = MODES[prefix]
    metadata = {}
    record = {}
    count = 0
    for line in raw.decode('ascii').splitlines():
        if not line or line.startswith('#'):
            continue
        if line.startswith('[') and line.endswith(']'):
            if line == '[Tested for Output of byte-oriented messages]':
                continue
            key, value = line[1:-1].split(' = ')
            require(key not in metadata, 'duplicate metadata')
            metadata[key] = value
            continue
        key, value = line.split(' = ')
        require(key not in record, 'duplicate field')
        record[key] = value
        if key not in ('MD', 'Output'):
            continue
        variable = 'VariableOut' in row['member']
        expected_keys = {'COUNT', 'Outputlen', 'Msg', 'Output'} if variable else {'Len', 'Msg', key}
        require(set(record) == expected_keys, 'record fields')
        if variable:
            require(int(record['COUNT']) == count, 'record ordinal')
        length = bit_count(metadata['Input Length'] if variable else record['Len'])
        encoded = octets(record['Msg'])
        if length == 0:
            require(encoded == b'\0', 'zero-message convention')
        else:
            require(len(encoded) == length, 'message extent')
        message = encoded[:length]
        output_length = fixed if fixed else bit_count(record['Outputlen'] if variable else metadata['Outputlen'])
        answer = octets(record[key])
        require(len(answer) == output_length and reference(mode, message, output_length) == answer,
                'reference answer: ' + row['member'] + ' record ' + str(count))
        require(length <= row['maximum_input_bytes'], 'input bound')
        count += 1
        record = {}
    require(not record and count == row['cases'], 'record count')
    return count


def boundary_requests():
    inputs = [0, 1, 33, 34, 71, 72, 73, 135, 136, 137, 167, 168, 169,
              335, 336, 337, 1120, 1184, 4096]
    outputs = [0, 1, 31, 32, 63, 64, 135, 136, 137, 167, 168, 169,
               503, 504, 505, 671, 672, 673, 1024]
    requests = []
    for size in inputs:
        for pattern in range(2):
            message = bytes(size) if pattern == 0 else bytes((197 * i + size + 7) % 256 for i in range(size))
            for mode, lengths in [('sha3-256', [32]), ('sha3-512', [64]),
                                  ('shake128', outputs), ('shake256', outputs)]:
                for length in lengths:
                    requests.append((mode, message, length, reference(mode, message, length)))
    for seed in range(16):
        message = bytes((29 * i + 17 * seed) % 256 for i in range(102))
        expected = b''.join(hashlib.shake_128(message[34 * i:34 * (i + 1)]).digest(672) for i in range(3))
        requests.append(('matrix128', message, len(expected), expected))
    require(len(requests) == 1536, 'boundary extent')
    return requests


def compare_program(program):
    requests = boundary_requests()
    wire = ''.join(f'{mode} {length} {message.hex() or "-"}\n'
                   for mode, message, length, _ in requests)
    # One process and one reused work area for the complete boundary matrix.
    completed = subprocess.run([str(Path(program).resolve()), '--oracle'], input=wire,
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    require(completed.returncode == 0, 'native oracle exit: ' + str(completed.returncode)
            + '\n' + completed.stderr)
    require(completed.stderr == f'ML-KEM hash oracle: cases={len(requests)} valid=1\n',
            'native oracle diagnostics: ' + completed.stderr)
    lines = completed.stdout.splitlines()
    require(len(lines) == len(requests), 'native oracle output count')
    for index, (line, request) in enumerate(zip(lines, requests)):
        require(line == request[3].hex(), 'native boundary answer: ' + str(index))
    print(f'ML-KEM hash boundary: requests={len(requests)} passed={len(requests)}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--program', help='built dssh_test_mlkem_hash executable')
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text())
    rows = manifest['selected_files']
    require(len(rows) == 10 and len({row['path'] for row in rows}) == 10,
            'selected file extent')
    total = sum(verify_file(row) for row in rows)
    require(total == manifest['total_cases'] == 3592, 'complete corpus count')
    print(f'ML-KEM hash Python: files=10 cases={total} valid=1')
    if args.program:
        compare_program(args.program)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, UnicodeError) as error:
        print('ML-KEM hash check failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
