#!/usr/bin/env python3
"""Exercise the V2 loader on bounded malformed instruction streams in a disposable PHP process.

Only forward jumps and a small fixed constant pool are generated, so the corpus contains no
intentional infinite loops or arbitrary function names. A crash, timeout, unexpected output or
memory exhaustion fails the run. Successful execution is not a proof of native memory safety.
"""
from __future__ import annotations

import argparse
import base64
import json
import random
import struct
import subprocess  # nosec B404 - explicit local PHP commands
import sys
import tempfile
import time
from pathlib import Path


def generate(rng: random.Random) -> bytes:
    values = [b'\x00', b'\x01\x01', b'\x01\x00', b'\x02' + struct.pack('>q', 1),
              b'\x02' + struct.pack('>q', -3), b'\x03' + struct.pack('<d', 1.5)]
    for value in (b'abc', b'strlen', b'strval', b'$x'):
        values.append(b'\x04' + len(value).to_bytes(3, 'big') + value)
    pool = b''.join(values)
    # Include valid terminating programs too: a corpus rejected entirely by the validator would
    # never exercise the interpreter's zval ownership and arithmetic paths.
    if rng.randrange(3) == 0:
        code = bytearray()
        size = rng.randrange(1, 9)
        for _ in range(size):
            code.extend(b'\x01' + rng.randrange(len(values)).to_bytes(2, 'big'))
        code.extend(b'\x0b' + size.to_bytes(2, 'big'))  # ARRAY, collapses to one stack item
        if rng.randrange(2):
            code.extend(b'\x05\x09')  # array cast; intentionally exercises reference ownership
        code.append(9)  # RETURN
        return (b'ENVVM3' + len(values).to_bytes(2, 'big') + b'\x00\x00' + pool
                + len(code).to_bytes(4, 'big') + code)
    code = bytearray()
    for _ in range(rng.randrange(1, 80)):
        op = rng.choice(list(range(1, 18)) + [0, 255])
        code.append(op)
        if op in (1, 2, 3, 11):
            code.extend(rng.randrange(0, 18).to_bytes(2, 'big'))
        elif op in (4, 5):
            code.append(rng.randrange(0, 27))
        elif op in (6, 7, 15, 16, 17):
            code.extend(rng.randrange(0, 80).to_bytes(4, 'big', signed=True))
        elif op == 8:
            code.extend(rng.randrange(0, 18).to_bytes(2, 'big'))
            code.append(rng.randrange(0, 10))
    if rng.randrange(4) == 0:
        del code[-rng.randrange(1, min(4, len(code)) + 1):]
    header = b'ENVVM3' + len(values).to_bytes(2, 'big') + rng.randrange(0, 7).to_bytes(2, 'big')
    blob = header + pool + len(code).to_bytes(4, 'big') + code
    if rng.randrange(10) == 0:
        blob = blob[:rng.randrange(0, len(blob))]
    return blob


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--loader', required=True, type=Path)
    parser.add_argument('--php', default='php')
    parser.add_argument('--count', type=int, default=5000)
    parser.add_argument('--seed', type=int, default=73)
    args = parser.parse_args()
    if not args.loader.is_file() or not 1 <= args.count <= 30000:
        parser.error('loader must exist and count must be 1..30000')
    rng = random.Random(args.seed)  # nosec B311 - deterministic malformed corpus
    programs = [base64.b64encode(generate(rng)).decode() for _ in range(args.count)]
    harness = r'''<?php
$programs=json_decode(file_get_contents($argv[1]),true,512,JSON_THROW_ON_ERROR);
set_error_handler(function(){return true;}); $returned=0; $rejected=0;
foreach($programs as $program){
    try {__envelock_vm_v2($program,[0,'abc',[1,2],1.5,new stdClass]);$returned++;}
    catch(Throwable $e){$rejected++;}
}
restore_error_handler();
echo json_encode(['returned'=>$returned,'rejected'=>$rejected],JSON_THROW_ON_ERROR);
'''
    start = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='envelock-malformed-vm-') as temp:
            script, corpus = Path(temp) / 'run.php', Path(temp) / 'corpus.json'
            script.write_text(harness)
            corpus.write_text(json.dumps(programs))
            result = subprocess.run(  # nosec B603 - local PHP, bounded generated data
                [args.php, '-n', '-d', f'extension={args.loader.resolve()}', '-d', 'memory_limit=256M',
                 '-d', 'display_errors=stderr', str(script), str(corpus)],
                capture_output=True, check=False, timeout=120)
        if result.returncode:
            print('malformed VM worker failed: ' + result.stderr.decode(errors='replace')[-2000:], file=sys.stderr)
            return 1
        data = json.loads(result.stdout)
        if data['returned'] + data['rejected'] != args.count:
            raise ValueError('worker did not process every program')
        print(f"seed={args.seed} programs={args.count} returned={data['returned']} rejected={data['rejected']} "
              f"elapsed={time.monotonic()-start:.2f}s")
        return 0
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
        print(f'malformed VM fuzz failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
