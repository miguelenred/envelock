#!/usr/bin/env python3
"""Continuous fuzzing of the bytecode deserializer: mutated images must be rejected, never crash.

The loader turns a bytecode image (an op_array serialized at pack time) back into engine structures.
In production every image is inside a signed, encrypted container, so a malformed one can only come
from the trusted signer; this checks the layer behind that boundary anyway (defence in depth). It
feeds mutated images to envelock_bc_load_check() — deserialize and install WITHOUT executing, the
TEST-ONLY entry of a loader built with --enable-envelock-bcrun-unsafe, never shipped — and requires
every one to end cleanly: loaded or rejected. A crash (a signal), or an AddressSanitizer/UBSan report
when the loader is built with them, is a failure, and its image is saved as a reproducer.

    python3 scripts/fuzz_bytecode.py --loader modules/envelock.so --seconds 300 --out /tmp/fuzz-bc

With a sanitizer build, run it with the sanitizer runtime preloaded (the PHP binary is not built with
it) and PHP's own allocator off, so the sanitizer sees every allocation:

    LD_PRELOAD="$(gcc -print-file-name=libasan.so) $(gcc -print-file-name=libubsan.so)" \
    USE_ZEND_ALLOC=0 ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 python3 scripts/fuzz_bytecode.py ...

How it works:
- Seed images are emitted by the loader under test (envelock_bc_emit) from a set of PHP programs that
  cover what the serializer handles: classes, traits, interfaces, enums, closures, generators, match,
  exceptions, static variables, references, attributes, heredocs, named arguments, constants. An image
  is bound to the exact PHP build, so seeds are always made by the PHP that loads them.
- Mutations are structure-aware: overwrite a 1/2/4/8-byte word with a boundary value, flip bits,
  randomize bytes, copy a chunk over another, truncate or extend, and corrupt the header's sizes and
  offsets. The program checksum (adler32) is recomputed for most cases so that they reach the
  deserializer instead of stopping at the checksum; some keep a stale one on purpose.
- Images are run in batches, one PHP process per batch; each case's index is written and flushed
  before it is loaded, so a crash points at its image directly. The image is then run alone to
  confirm, and kept.
- The run is reproducible from --seed (printed); the time budget is --seconds.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import random
import shutil
import struct
import subprocess  # nosec B404 - runs the local php CLI with fixed argument lists, no shell
import sys
import tempfile
import time
import zlib

HEADER = 80
OFF_MEM_SIZE, OFF_STR_SIZE, OFF_SCRIPT, OFF_TIMESTAMP, OFF_ADLER = 48, 56, 64, 72, 76

PROGRAMS = {
    "core": r"""<?php
declare(strict_types=1);
const FZ_NAME = "fuzz";
interface FzShape { public function area(): float; }
trait FzTagged { private array $tags = []; public function tag(string ...$t): static { array_push($this->tags, ...$t); return $this; } }
abstract class FzBase implements FzShape { public function __construct(protected readonly string $id = "x") {} abstract public function area(): float; }
final class FzRect extends FzBase { use FzTagged; public function __construct(private float $w, private float $h) { parent::__construct("rect"); } public function area(): float { return $this->w * $this->h; } }
enum FzSuit: string { case Hearts = "H"; case Spades = "S"; public function color(): string { return match ($this) { self::Hearts => "red", self::Spades => "black" }; } }
function fz_gen(int $n): Generator { for ($i = 0; $i < $n; $i++) { $x = yield $i => $i * $i; if ($x) { break; } } return $n; }
function fz_static(): int { static $c = 0; return ++$c; }
function &fz_ref(array &$a) { $r = &$a[0]; return $r; }
$f = fn(int $x): int => $x + 1;
$g = function (int $y) use ($f, &$out) { $out = $f($y); return $out; };
try { $g(2); throw new RuntimeException("e", 3); } catch (LogicException | RuntimeException $e) { $m = $e->getMessage(); } finally { $z = 1; }
$s = <<<EOT
heredoc {$m} and {$z}
EOT;
$arr = ['a' => 1, ...['b' => 2]];
echo (new FzRect(2.0, 3.0))->tag("a", "b")->area(), FzSuit::from("H")->color(), fz_static(), strlen(...)("ab"), $s;
""",
    "control": r"""<?php
namespace Fz\Control;
use InvalidArgumentException as Bad;
#[\Attribute(\Attribute::TARGET_CLASS | \Attribute::TARGET_METHOD)]
final class Marker { public function __construct(public string $name = "m", public array $opts = []) {} }
#[Marker("svc", opts: ["a" => 1])]
class Service {
    public const LIMIT = 10;
    public static int $count = 0;
    #[Marker] public function run(array $items, ?callable $cb = null): array {
        $out = [];
        foreach ($items as $k => [$a, $b]) {
            switch (true) { case $a > self::LIMIT: continue 2; case $a < 0: break; default: $out[$k] = $cb ? $cb($a, b: $b) : $a <=> $b; }
        }
        while (count($out) > 3) { array_pop($out); }
        do { static::$count++; } while (static::$count < 2);
        if (!$out) { throw new Bad("empty"); }
        return $out;
    }
    public function __get(string $n): mixed { return $n; }
    public function __call(string $n, array $a): mixed { return [$n, $a]; }
}
function label(int|string $v): string { return match (true) { is_int($v) && $v > 0 => "pos", is_int($v) => "int", default => (string) $v }; }
$svc = new Service();
echo json_encode($svc->run([[1, 2], [30, 1], [3, 3]], fn($a, $b) => $a * $b)), label(5), $svc->missing, isset($svc?->x) ? 1 : 0;
goto end;
echo "skipped";
end:
echo PHP_EOL;
""",
    "strings": r"""<?php
$long = str_repeat("Envelock-", 300);
$map = [];
for ($i = 0; $i < 200; $i++) { $map["key_$i"] = ["v" => $i, "s" => "s$i", "f" => $i / 3, "b" => $i % 2 === 0, "n" => null]; }
$nested = ['a' => ['b' => ['c' => ['d' => [1, 2, 3, ['e' => 'deep']]]]]];
list('a' => $x, 'b' => $y) = ['a' => 1, 'b' => 2];
printf("%s %d %.2f %s\n", substr($long, 0, 9), count($map), 1.5, $nested['a']['b']['c']['d'][3]['e']);
echo implode(",", array_map(static fn(array $r): string => $r["s"], array_slice($map, 0, 5))), PHP_EOL;
""",
}

INTERESTING = [0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 0x7F, 0x80, 0xFF,
               0x7FFF, 0x8000, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x100000000,
               0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF]

RUNNER = r"""<?php
$data = file_get_contents($argv[1]);
$pos = 0; $i = 0;
while ($pos < strlen($data)) {
    $len = unpack("N", substr($data, $pos, 4))[1];
    $image = substr($data, $pos + 4, $len);
    $pos += 4 + $len;
    fwrite(STDOUT, "case $i\n"); fflush(STDOUT);
    $ok = envelock_bc_load_check($image);
    fwrite(STDOUT, $ok ? "loaded $i\n" : "rejected $i\n"); fflush(STDOUT);
    $i++;
}
fwrite(STDOUT, "done $i\n");
"""


PHP_ENV = dict(os.environ)


def emit_seeds(php: list[str], work: pathlib.Path) -> dict[str, bytes]:
    seeds = {}
    for name, source in PROGRAMS.items():
        path = work / f"{name}.php"
        path.write_text(source, encoding="utf-8")
        out = work / f"{name}.bin"
        result = subprocess.run([*php, "-r", "$i = envelock_bc_emit($argv[1]); if ($i === false) exit(3);"  # nosec B603
                                 " file_put_contents($argv[2], $i);", str(path), str(out)],
                                capture_output=True, text=True, timeout=120, check=False, env=PHP_ENV)
        if result.returncode != 0 or not out.is_file():
            raise SystemExit(f"cannot emit the {name} seed: rc={result.returncode}\n{result.stdout}\n{result.stderr}")
        seeds[name] = out.read_bytes()
    return seeds


def fix_checksum(image: bytearray) -> None:
    if len(image) < HEADER:
        return
    mem_size = int.from_bytes(image[OFF_MEM_SIZE:OFF_MEM_SIZE + 8], "big")
    if HEADER + mem_size <= len(image):
        image[OFF_ADLER:OFF_ADLER + 4] = zlib.adler32(bytes(image[HEADER:HEADER + mem_size])).to_bytes(4, "big")


def mutate(rng: random.Random, seed: bytes) -> tuple[bytes, str]:
    image = bytearray(seed)
    body = len(image) - HEADER
    kind = rng.choice(["word", "word", "word", "bits", "bytes", "chunk", "header", "truncate", "extend"])
    for _ in range(rng.choice([1, 1, 1, 2, 3, 8])):
        if kind == "word" and body > 8:
            width = rng.choice([1, 2, 4, 8])
            offset = HEADER + rng.randrange(0, body - width)
            value = rng.choice(INTERESTING + [rng.getrandbits(8 * width), len(seed) + rng.randrange(-16, 16)])
            value &= (1 << (8 * width)) - 1
            image[offset:offset + width] = value.to_bytes(width, rng.choice(["little", "big"]))
        elif kind == "bits" and body > 0:
            offset = HEADER + rng.randrange(body)
            image[offset] ^= 1 << rng.randrange(8)
        elif kind == "bytes" and body > 0:
            offset = HEADER + rng.randrange(body)
            image[offset] = rng.randrange(256)
        elif kind == "chunk" and body > 32:
            size = rng.randrange(1, min(256, body // 2))
            source = HEADER + rng.randrange(0, body - size)
            target = HEADER + rng.randrange(0, body - size)
            image[target:target + size] = image[source:source + size]
        elif kind == "header":
            field = rng.choice([OFF_MEM_SIZE, OFF_STR_SIZE, OFF_SCRIPT, OFF_TIMESTAMP])
            value = rng.choice(INTERESTING + [body, body - 1, body + 1, rng.randrange(0, max(body, 1))])
            image[field:field + 8] = (value & (1 << 64) - 1).to_bytes(8, "big")
        elif kind == "truncate":
            del image[rng.randrange(0, len(image)):]
            break
        elif kind == "extend":
            image += bytes(rng.randrange(256) for _ in range(rng.randrange(1, 64)))
            break
    if rng.random() < 0.9:
        fix_checksum(image)
    return bytes(image), kind


_MARKERS = ("runtime error:", "ERROR: AddressSanitizer", "SUMMARY:", "Fatal error", "Segmentation", "#0 ", "#1 ",
            "#2 ", "#3 ")


def key_lines(text: str) -> list[str]:
    """The lines that say what went wrong: the sanitizer's verdict, PHP's fatal error, the top frames."""
    return [line.strip()[:300] for line in text.splitlines() if any(m in line for m in _MARKERS)][:12]


def is_fault(code: int, output: str) -> bool:
    """A crash, a sanitizer report or a hang. A PHP fatal error (exit 255) is a clean rejection."""
    return (code != 0 and code != 255) or "AddressSanitizer" in output or "runtime error:" in output


def run_batch(php: list[str], runner: pathlib.Path, batch: list[bytes], work: pathlib.Path,
              timeout: int) -> tuple[int, list[int], str, int | None, int]:
    """Run images in one PHP process: (exit code, indices that loaded, output when not clean, last case
    started, cases started)."""
    path = work / "batch.bin"
    path.write_bytes(b"".join(struct.pack(">I", len(image)) + image for image in batch))
    try:
        result = subprocess.run([*php, str(runner), str(path)], capture_output=True, timeout=timeout,  # nosec B603
                                check=False, env=PHP_ENV)
    except subprocess.TimeoutExpired:
        return -999, [], "timeout", None, 0
    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")
    started = [int(line.split()[1]) for line in stdout.splitlines() if line.startswith("case ")]
    loaded = [int(line.split()[1]) for line in stdout.splitlines() if line.startswith("loaded ")]
    finished = stdout.rstrip().endswith(f"done {len(batch)}")
    sanitizer = "ERROR: AddressSanitizer" in stderr or "runtime error:" in stderr
    last = started[-1] if started else None
    if finished and not sanitizer and result.returncode == 0:
        return 0, loaded, "", None, len(batch)
    # PHP (CLI) prints its fatal errors on stdout; the sanitizers write to stderr.
    tail = "\n".join(line for line in stdout.splitlines() if not line.startswith(("case ", "loaded ", "rejected ")))
    return result.returncode, loaded, (tail + "\n" + stderr)[-12000:], last, len(started)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--php", default="php")
    parser.add_argument("--loader", type=pathlib.Path, required=True,
                        help="a loader built with --enable-envelock-bcrun-unsafe (TEST ONLY)")
    parser.add_argument("--seconds", type=int, default=300)
    parser.add_argument("--batch", type=int, default=150)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--out", type=pathlib.Path, required=True, help="folder for reproducers and the summary")
    parser.add_argument("--preload", default="", help="sanitizer runtime(s) for LD_PRELOAD of the PHP processes")
    arguments = parser.parse_args()
    if arguments.preload:
        PHP_ENV["LD_PRELOAD"] = arguments.preload

    seed = arguments.seed if arguments.seed is not None else int.from_bytes(os.urandom(4), "big")
    # A seeded PRNG on purpose: a run must be reproducible from the seed it prints (not for secrets).
    rng = random.Random(seed)  # nosec B311
    php = [arguments.php, "-n", "-d", f"extension={arguments.loader.resolve()}", "-d", "memory_limit=1G"]
    probe = subprocess.run([*php, "-r", "echo function_exists('envelock_bc_load_check') ? 'y' : 'n';"],  # nosec B603
                           capture_output=True, text=True, timeout=60, check=False, env=PHP_ENV)
    if probe.stdout.strip() != "y":
        raise SystemExit(f"{arguments.loader} has no envelock_bc_load_check (build it with "
                         f"--enable-envelock-bcrun-unsafe): {probe.stdout}{probe.stderr}")
    arguments.out.mkdir(parents=True, exist_ok=True)
    work = pathlib.Path(tempfile.mkdtemp(prefix="envelock-fuzz-bc-"))
    try:
        seeds = emit_seeds(php, work)
        runner = work / "runner.php"
        runner.write_text(RUNNER, encoding="utf-8")
        # The unmutated seeds must load: otherwise every mutation is rejected for the wrong reason.
        code, loaded, stderr, _last, _ = run_batch(php, runner, list(seeds.values()), work, 120)
        if code != 0 or len(loaded) != len(seeds):
            raise SystemExit(f"the seed images do not load cleanly (rc={code}, loaded {len(loaded)}/{len(seeds)}):\n{stderr}")
        print(f"seed {seed}; {len(seeds)} seed images ({', '.join(f'{k} {len(v)} B' for k, v in seeds.items())}); "
              f"budget {arguments.seconds} s", flush=True)
        # Two protected files that declare the same function or class are an ordinary PHP error: the
        # second load must end in that fatal error ("Cannot redeclare"), and the process must shut down
        # cleanly after it, with half of an image installed (a batch once crashed in zend_hash_release).
        duplicate_failures = []
        for name, image in seeds.items():
            code, _loaded, output, _last, _ran = run_batch(php, runner, [image, image], work, 120)
            if is_fault(code, output):
                duplicate_failures.append(name)
                print(f"FAILURE: loading the {name} image twice rc={code}", flush=True)
                for line in key_lines(output):
                    print(f"    {line}", flush=True)
            else:
                verdict = [line for line in output.splitlines() if "Fatal error" in line][:1]
                print(f"duplicate load of {name}: rc={code} {verdict[0].strip()[:160] if verdict else ''}", flush=True)
        deadline = time.monotonic() + arguments.seconds
        cases = accepted = interactions = 0
        kinds: dict[str, int] = {}
        failures = []
        while time.monotonic() < deadline:
            batch, labels = [], []
            for _ in range(arguments.batch):
                name = rng.choice(list(seeds))
                image, kind = mutate(rng, seeds[name])
                batch.append(image)
                labels.append(f"{name}/{kind}")
                kinds[kind] = kinds.get(kind, 0) + 1
            code, loaded, stderr, last, ran = run_batch(php, runner, batch, work, 600)
            cases += ran
            accepted += len(loaded)
            if code == 0:
                continue
            if last is None:
                raise SystemExit(f"the runner failed before its first case: rc={code}\n{stderr}")
            if not is_fault(code, stderr):
                # A PHP fatal error ends the batch early: typically an earlier image of the batch loaded
                # and declared a class or function that this one declares again. That is PHP refusing a
                # duplicate declaration, not a deserializer fault.
                interactions += 1
                continue
            # Reduce to a reproducer that does not depend on the rest of the batch: the image alone,
            # or else an earlier image that loaded, followed by this one (a crash at shutdown comes
            # from what an accepted image left installed, not from the image that was running).
            reproducer, culprit = [batch[last]], labels[last]
            repro_code, _, repro_out, _, _ = run_batch(php, runner, reproducer, work, 120)
            if not is_fault(repro_code, repro_out):
                for earlier in (i for i in loaded if i < last):
                    pair = [batch[earlier], batch[last]]
                    pair_code, _, pair_out, _, _ = run_batch(php, runner, pair, work, 120)
                    if is_fault(pair_code, pair_out):
                        reproducer, culprit = pair, f"{labels[earlier]} (case {earlier}) then {labels[last]}"
                        repro_code, repro_out = pair_code, pair_out
                        break
                else:
                    culprit = f"{labels[last]} (needs the whole batch: not reduced)"
                    repro_out = stderr
            index = len(failures)
            for n, image in enumerate(reproducer):
                (arguments.out / f"crash-{index}-{n}.bin").write_bytes(image)
            (arguments.out / f"crash-{index}.txt").write_text(
                f"seed {seed}, {culprit}\nbatch rc={code}, reproducer rc={repro_code}\n"
                f"--- batch output ---\n{stderr}\n--- reproducer output ---\n{repro_out}\n", encoding="utf-8")
            lines = key_lines(repro_out)
            failures.append((culprit, code, repro_code, lines[0] if lines else f"rc={repro_code}"))
            print(f"FAILURE {index}: {culprit} batch rc={code} reproducer rc={repro_code}", flush=True)
            for line in lines:
                print(f"    {line}", flush=True)
            if len(failures) >= 25:
                break
        summary = (f"bytecode deserializer fuzz: seed {seed}, {cases} mutated images, {accepted} still loaded, "
                   f"{cases - accepted - len(failures)} rejected, {len(failures)} failures, {interactions} "
                   f"duplicate-declaration interactions between cases (not faults); mutations "
                   + ", ".join(f"{k} {v}" for k, v in sorted(kinds.items())))
        distinct = sorted({first for *_rest, first in failures})
        if distinct:
            summary += "\ndistinct findings:\n" + "\n".join(f"  {line}" for line in distinct)
        if duplicate_failures:
            summary += "\nloading an image twice crashed: " + ", ".join(duplicate_failures)
        print(summary, flush=True)
        (arguments.out / "summary.txt").write_text(summary + "\n", encoding="utf-8")
        return 1 if failures or duplicate_failures else 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
