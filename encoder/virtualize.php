<?php
/**
 * Objective O4: compiler from a marked PHP function to the Envelock mini-VM instruction stream.
 *
 * Reads a JSON payload on STDIN: {"files": {"path": source, ...}, "marked": ["name", ...]}
 * Writes JSON on STDOUT: {"programs": {"name": base64}, "rewritten": {"path": source}, "refused": [...]}
 *
 * This is not a PHP interpreter and does not try to be one: constructs outside the restricted
 * subset below are refused by name. That restriction does NOT guarantee semantic equivalence:
 * differential tests show known observable divergences even inside the subset. The packer quarantines
 * this compiler and permits it only with an explicit unsafe laboratory override.
 *
 * Supported: integer/float/string/true/false/null literals, short arrays, local variables, the
 * arithmetic / comparison / bitwise / logical operators, unary - + ! ~, casts, assignment and
 * compound assignments, if/elseif/else, while, for, blocks, return, and array reads. Function calls
 * and user-defined constants are refused: the compiler cannot yet prove namespace, by-reference
 * and caller-sensitive behavior. Also refused: classes and objects, references, closures, try/catch,
 * foreach, switch, goto, static/global variables, variable variables, heredoc, increment/decrement,
 * and short ternary elision beyond the plain form.
 */

function envelock_fail(string $message): void {
    fwrite(STDERR, "envelock-virtualize: " . $message . "\n");
    exit(3);
}

/* ------------------------------------------------------------------ tokens */

final class VmTokens {
    /** @var array<int, array{0:string,1:string,2:int}> normalised: [kind, text, line] */
    public array $items = [];
    public int $pos = 0;

    public function __construct(string $code) {
        $raw = token_get_all($code, TOKEN_PARSE);
        foreach ($raw as $token) {
            if (is_array($token)) {
                $kind = strtolower(substr(token_name($token[0]), 2));
                /* Whitespace and comments carry no meaning here and the parser is a token-at-a-time
                 * recursive descent with no lexer state of its own, so they go now rather than
                 * being skipped at a dozen call sites. */
                if ($kind === 'whitespace' || $kind === 'comment' || $kind === 'doc_comment') {
                    continue;
                }
                $this->items[] = [$kind, $token[1], $token[2]];
            } else {
                $this->items[] = ['char', $token, 0];
            }
        }
        /* The body is tokenised with a synthetic opening tag so that PHP treats it as code rather
         * than inline HTML; that tag is scaffolding, not part of the function. */
        while ($this->items !== [] && ($this->items[0][0] === 'open_tag'
                || $this->items[0][0] === 'whitespace')) {
            array_shift($this->items);
        }
    }

    public function peek(int $ahead = 0): ?array {
        return $this->items[$this->pos + $ahead] ?? null;
    }

    public function text(int $ahead = 0): string {
        $t = $this->peek($ahead);
        return $t === null ? '' : $t[1];
    }

    public function kind(int $ahead = 0): string {
        $t = $this->peek($ahead);
        return $t === null ? '' : $t[0];
    }

    public function at(string $kind, ?string $text = null): bool {
        $t = $this->peek();
        if ($t === null || $t[0] !== $kind) {
            return false;
        }
        return $text === null || strtolower($t[1]) === strtolower($text);
    }

    public function eat(string $kind, ?string $text = null): array {
        if (!$this->at($kind, $text)) {
            $t = $this->peek();
            envelock_fail(sprintf('expected %s%s but found %s on line %d',
                $kind, $text === null ? '' : " '$text'",
                $t === null ? 'end of input' : "'{$t[1]}'", $t === null ? 0 : $t[2]));
        }
        return $this->items[$this->pos++];
    }

    public function done(): bool {
        return $this->pos >= count($this->items);
    }
}

/* ------------------------------------------------------------------ program */

final class VmProgram {
    /** @var list<array{0:int,1:mixed}> */
    public array $constants = [];
    /** @var array<string,int> */
    public array $constantIndex = [];
    /** @var array<string,int> */
    public array $locals = [];
    public string $code = '';
    /** @var list<int> */
    public array $argLocals = [];

    public function constant(mixed $value): int {
        /* A float is keyed by its exact IEEE-754 bits, never by its text: var_export follows the
         * packer's serialize_precision, with which 0.1 + 0.2 and 0.3 print alike and would share
         * one slot. The bits also keep -0.0 apart from 0.0; a NAN merges only with the same NAN. */
        $key = is_float($value) ? "double\0" . bin2hex(pack('e', $value))
            : gettype($value) . "\0" . (is_string($value) ? $value : var_export($value, true));
        if (isset($this->constantIndex[$key])) {
            return $this->constantIndex[$key];
        }
        $index = count($this->constants);
        if ($index >= 0xFFFF) {
            /* The header stores a u16 COUNT, so the maximum valid index is 65534. */
            envelock_fail('too many constants in one virtualized function');
        }
        $this->constants[] = [$index, $value];
        $this->constantIndex[$key] = $index;
        return $index;
    }

    public function local(string $name): int {
        if (isset($this->locals[$name])) {
            return $this->locals[$name];
        }
        $index = count($this->locals);
        if ($index >= 0xFFFF) {
            envelock_fail('too many locals in one virtualized function');
        }
        $this->locals[$name] = $index;
        return $index;
    }

    public function emit(int $opcode, string $operands = ''): int {
        $offset = strlen($this->code);
        $this->code .= chr($opcode) . $operands;
        return $offset;
    }

    public function here(): int {
        return strlen($this->code);
    }

    /** Offset of the opcode of the jump just emitted. A jump is 1 opcode byte + a 4-byte operand,
     * so it is here() - 5; using - 4 hands patch() the operand instead of the instruction and the
     * displacement lands one byte off, which sends the loop somewhere inside another instruction. */
    public function lastJump(): int {
        return strlen($this->code) - 5;
    }

    /** Rewrites the operand of the jump whose OPCODE sits at $opcodeOffset.
     *
     * The operand starts one byte later, and the displacement is measured from the end of the
     * instruction (where the loader's instruction pointer is after reading it). Writing at
     * $opcodeOffset instead — the mistake this replaced — overwrote the opcode byte itself, so the
     * loader saw opcode 0x00 and reported an instruction it did not know. */
    public function patch(int $opcodeOffset, int $target): void {
        $operandAt = $opcodeOffset + 1;
        $relative = $target - ($opcodeOffset + 5);
        $this->code = substr($this->code, 0, $operandAt)
            . pack('N', $relative & 0xFFFFFFFF) . substr($this->code, $operandAt + 4);
    }

    /** Width of the FETCH_DIM_MIXED instruction at $at, after its opcode byte. */
    private function mixedWidth(int $at): int {
        [, , $width] = $this->mixedLayout($at);
        return $width;
    }

    /** Stack keys and local-container flag of the FETCH_DIM_MIXED instruction at $at. */
    private function mixedStack(int $at): array {
        [$stackKeys, $localContainer] = $this->mixedLayout($at);
        return [$stackKeys, $localContainer];
    }

    /** Walks a FETCH_DIM_MIXED layout: [stackKeys, localContainer, width]. */
    private function mixedLayout(int $at): array {
        $length = strlen($this->code);
        $p = $at + 1;
        if ($p + 2 > $length) envelock_fail('internal VM compiler error: truncated dimension fetch');
        $count = ord($this->code[$p]);
        $flags = ord($this->code[$p + 1]);
        $p += 2;
        if ($count === 0 || ($flags & ~1)) envelock_fail('internal VM compiler error: malformed dimension fetch');
        $local = ($flags & 1) === 1;
        if ($local) $p += 2;
        $stackKeys = 0;
        for ($i = 0; $i < $count; $i++) {
            if ($p >= $length) envelock_fail('internal VM compiler error: truncated dimension fetch');
            if (ord($this->code[$p]) === 0) {
                $stackKeys++;
                $p += 1;
            } else {
                $p += 3;
            }
        }
        if ($p > $length) envelock_fail('internal VM compiler error: truncated dimension fetch');
        return [$stackKeys, $local, $p - $at - 1];
    }

    /** Verify stack depth over all reachable control-flow paths, including nested expressions.
     * The loader has its own runtime checks; this prevents the compiler from knowingly producing
     * a program that overflows on a possible branch. No values or semantic equivalence are inferred. */
    private function validateStack(): void {
        $widths = [1 => 2, 2 => 2, 3 => 2, 4 => 1, 5 => 1, 6 => 4, 7 => 4, 8 => 3,
                   9 => 0, 10 => 0, 11 => 2, 12 => 0, 13 => 0, 14 => 0, 15 => 4,
                   16 => 4, 17 => 4, 18 => 0, 19 => 1, 20 => 3, 22 => 3];
        $length = strlen($this->code);
        $instructions = [];
        for ($at = 0; $at < $length;) {
            $op = ord($this->code[$at]);
            if ($op === 21) {
                $width = $this->mixedWidth($at);
                $instructions[$at] = [$op, $at + 1 + $width];
                $at += 1 + $width;
                continue;
            }
            if (!isset($widths[$op]) || $widths[$op] > $length - $at - 1) {
                envelock_fail('internal VM compiler error: invalid or truncated instruction');
            }
            $next = $at + 1 + $widths[$op];
            $instructions[$at] = [$op, $next];
            $at = $next;
        }
        $depths = [0 => 0];
        $queue = [0];
        for ($head = 0; $head < count($queue); $head++) {
            $at = $queue[$head];
            if (!isset($instructions[$at])) {
                envelock_fail('internal VM compiler error: control flow leaves instruction boundaries');
            }
            [$op, $next] = $instructions[$at];
            $depth = $depths[$at];
            $required = 0;
            $change = 0;
            switch ($op) {
                case 1: case 2: $change = 1; break;                 // push
                case 3: case 7: case 9: case 12: case 15:
                    $required = 1; $change = -1; break;             // pop
                case 4: case 10: $required = 2; $change = -1; break; // binary / index
                case 5: case 16: case 17: $required = 1; break;      // unary / peek
                case 8:
                    $required = ord($this->code[$at + 3]);
                    $change = 1 - $required;
                    break;
                case 11:
                    $required = unpack('n', substr($this->code, $at + 1, 2))[1];
                    $change = 1 - $required;
                    break;
                case 13: $required = 1; $change = 1; break;        // dup
                case 22: break;                                    // INIT_CALL: checks only
                case 18: $required = 2; break;                     // swap
                case 19:                                           // container below n keys
                    $required = ord($this->code[$at + 1]) + 1; $change = -ord($this->code[$at + 1]);
                    break;
                case 20:                                           // local container, n keys
                    $required = ord($this->code[$at + 3]);
                    $change = 1 - $required;
                    break;
                case 21:                                           // container and stack keys, one result
                    [$stackKeys, $localContainer] = $this->mixedStack($at);
                    $required = $stackKeys + ($localContainer ? 0 : 1);
                    $change = 1 - $required;
                    break;
            }
            if ($depth < $required) {
                envelock_fail('internal VM compiler error: possible stack underflow');
            }
            $depth += $change;
            if ($depth > 4096) {
                envelock_fail('this construct is outside the virtualized subset: VM stack limit exceeded');
            }
            if ($op === 9 || $op === 14) continue;                 // return terminates this path
            $successors = [];
            if (in_array($op, [6, 7, 15, 16, 17], true)) {
                $offset = unpack('N', substr($this->code, $at + 1, 4))[1];
                if ($offset >= 0x80000000) $offset -= 0x100000000;
                $successors[] = $next + $offset;
            }
            if ($op !== 6) $successors[] = $next;
            foreach ($successors as $target) {
                if (!isset($instructions[$target])) {
                    envelock_fail('internal VM compiler error: jump or fallthrough outside an instruction');
                }
                if (isset($depths[$target])) {
                    if ($depths[$target] !== $depth) {
                        envelock_fail('internal VM compiler error: inconsistent stack depth at a join');
                    }
                } else {
                    $depths[$target] = $depth;
                    $queue[] = $target;
                }
            }
        }
    }

    public function bytes(): string {
        $this->validateStack();
        /* v2 requires a loader with the corrected operator semantics; a v1 loader rejects it. */
        $out = "ENVVM3" . pack('nn', count($this->constants), count($this->locals));
        foreach ($this->constants as [, $value]) {
            if ($value === null) {
                $out .= chr(0);
            } elseif (is_bool($value)) {
                $out .= chr(1) . chr($value ? 1 : 0);
            } elseif (is_int($value)) {
                $out .= chr(2) . pack('J', $value);
            } elseif (is_float($value)) {
                /* VM format: IEEE-754 little endian. PHP's 'e' is little; uppercase 'E' is big. */
                $out .= chr(3) . pack('e', $value);
            } elseif (is_string($value)) {
                if (strlen($value) > 0xFFFFFF) {
                    envelock_fail('a string constant is too long to virtualize');
                }
                $out .= chr(4) . substr(pack('N', strlen($value)), 1) . $value;
            } else {
                envelock_fail('a constant of type ' . gettype($value) . ' cannot be virtualized');
            }
        }
        return $out . pack('N', strlen($this->code)) . $this->code;
    }
}

/* Operator tables. The numeric ids are shared with the loader, which maps each one onto Zend's own
 * operator function. That delegation alone does not guarantee PHP evaluation order or observable
 * exception/warning equivalence; the VM remains quarantined. */
const VM_BINARY = [
    '+' => 1, '-' => 2, '*' => 3, '/' => 4, '%' => 5, '.' => 6,
    '==' => 7, '!=' => 8, '===' => 9, '!==' => 10,
    '<' => 11, '<=' => 12, '>' => 13, '>=' => 14,
    '&' => 15, '|' => 16, '^' => 17, '<<' => 18, '>>' => 19,
    '&&' => 20, '||' => 21, '**' => 22, '<=>' => 23,
];
const VM_ASSIGN_BINARY = [
    '+=' => 1, '-=' => 2, '*=' => 3, '/=' => 4, '%=' => 5, '.=' => 6,
    '&=' => 15, '|=' => 16, '^=' => 17, '<<=' => 18, '>>=' => 19, '**=' => 22,
];
const VM_UNARY = [
    '-' => 1, '+' => 2, '!' => 3, '~' => 4,
    '(int)' => 5, '(float)' => 6, '(string)' => 7, '(bool)' => 8, '(array)' => 9,
];

/* Precedence climbing. Higher binds tighter; matches PHP for the supported operators. */
const VM_PRECEDENCE = [
    '||' => 1, '&&' => 2, '|' => 3, '^' => 4, '&' => 5,
    '==' => 6, '!=' => 6, '===' => 6, '!==' => 6, '<=>' => 6,
    '<' => 7, '<=' => 7, '>' => 7, '>=' => 7,
    '.' => 8,                                      /* PHP 8: lower than shifts and addition */
    '<<' => 9, '>>' => 9,
    '+' => 10, '-' => 10,
    '*' => 11, '/' => 11, '%' => 11,
    '**' => 13,
];

final class VmCompiler {
    public VmProgram $program;
    public VmTokens $tokens;
    private int $assignmentDepth = 0;
    /* Whether the expression just parsed is a constant that Zend folds at compile time. Zend
     * orders COMMUTATIVE operands by this, so it is tracked during parsing, not guessed from code. */
    private bool $constant = false;
    /* The value of the constant expression just parsed (only meaningful while $constant is true). */
    private mixed $constValue = null;
    /** @var list<string> */
    public array $refused = [];
    /* Calls compile only in files with no namespace and no strict_types: an unqualified name
     * resolves differently in a namespace, and strict_types changes argument coercion. */
    public bool $callsAllowed = false;
    /** @var array<string,true> lower-case names the file imports with `use function` / `use const`
     * (envelock_imports): an unqualified call or true/false/null would resolve to the import. */
    public array $functionImports = [];
    public array $constImports = [];
    /** @var ?Closure(): array<string,true> the pack's own global functions taking a by-reference
     * parameter (envelock_pack_by_ref_functions), computed on first use. */
    public ?Closure $packByRef = null;
    /* Builtins whose result depends on the frame that calls them (not the loader's frame). */
    private const FRAME_FUNCTIONS = ['compact', 'extract', 'func_get_args', 'func_get_arg',
        'func_num_args', 'get_defined_vars', 'get_called_class', 'debug_backtrace',
        'debug_print_backtrace', 'call_user_func', 'call_user_func_array', 'assert'];
    /* Builtins a direct call does not run the way a call through a value does. Zend compiles the
     * first group to opcodes of its own (zend_try_compile_special_func_ex, PHP 8.4 source): those
     * skip the undefined-variable warning (`count($undef)` raises only the TypeError). min and max
     * disagree with the dynamic call: 20 of 81 mixed-scalar pairs for min, and max(2, NAN) gives NAN
     * directly but 2 dynamically. implode(array, string) reports a different argument in its TypeError
     * directly (#1 $separator) than through a value (#2 $array). Refused, not emulated, because the
     * mechanism is not known. */
    private const DIRECT_CALL_DIFFERS = ['array_key_exists', 'array_slice', 'boolval', 'call_user_func',
        'call_user_func_array', 'chr', 'count', 'defined', 'doubleval', 'floatval', 'func_get_args',
        'func_num_args', 'get_called_class', 'get_class', 'gettype', 'in_array', 'intval', 'is_array',
        'is_bool', 'is_double', 'is_float', 'is_int', 'is_integer', 'is_long', 'is_null', 'is_object',
        'is_resource', 'is_scalar', 'is_string', 'ord', 'sizeof', 'sprintf', 'strlen', 'strval',
        'min', 'max', 'implode'];
    /* Reserved words and language constructs that look like calls but are not function calls. */
    private const LANGUAGE_WORDS = ['array', 'list', 'isset', 'unset', 'empty', 'eval', 'exit',
        'die', 'echo', 'print', 'include', 'include_once', 'require', 'require_once', 'function',
        'fn', 'match', 'new', 'clone', 'instanceof', 'yield', 'static', 'self', 'parent', 'global',
        'return', 'if', 'elseif', 'else', 'while', 'for', 'foreach', 'switch', 'case', 'default',
        'break', 'continue', 'do', 'try', 'catch', 'finally', 'throw', 'declare', 'namespace',
        'use', 'const', 'class', 'interface', 'trait', 'enum', 'and', 'or', 'xor', 'goto'];

    public function __construct(VmTokens $tokens) {
        $this->tokens = $tokens;
        $this->program = new VmProgram();
        foreach ($tokens->items as [$kind, $text]) {
            if ($kind === 'variable' && in_array($text, ['$GLOBALS', '$_SERVER', '$_GET', '$_POST',
                    '$_FILES', '$_COOKIE', '$_SESSION', '$_REQUEST', '$_ENV', '$this'], true)) {
                $this->refuse("the non-local variable $text");
            }
        }
    }

    public function refuse(string $what): void {
        $line = $this->tokens->peek()[2] ?? 0;
        envelock_fail("this construct is outside the virtualized subset: $what (line $line)");
    }

    /* ------------------------------------------------------------ statements */

    public function body(): void {
        $this->tokens->eat('char', '{');
        $this->statements();
        $this->tokens->eat('char', '}');
    }

    public function statements(): void {
        while (!$this->tokens->at('char', '}') && !$this->tokens->done()) {
            $this->statement();
        }
    }

    public function statement(): void {
        $kind = $this->tokens->kind();
        $text = $this->tokens->text();
        if ($kind === 'char' && $text === ';') {
            $this->tokens->pos++;
            return;
        }
        if ($kind === 'char' && $text === '{') {
            $this->body();
            return;
        }
        if ($kind === 'if') {
            $this->ifStatement();
            return;
        }
        if ($kind === 'while') {
            $this->whileStatement();
            return;
        }
        if ($kind === 'for') {
            $this->forStatement();
            return;
        }
        if ($kind === 'return') {
            $this->tokens->pos++;
            if ($this->tokens->at('char', ';')) {
                $this->tokens->pos++;
                $this->program->emit(0x0E);                  /* RETURN_NULL */
                return;
            }
            $this->expression();
            $this->tokens->eat('char', ';');
            $this->program->emit(0x09);                      /* RETURN */
            return;
        }
        foreach (['echo', 'print', 'foreach', 'switch', 'try', 'throw', 'goto', 'break',
                  'continue', 'do', 'global', 'static', 'unset', 'isset', 'empty', 'list',
                  'function', 'fn', 'class', 'interface', 'trait', 'enum', 'yield',
                  'include', 'require', 'include_once', 'require_once', 'declare', 'match'] as $no) {
            if ($kind === $no) {
                $this->refuse($no);
            }
        }
        $this->expressionStatement();
    }

    public function ifStatement(): void {
        $this->tokens->eat('if');
        $this->tokens->eat('char', '(');
        $this->expression();
        $this->tokens->eat('char', ')');
        $jumpFalse = $this->program->emit(0x07, pack('N', 0));   /* JMP_FALSE */
        $this->statement();
        $ends = [];
        while ($this->tokens->at('elseif')) {
            $ends[] = $this->program->emit(0x06, pack('N', 0));  /* JMP to end */
            $this->program->patch($jumpFalse, $this->program->here());
            $this->tokens->pos++;
            $this->tokens->eat('char', '(');
            $this->expression();
            $this->tokens->eat('char', ')');
            $jumpFalse = $this->program->emit(0x07, pack('N', 0));
            $this->statement();
        }
        if ($this->tokens->at('else')) {
            $ends[] = $this->program->emit(0x06, pack('N', 0));
            $this->program->patch($jumpFalse, $this->program->here());
            $jumpFalse = null; // already points to else; do not overwrite it with end below
            $this->tokens->pos++;
            $this->statement();
        }
        $end = $this->program->here();
        if ($jumpFalse !== null) $this->program->patch($jumpFalse, $end);
        foreach ($ends as $jump) {
            $this->program->patch($jump, $end);
        }
    }

    public function whileStatement(): void {
        $this->tokens->eat('while');
        $top = $this->program->here();
        $this->tokens->eat('char', '(');
        $this->expression();
        $this->tokens->eat('char', ')');
        $jumpFalse = $this->program->emit(0x07, pack('N', 0));
        $this->statement();
        $this->program->emit(0x06, pack('N', 0));               /* JMP back */
        $this->program->patch($this->program->lastJump(), $top);
        $this->program->patch($jumpFalse, $this->program->here());
    }

    public function forStatement(): void {
        /* Layout:  init | top: cond -> JMP_FALSE end | JMP body | loop: exprs | JMP top
         *          body: <body> | JMP loop | end:
         * The loop expressions run AFTER the body, so they get their own block the body jumps to. */
        $this->tokens->eat('for');
        $this->tokens->eat('char', '(');
        if (!$this->tokens->at('char', ';')) {
            $this->expressionStatementNoSemicolon();
        }
        $this->tokens->eat('char', ';');
        $top = $this->program->here();
        $jumpFalse = 0;
        $hasCondition = !$this->tokens->at('char', ';');
        if ($hasCondition) {
            $this->expression();
            $jumpFalse = $this->program->emit(0x07, pack('N', 0));
        }
        $this->tokens->eat('char', ';');
        $jumpBody = $this->program->emit(0x06, pack('N', 0));
        $loop = $this->program->here();
        while (!$this->tokens->at('char', ')') && !$this->tokens->done()) {
            $this->assignment();
            $this->program->emit(0x0C);
            if ($this->tokens->at('char', ',')) {
                $this->tokens->pos++;
            }
        }
        $this->tokens->eat('char', ')');
        $this->program->emit(0x06, pack('N', 0));
        $this->program->patch($this->program->lastJump(), $top);
        $this->program->patch($jumpBody, $this->program->here());
        $this->statement();
        $this->program->emit(0x06, pack('N', 0));
        $this->program->patch($this->program->lastJump(), $loop);
        if ($hasCondition) {
            $this->program->patch($jumpFalse, $this->program->here());
        }
    }

    public function expressionStatement(): void {
        $this->expressionStatementNoSemicolon();
        $this->tokens->eat('char', ';');
    }

    public function expressionStatementNoSemicolon(): void {
        $this->expression();
        /* An expression statement's value is discarded unless it was an assignment, which leaves
         * the assigned value on the stack. */
        $this->program->emit(0x0C);                            /* POP */
    }

    /* ------------------------------------------------------------ expressions */

    public function expression(): void {
        $this->assignment();
        while ($this->tokens->at('char', ',')) {
            $this->tokens->pos++;
            $this->program->emit(0x0C);                        /* POP the previous value */
            $this->assignment();
        }
    }

    public function assignment(): void {
        $this->assignmentDepth++;
        try {
        /* Only a plain local variable may be assigned to; anything else is refused rather than
         * approximated, because a wrong lvalue silently writes somewhere else. */
        if ($this->tokens->at('variable')) {
            $name = $this->tokens->text();
            $ahead = $this->tokens->peek(1);
            $op = $ahead === null ? '' : $ahead[1];
            if ($op === '=' || isset(VM_ASSIGN_BINARY[$op])) {
                $this->tokens->pos += 2;
                if ($op === '=') {
                    $this->assignment();                       /* right associative */
                } else {
                    /* PHP reads the target of a compound assignment when the operation runs, after
                     * the right side has been evaluated: $a += ($a = 5) uses the new $a. */
                    $target = chr(0x02) . pack('n', $this->program->local($name));
                    $rhsStart = $this->program->here();
                    $this->assignment();
                    $rhsEnd = $this->program->here();
                    if ($this->isTrivialOperand($rhsStart, $rhsEnd)) {
                        /* A constant or a plain local has no side effects: keep the read first. */
                        $this->program->code = substr($this->program->code, 0, $rhsStart) . $target
                            . substr($this->program->code, $rhsStart);
                    } else {
                        $this->program->code .= $target;
                        $this->program->emit(0x12);            /* SWAP: target below the value */
                    }
                    $this->program->emit(0x04, chr(VM_ASSIGN_BINARY[$op]));
                }
                $index = $this->program->local($name);
                /* DUP takes NO operand: the index travels with the STORE_LOCAL that follows.
                 * Emitting one here shifts every following instruction by two bytes, and the
                 * loader then reads operands out of the middle of the code. */
                $this->program->emit(0x0D);
                $this->program->emit(0x03, pack('n', $index));  /* STORE_LOCAL */
                $this->constant = false;
                $this->constValue = null;
                return;
            }
            foreach (['++', '--'] as $no) {
                if ($op === $no) {
                    $this->refuse("'$no'");
                }
            }
        }
        $this->ternary();
        } finally {
            $this->assignmentDepth--;
        }
    }

    public function ternary(): void {
        $this->binary(0);
        if ($this->tokens->at('char', '?')) {
            $this->tokens->pos++;
            $conditionConstant = $this->constant;
            $jumpFalse = $this->program->emit(0x07, pack('N', 0));
            $this->assignment();
            $thenConstant = $this->constant;
            $jumpEnd = $this->program->emit(0x06, pack('N', 0));
            $this->program->patch($jumpFalse, $this->program->here());
            $this->tokens->eat('char', ':');
            $elseStart = $this->program->here();
            $this->assignment();
            /* PHP copies a plain local of the else branch with an operation of its own (QM_ASSIGN). A
             * warning that throws stops right there, so the operation after the ternary never runs. A
             * PUSH_LOCAL alone would leave the exception pending for that operation to replace; DUP is not
             * exempt from the loader's check, so it stops the program at the same point. POP restores the stack. */
            if ($this->isPlainLocal($elseStart, $this->program->here())) {
                $this->program->emit(0x0D);                              /* DUP */
                $this->program->emit(0x0C);                              /* POP */
            }
            /* PHP does not fold a ternary into a constant, even when its condition is one: the result
             * is a temporary. The COMMUTATIVE rule below depends on this, so it is never constant. */
            $this->constant = false;
            $this->constValue = null;
            $this->program->patch($jumpEnd, $this->program->here());
        }
    }

    /** Zend's rank of an operand for a COMMUTATIVE pair (zend_vm_set_opcode_handler swaps the pair when
     * op1_type < op2_type, with IS_CONST=1, IS_TMP_VAR=2, IS_CV=8). A dimension read, a ternary, a cast
     * or a logical operator is a temporary. */
    private function operandRank(bool $constant, int $start, int $end, bool $isCall): int {
        if ($constant) return 1;
        if ($this->isPlainLocal($start, $end)) return 8;
        /* A function call's result is a VAR in Zend (rank 4), not a TMP (rank 2): `f() | ($a + 1)`
         * is not swapped, while `($a += 1) | f()` is. */
        return $isCall ? 4 : 2;
    }

    /* True when the tokens [from, to) are exactly one call `name(...)`, possibly parenthesised. The
     * decision reads the tokens, not the emitted code, so it is independent of code moves. */
    private function isWholeCall(int $from, int $to): bool {
        while ($to - $from >= 2 && $this->tokens->items[$from][0] === 'char' && $this->tokens->items[$from][1] === '('
                && $this->matchingClose($from, $to) === $to - 1) {
            $from++;
            $to--;
        }
        if ($to - $from < 3) return false;
        $name = $this->tokens->items[$from];
        $open = $this->tokens->items[$from + 1] ?? null;
        return $name[0] === 'string' && $open !== null && $open[0] === 'char' && $open[1] === '('
            && $this->matchingClose($from + 1, $to) === $to - 1;
    }

    public function binary(int $minimum): void {
        $leftStart = $this->program->here();
        $leftTokens = $this->tokens->pos;
        $this->unary();
        $leftVar = $this->isWholeCall($leftTokens, $this->tokens->pos);
        $leftConstant = $this->constant;
        $leftValue = $this->constValue;
        while (true) {
            $text = $this->tokens->text();
            $kind = $this->tokens->kind();
            if (!isset(VM_PRECEDENCE[$text]) || VM_PRECEDENCE[$text] < $minimum) {
                $this->constant = $leftConstant;
                $this->constValue = $leftValue;
                return;
            }
            $precedence = VM_PRECEDENCE[$text];
            $opcode = VM_BINARY[$text];
            $this->tokens->pos++;
            /* The left operand of this operator; the result of this operator is never a call. */
            $leftIsVar = $leftVar;
            $leftVar = false;
            if ($opcode === 20 || $opcode === 21) {
                /* Zend's zend_compile_short_circuiting: a constant left operand decides the
                 * result at compile time. A short-circuit result is a constant and the right operand
                 * is not compiled at all; otherwise the result is a constant only when the right one is
                 * constant too. Any other result is a temporary. */
                if ($leftConstant) {
                    $leftTruth = (bool) $leftValue;
                    $shortCircuit = $opcode === 20 ? !$leftTruth : $leftTruth;
                    $rightStart = $this->program->here();
                    $this->binary($precedence + 1);
                    if ($shortCircuit) {
                        $this->program->code = substr($this->program->code, 0, $leftStart)
                            . $this->pushConstant($leftTruth);
                        $leftValue = $leftTruth;
                        continue;
                    }
                    if ($this->constant) {
                        $rightValue = (bool) $this->constValue;
                        $this->program->code = substr($this->program->code, 0, $leftStart)
                            . $this->pushConstant($rightValue);
                        $leftValue = $rightValue;
                        continue;
                    }
                    /* The left constant has no effect: keep only the right operand and its (bool). */
                    $this->program->code = substr($this->program->code, 0, $leftStart)
                        . substr($this->program->code, $rightStart);
                    $this->program->emit(0x05, chr(8));            /* (bool) right */
                    $leftConstant = false;
                    $leftValue = null;
                    continue;
                }
                /* PHP short-circuits && / || AND returns a boolean, not the selected operand.
                 * Cast the left value before the peek jump, and the right only on the path where
                 * it is evaluated. The jump lands after the right cast and leaves one bool. The
                 * result is a temporary, never a constant. */
                $this->program->emit(0x05, chr(8));            /* (bool) left */
                $jump = $this->program->emit($opcode === 20 ? 0x10 : 0x11, pack('N', 0));
                $this->program->emit(0x0C);                    /* discard left on fallthrough */
                $this->binary($precedence + 1);
                $this->program->emit(0x05, chr(8));            /* (bool) right */
                $this->program->patch($jump, $this->program->here());
                $leftConstant = false;
                $leftValue = null;
                continue;
            }
            /* '**' is right associative in PHP; everything else here is left associative. */
            $rightStart = $this->program->here();
            $rightTokens = $this->tokens->pos;
            $this->binary($opcode === 22 ? $precedence : $precedence + 1);
            $rightVar = $this->isWholeCall($rightTokens, $this->tokens->pos);
            $rightEnd = $this->program->here();
            $rightConstant = $this->constant;
            $rightValue = $this->constValue;
            /* PHP's concatenation converts a constant array on the right ("Array to string conversion")
             * before it reads a plain local on the left: an undefined local warns second. Measured with
             * PHP 8.4 for CV-undef, CV-object and CV-int on the left. A plain local has no side effect of its
             * own, so the right operand is converted first and a SWAP restores the operand order. A left
             * operand with effects (a call, a dimension read) keeps its place: those happen first in PHP. */
            if ($text === '.' && !$leftConstant && $rightConstant && is_array($rightValue)
                    && $this->isPlainLocal($leftStart, $rightStart)) {
                $leftCode = substr($this->program->code, $leftStart, $rightStart - $leftStart);
                $rightCode = substr($this->program->code, $rightStart, $rightEnd - $rightStart);
                $this->program->code = substr($this->program->code, 0, $leftStart)
                    . $rightCode . chr(0x05) . chr(VM_UNARY['(string)'])   /* (string) right: the warning */
                    . $leftCode . chr(0x12)                                  /* SWAP: left below right */
                    . chr(0x04) . chr($opcode);                              /* CONCAT */
                $leftConstant = false;
                $leftValue = null;
                $this->constant = false;
                $this->constValue = null;
                continue;
            }
            /* The mirror case: a constant array on the left is converted before a plain local on the right
             * is read (`[1, 2] . $undef` warns "Array to string conversion" first). The conversion is
             * placed where the array is pushed; the right local has no effect until it is read. */
            if ($text === '.' && $leftConstant && is_array($leftValue) && !$rightConstant
                    && $this->isPlainLocal($rightStart, $rightEnd)) {
                $this->program->code = substr($this->program->code, 0, $rightStart) . chr(0x05) . chr(VM_UNARY['(string)'])
                    . substr($this->program->code, $rightStart);
                $rightStart += 2;
                $rightEnd += 2;
                $leftConstant = false;
                $leftValue = null;
            }
            /* A float converted to a string follows the `precision` INI of the PHP that converts it:
             * Zend folds `1.5 . "x"` (or a float compared with a non-numeric string) when the SERVER
             * compiles the file, with the server's setting. Folding it here would freeze the packer's
             * setting into the program, so the operation stays a runtime one (a temporary). */
            $serverFolds = $leftConstant && $rightConstant
                && self::convertsFloatToString($text, $leftValue, $rightValue);
            /* PHP folds a binary operation on two constants when it cannot throw or warn (its
             * zend_try_ct_eval_binary_op). The fold is replaced by one push of the value, so no
             * runtime operation remains. An array result keeps the runtime operation. */
            if ($leftConstant && $rightConstant && !$serverFolds) {
                [$ok, $value] = self::foldBinary($text, $leftValue, $rightValue);
                if ($ok && (is_scalar($value) || $value === null)) {
                    $this->program->code = substr($this->program->code, 0, $leftStart)
                        . $this->pushConstant($value);
                    $leftValue = $value;
                    continue;
                }
                /* An array result stays a constant operation; a failed fold leaves a temporary. */
                $leftConstant = $ok;
                $leftValue = $ok ? $value : null;
            }
            /* Ranks are read from the operands: a folded array is a constant, a failed fold is a
             * temporary (PHP keeps the runtime operation, whose result is a TMP). */
            $rankLeft = $this->operandRank($leftConstant, $leftStart, $rightStart, $leftIsVar);
            $rankRight = $this->operandRank($rightConstant, $rightStart, $rightEnd, $rightVar);
            $commutative = in_array($opcode, [3, 15, 16, 17], true);
            $resultConstant = $leftConstant && $rightConstant && !$serverFolds;
            /* Zend reads a plain local operand when the operation runs, after the right operand has
             * been evaluated: $a + ($a = 5) uses the new $a. */
            if ($this->isPlainLocal($leftStart, $rightStart) && !$this->isTrivialOperand($rightStart, $rightEnd)) {
                $this->relocateLeftAfterRight($leftStart, $rightStart);
            }
            if ($commutative && $rankLeft === 1 && $rankRight > 1) {
                $left = substr($this->program->code, $leftStart, $rightStart - $leftStart);
                $right = substr($this->program->code, $rightStart, $rightEnd - $rightStart);
                $this->program->code = substr_replace($this->program->code, $right . $left,
                    $leftStart, $rightEnd - $leftStart);
            } elseif ($commutative && $rankLeft > 1 && $rankRight > $rankLeft) {
                /* Zend swaps when op1_type < op2_type: TMP<VAR, TMP<CV, VAR<CV. */
                $this->program->emit(0x12);
            }
            $this->program->emit(0x04, chr($opcode));
            $leftConstant = $resultConstant;
            $leftValue = $resultConstant ? $leftValue : null;
        }
    }

    /** Pushes a folded scalar as a constant. */
    private function pushConstant(mixed $value): string {
        $saved = $this->program->code;
        $this->program->code = '';
        $this->program->emit(0x01, pack('n', $this->program->constant($value)));
        $bytes = $this->program->code;
        $this->program->code = $saved;
        return $bytes;
    }

    /** Evaluates a binary operator on two compile-time constants the way PHP would at run time, and
     * reports success only when it raised no warning, deprecation or exception: Zend folds only then. */
    private static function foldBinary(string $op, mixed $left, mixed $right): array {
        return self::evaluateConstant(static fn(): mixed => match ($op) {
            '+' => $left + $right, '-' => $left - $right, '*' => $left * $right,
            '/' => $left / $right, '%' => $left % $right, '.' => $left . $right,
            '==' => $left == $right, '!=' => $left != $right, '===' => $left === $right,
            '!==' => $left !== $right, '<' => $left < $right, '<=' => $left <= $right,
            '>' => $left > $right, '>=' => $left >= $right, '<=>' => $left <=> $right,
            '&' => $left & $right, '|' => $left | $right, '^' => $left ^ $right,
            '<<' => $left << $right, '>>' => $left >> $right, '**' => $left ** $right,
            default => throw new LogicException("no folding for $op"),
        });
    }

    /** True when the operation turns a float operand into a string, whose text depends on the
     * `precision` INI of the PHP that runs it: a concatenation with a float, or a loose comparison
     * of a float with a string (PHP 8 compares a float with a non-numeric string as strings), also
     * inside constant arrays compared element by element. */
    private static function convertsFloatToString(string $op, mixed $left, mixed $right): bool {
        if ($op === '.') {
            return self::holds($left, 'is_float') || self::holds($right, 'is_float');
        }
        if (in_array($op, ['==', '!=', '<', '<=', '>', '>=', '<=>'], true)) {
            return (self::holds($left, 'is_float') || self::holds($right, 'is_float'))
                && (self::holds($left, 'is_string') || self::holds($right, 'is_string'));
        }
        return false;
    }

    /** True when $value, or any element of a (nested) constant array, satisfies $test. */
    private static function holds(mixed $value, callable $test): bool {
        if (is_array($value)) {
            foreach ($value as $element) {
                if (self::holds($element, $test)) return true;
            }
            return false;
        }
        return $test($value);
    }

    /** Unary -, +, ! and ~. PHP folds - and + as a multiplication by -1 or 1. */
    private static function foldUnary(string $op, mixed $value): array {
        return self::evaluateConstant(static fn(): mixed => match ($op) {
            '-' => $value * -1, '+' => $value * 1, '!' => !$value, '~' => ~$value,
            default => throw new LogicException("no folding for $op"),
        });
    }

    /** Runs $compute with every diagnostic turned into an exception. Returns [true, value] or [false, null]. */
    private static function evaluateConstant(callable $compute): array {
        set_error_handler(static function (int $number, string $message): never {
            throw new ErrorException($message, 0, $number);
        });
        try {
            return [true, $compute()];
        } catch (Throwable) {
            return [false, null];
        } finally {
            restore_error_handler();
        }
    }

    /** True when [$start, $end) is exactly one push of a plain local variable. */
    private function isPlainLocal(int $start, int $end): bool {
        return $end - $start === 3 && ord($this->program->code[$start]) === 0x02;
    }

    /** True when [$start, $end) is one push of a constant or a plain local: no side effects and no
     * diagnostics, so its position relative to another operand is unobservable. */
    private function isTrivialOperand(int $start, int $end): bool {
        return $end - $start === 3 && in_array(ord($this->program->code[$start]), [0x01, 0x02], true);
    }

    /** Moves the plain local at [$leftStart, $rightStart) after the block that follows it and swaps
     * the two values, so that the read happens when the operation runs. Relative jumps inside the
     * moved block stay valid, and a jump that targeted the end of the block now reaches the read,
     * which is the next instruction in the new layout. */
    private function relocateLeftAfterRight(int $leftStart, int $rightStart): void {
        $code = $this->program->code;
        $left = substr($code, $leftStart, $rightStart - $leftStart);
        $right = substr($code, $rightStart);
        $this->program->code = substr($code, 0, $leftStart) . $right . $left . chr(0x12);
    }

    public function unary(): void {
        $kind = $this->tokens->kind();
        $text = $this->tokens->text();
        if ($kind === 'char' && isset(VM_UNARY[$text]) && $text !== '(int)') {
            $this->tokens->pos++;
            if ($text === '&' || $text === '@') {
                $this->refuse("'$text'");
            }
            /* Exponentiation binds more tightly than a prefix operator in PHP: -2 ** 2 is -4. */
            $operandStart = $this->program->here();
            $this->binary(VM_PRECEDENCE['**']);
            $operandConstant = $this->constant;
            $operandValue = $this->constValue;
            /* PHP folds a prefix operator on a constant when it cannot throw or warn, so no operation
             * runs for it (zend_try_ct_eval_unary_pm and zend_try_ct_eval_unary_op). */
            if ($operandConstant && in_array($text, ['-', '+', '!', '~'], true)) {
                [$ok, $value] = self::foldUnary($text, $operandValue);
                if ($ok && (is_scalar($value) || $value === null)) {
                    $this->program->code = substr($this->program->code, 0, $operandStart)
                        . $this->pushConstant($value);
                    $this->constant = true;
                    $this->constValue = $value;
                    return;
                }
                if ($ok) {
                    $this->program->emit(0x05, chr(VM_UNARY[$text]));
                    $this->constant = true;
                    $this->constValue = $value;
                    return;
                }
            }
            $this->program->emit(0x05, chr(VM_UNARY[$text]));
            $this->constant = false;
            $this->constValue = null;
            return;
        }
        if ($kind === 'int_cast' || $kind === 'double_cast' || $kind === 'string_cast'
                || $kind === 'bool_cast' || $kind === 'array_cast' || $kind === 'object_cast'
                || $kind === 'unset_cast') {
            if ($kind === 'object_cast' || $kind === 'unset_cast') {
                $this->refuse("($kind)");
            }
            $map = ['int_cast' => 5, 'double_cast' => 6, 'string_cast' => 7,
                    'bool_cast' => 8, 'array_cast' => 9];
            $this->tokens->pos++;
            $this->binary(VM_PRECEDENCE['**']);
            $this->program->emit(0x05, chr($map[$kind]));
            $this->constant = false;
            $this->constValue = null;
            return;
        }
        if ($kind === 'inc' || $kind === 'dec') {
            $this->refuse("'$text'");
        }
        $this->postfix();
    }

    /** Index of the bracket that closes the one opened at $open, or null when it is not closed
     * before $end. Only ( [ and their closers are counted: the token stream is already valid PHP. */
    private function matchingClose(int $open, int $end): ?int {
        $depth = 0;
        for ($i = $open; $i < $end; $i++) {
            $item = $this->tokens->items[$i] ?? null;
            if ($item === null || $item[0] !== 'char') continue;
            if ($item[1] === '(' || $item[1] === '[') $depth++;
            elseif ($item[1] === ')' || $item[1] === ']') {
                $depth--;
                if ($depth === 0) return $i;
            }
        }
        return null;
    }

    /** Index just after one primary that starts at $i, or null when the token is not a plain primary
     * (a variable, a literal, true/false/null, a parenthesised expression or an array literal). */
    private function primaryEnd(int $i, int $end): ?int {
        $item = $this->tokens->items[$i] ?? null;
        if ($item === null || $i >= $end) return null;
        [$kind, $text] = $item;
        if ($kind === 'variable' || $kind === 'lnumber' || $kind === 'dnumber'
                || $kind === 'constant_encapsed_string' || $kind === 'quoted_string') {
            return $i + 1;
        }
        if ($kind === 'string' && in_array(strtolower($text), ['true', 'false', 'null'], true)) {
            return $i + 1;
        }
        if ($kind === 'char' && ($text === '(' || $text === '[')) {
            $close = $this->matchingClose($i, $end);
            return $close === null ? null : $close + 1;
        }
        return null;
    }

    /** Zend compiles a parenthesised dimension chain like ((B)[K1])[K2] as the same AST as B[K1][K2]:
     * keys of all levels are evaluated before the fetches, and the parentheses have no runtime effect.
     * While the parenthesised group is exactly a primary followed only by [..] groups, and another [
     * follows the group, its parentheses are removed so that postfix() sees one chain. Nested groups
     * such as (((B)[K1])[K2])[K3] are removed one level at a time. Anything else is left alone. */
    private function flattenParenthesizedChain(): void {
        while ($this->flattenOneParenthesizedChain()) {
        }
    }

    private function flattenOneParenthesizedChain(): bool {
        if (!$this->tokens->at('char', '(')) return false;
        $open = $this->tokens->pos;
        $close = $this->matchingClose($open, count($this->tokens->items));
        if ($close === null) return false;
        $after = $this->tokens->items[$close + 1] ?? null;
        if ($after === null || $after[0] !== 'char' || $after[1] !== '[') return false;
        $i = $this->primaryEnd($open + 1, $close);
        if ($i === null) return false;
        while ($i < $close) {
            $item = $this->tokens->items[$i];
            if ($item[0] !== 'char' || $item[1] !== '[') return false;
            $end = $this->matchingClose($i, $close);
            if ($end === null) return false;
            $i = $end + 1;
        }
        array_splice($this->tokens->items, $close, 1);
        array_splice($this->tokens->items, $open, 1);
        return true;
    }

    public function postfix(): void {
        $this->flattenParenthesizedChain();
        $baseStart = $this->program->here();
        $this->primary();
        $baseEnd = $this->program->here();
        $constant = $this->constant;
        $constValue = $this->constValue;
        $dimensions = 0;
        $firstKeyEnd = $baseEnd;
        $keyRanges = [];
        while (true) {
            if ($this->tokens->at('char', '[')) {
                $this->tokens->pos++;
                if ($this->tokens->at('char', ']')) {
                    $this->refuse('array append []');
                }
                /* Keys are only compiled here; the fetches follow them, as in Zend's delayed
                 * compilation of dimensions. */
                $keyStart = $this->program->here();
                $this->expression();
                $keyRanges[] = [$keyStart, $this->program->here()];
                $constant = $constant && $this->constant;
                $this->tokens->eat('char', ']');
                $dimensions++;
                if ($dimensions === 1) $firstKeyEnd = $this->program->here();
                if ($dimensions > 255) $this->refuse('a dimension chain longer than 255 keys');
                continue;
            }
            if ($this->tokens->at('object_operator') || $this->tokens->at('double_colon')
                    || $this->tokens->at('nullsafe_object_operator')) {
                $this->refuse('object or static member access');
            }
            break;
        }
        /* PHP does not fold a dimension fetch, even on a constant base and key: "abc"[0] and
         * ["x"][0] behave as temporaries in TypeError order (measured with PHP 8.4). */
        $this->constant = $dimensions === 0 && $constant;
        $this->constValue = $this->constant ? $constValue : null;
        if ($dimensions === 0) return;
        $code = $this->program->code;
        $base = substr($code, $baseStart, $baseEnd - $baseStart);
        $keys = substr($code, $baseEnd);
        $prefix = substr($code, 0, $baseStart);
        $baseIsLocal = $baseEnd - $baseStart === 3 && ord($base[0]) === 0x02;
        /* A plain local with one trivial key keeps the local first, as before: the warning for an
         * undefined local precedes the key's own warning, because the key is a constant or a plain
         * local read. Every other chain reads its keys first. */
        $hasLocalKey = false;
        foreach ($keyRanges as [$keyFrom, $keyTo]) {
            $hasLocalKey = $hasLocalKey || $this->isPlainLocal($keyFrom, $keyTo);
        }
        if ($dimensions === 1 && (!$baseIsLocal || $this->isTrivialOperand($baseEnd, $firstKeyEnd))) {
            $this->program->code = $prefix . $base . $keys . chr(0x0A);     /* FETCH_DIM_R */
        } elseif ($dimensions > 1 && $hasLocalKey) {
            /* A plain local key is read at its own fetch, after the fetch before it, as Zend's CV
             * operands are. Keys that are not locals are computed in order, before the fetches. */
            $stackKeys = '';
            $descriptors = '';
            foreach ($keyRanges as [$keyFrom, $keyTo]) {
                if ($this->isPlainLocal($keyFrom, $keyTo)) {
                    $descriptors .= chr(1) . substr($code, $keyFrom + 1, 2);
                } else {
                    $stackKeys .= substr($code, $keyFrom, $keyTo - $keyFrom);
                    $descriptors .= chr(0);
                }
            }
            $container = $baseIsLocal ? substr($base, 1, 2) : $base;
            $this->program->code = $prefix . ($baseIsLocal ? '' : $base) . $stackKeys
                . chr(0x15) . chr($dimensions) . chr($baseIsLocal ? 1 : 0)
                . ($baseIsLocal ? $container : '') . $descriptors;
        } elseif ($baseIsLocal) {
            $index = unpack('n', substr($base, 1, 2))[1];
            $this->program->code = $prefix . $keys . chr(0x14) . pack('n', $index) . chr($dimensions);
        } else {
            $this->program->code = $prefix . $base . $keys . chr(0x13) . chr($dimensions);
        }
    }

    /* Number of top-level arguments of the call whose name is at pos, counted before parsing so that
     * INIT_CALL can carry argc ahead of the argument code. A trailing comma makes the count disagree
     * with the parser's, and the caller then refuses. */
    private function callArgumentCount(): int {
        $depth = 0;
        $commas = 0;
        $any = false;
        for ($i = $this->tokens->pos + 2; ; $i++) {
            $item = $this->tokens->items[$i] ?? null;
            if ($item === null) {
                $this->refuse('an unterminated function call');
            }
            [$kind, $text] = $item;
            if ($kind === 'char' && ($text === '(' || $text === '[' || $text === '{')) {
                $depth++;
            } elseif ($kind === 'char' && ($text === ')' || $text === ']' || $text === '}')) {
                if ($depth === 0) {
                    return $any ? $commas + 1 : 0;
                }
                $depth--;
            } elseif ($kind === 'char' && $text === ',' && $depth === 0) {
                $commas++;
            }
            $any = true;
        }
    }

    /* A call `name(args)`: INIT_CALL first (existence, frame and by-reference checks, before any
     * argument runs, as PHP's INIT_FCALL), then the arguments left to right, then CALL. Named,
     * spread and by-reference arguments never reach here: the parser refuses ':' and '...', and the
     * by-reference check below refuses builtins that take a reference. */
    private function functionCall(): void {
        $name = $this->tokens->text(0);
        $lower = strtolower($name);
        if (!$this->callsAllowed) {
            $this->refuse("a function call to '$name' in a namespaced or strict_types file");
        }
        if (isset($this->functionImports[$lower])) {
            $this->refuse("a call to '$name', which the file imports with `use function` (the VM would call the global function)");
        }
        if (in_array($lower, self::LANGUAGE_WORDS, true)) {
            $this->refuse("the language construct '$name'");
        }
        if (in_array($lower, self::FRAME_FUNCTIONS, true)) {
            $this->refuse("the frame-dependent function '$name'");
        }
        if (in_array($lower, self::DIRECT_CALL_DIFFERS, true)) {
            $this->refuse("'$name' compares differently when called directly (measured, not emulated)");
        }
        $argc = $this->callArgumentCount();
        if ($argc > 64) {
            $this->refuse("a call to '$name' with more than 64 arguments");
        }
        $reflection = function_exists($lower) ? new ReflectionFunction($lower) : null;
        if ($reflection !== null && $reflection->isInternal()) {
            foreach ($reflection->getParameters() as $parameter) {
                if ($parameter->isPassedByReference()) {
                    $this->refuse("'$name' takes a by-reference parameter");
                }
            }
            if (!$reflection->isVariadic() && $argc > $reflection->getNumberOfParameters()) {
                $this->refuse("'$name' called with more arguments than it accepts");
            }
        } elseif ($this->packByRef !== null && isset(($this->packByRef)()[$lower])) {
            /* A user function: the loader can only pass values, so a by-reference parameter of a
             * function the pack declares would fail on every call. Unknown ones are checked by the
             * loader at INIT_CALL. */
            $this->refuse("'$name', declared in the pack, takes a by-reference parameter");
        }
        $this->tokens->pos += 2;
        $this->program->emit(0x16, pack('n', $this->program->constant($name)) . chr($argc));  /* INIT_CALL */
        $count = 0;
        while (!$this->tokens->at('char', ')') && !$this->tokens->done()) {
            $this->assignment();
            $count++;
            if ($this->tokens->at('char', ',')) {
                $this->tokens->pos++;
            } else {
                break;
            }
        }
        $this->tokens->eat('char', ')');
        if ($count !== $argc) {
            $this->refuse("an argument list of '$name' the compiler does not follow");
        }
        $this->program->emit(0x08, pack('n', $this->program->constant($name)) . chr($count));  /* CALL */
        $this->constant = false;
        $this->constValue = null;
    }

    public function primary(): void {
        $this->constant = false;
        $this->constValue = null;
        $kind = $this->tokens->kind();
        $text = $this->tokens->text();
        if ($kind === 'lnumber' || $kind === 'dnumber' || $kind === 'constant_encapsed_string') {
            /* Evaluate exactly ONE token already identified by token_get_all(TOKEN_PARSE), never a
             * user expression. These tokens contain only a numeric or non-interpolated quoted
             * literal. Let PHP decode octal, separators, binary-string prefixes and escape rules;
             * hand-written conversions silently changed both values and types. */
            $this->tokens->pos++;
            try { $value = eval('return ' . $text . ';'); }
            catch (Throwable $e) { $this->refuse('an invalid literal'); }
            if (!(is_int($value) || is_float($value) || is_string($value))) {
                $this->refuse('a literal whose type is unsupported');
            }
            $this->program->emit(0x01, pack('n', $this->program->constant($value)));
            $this->constant = true;
            $this->constValue = $value;
            return;
        }
        if ($kind === 'encapsed_and_whitespace' || $kind === 'start_heredoc'
                || ($kind === 'char' && $text === '"')) {
            $this->refuse('an interpolated string');
        }
        if ($kind === 'constant_string' || $kind === 'inline_html') {
            $this->refuse($kind);
        }
        if ($kind === 'char' && ($text === "'" || $text === '"')) {
            /* A literal quoted string is a single quoted-string token in PHP 8; reaching here means
             * the tokeniser split it, which this compiler does not try to reassemble. */
            $this->refuse('a string literal this tokeniser split');
        }
        if ($kind === 'quoted_string') {
            $this->tokens->pos++;
            $this->program->emit(0x01, pack('n', $this->program->constant($text)));
            $this->constant = true;
            $this->constValue = $text;
            return;
        }
        if ($kind === 'string') {
            $word = strtolower($text);
            if (in_array($word, ['true', 'false', 'null'], true)) {
                if (isset($this->constImports[$word])) {
                    $this->refuse("'$text', which the file imports with `use const`");
                }
                $this->tokens->pos++;
                $value = $word === 'true' ? true : ($word === 'false' ? false : null);
                $this->program->emit(0x01, pack('n', $this->program->constant($value)));
                $this->constant = true;
                $this->constValue = $value;
                return;
            }
            if ($this->tokens->kind(1) === 'char' && $this->tokens->text(1) === '(') {
                $this->functionCall();
                return;
            }
            $this->refuse("a reference to the constant or function '$text' without a call");
        }
        if ($kind === 'variable') {
            $this->tokens->pos++;
            $this->program->emit(0x02, pack('n', $this->program->local($text)));
            return;
        }
        if ($kind === 'name') $this->refuse('a bare name');
        if (in_array($kind, ['array', 'open_square_bracket'], true)
                || ($kind === 'char' && $text === '[')) {
            $this->tokens->pos++;
            $count = 0;
            /* PHP folds an array literal of constants into one constant array. */
            $allConstant = true;
            $elementValues = [];
            while (!$this->tokens->at('char', ']') && !$this->tokens->done()) {
                if ($this->tokens->at('double_arrow')) {
                    $this->refuse('an array with keys');
                }
                $this->assignment();
                $allConstant = $allConstant && $this->constant;
                $elementValues[] = $this->constValue;
                $count++;
                /* The interpreter's operand stack is bounded at 4096. A single larger literal
                 * cannot succeed even when it begins with an empty stack. */
                if ($count > 4096) $this->refuse('an array larger than the VM stack');
                if ($this->tokens->at('char', ',')) {
                    $this->tokens->pos++;
                }
                if ($this->tokens->at('double_arrow')) {
                    $this->refuse('an array with keys');
                }
            }
            $this->tokens->eat('char', ']');
            $this->program->emit(0x0B, pack('n', $count));      /* ARRAY n */
            $this->constant = $allConstant;
            $this->constValue = $allConstant ? $elementValues : null;
            return;
        }
        if ($kind === 'char' && $text === '(') {
            $this->tokens->pos++;
            $this->expression();
            $this->tokens->eat('char', ')');
            return;
        }
        if (in_array($kind, ['name_qualified', 'name_fully_qualified', 'name_relative'], true)) {
            $this->refuse('a qualified name or function call');
        }
        if ($kind === 'array' && strtolower($text) === 'array') {
            $this->refuse('the array() syntax');
        }
        $this->refuse("the token '$text' ($kind)");
    }
}

/* ------------------------------------------------------- function extraction */

/* The names a file imports with `use function` and `use const`, in every form (plain, aliased,
 * several per statement, `use X\{function a, const B}` and `use function X\{a, b}`), as
 * ['function' => [lower-case alias => true], 'const' => [lower-case alias => true]]. In a file
 * without a namespace an unqualified call resolves to an imported function before the global one
 * (`use function Lib\shout as strtoupper;` makes strtoupper() call Lib\shout), and an imported
 * constant can even shadow true/false/null. The VM resolves names globally, so these are refused. */
function envelock_imports(array $nodes): array {
    $imports = ['function' => [], 'const' => []];
    $kinds = [PhpParser\Node\Stmt\Use_::TYPE_FUNCTION => 'function',
              PhpParser\Node\Stmt\Use_::TYPE_CONSTANT => 'const'];
    $statements = [];
    foreach ($nodes as $node) {
        /* `use` is a top-level statement, also inside `namespace X { }` blocks. */
        if ($node instanceof PhpParser\Node\Stmt\Namespace_) {
            array_push($statements, ...($node->stmts ?? []));
        } else {
            $statements[] = $node;
        }
    }
    foreach ($statements as $node) {
        if (!$node instanceof PhpParser\Node\Stmt\Use_ && !$node instanceof PhpParser\Node\Stmt\GroupUse) {
            continue;
        }
        foreach ($node->uses as $use) {
            /* A mixed group use types each element; otherwise the statement carries the type. */
            $type = $use->type !== PhpParser\Node\Stmt\Use_::TYPE_UNKNOWN ? $use->type : $node->type;
            if (isset($kinds[$type])) {
                $imports[$kinds[$type]][strtolower($use->getAlias()->toString())] = true;
            }
        }
    }
    return $imports;
}

/* The global functions the pack itself declares, as [lower-case name => true] for those taking a
 * parameter by reference (variadic by-reference included). A call from the VM can only pass values,
 * so such a call always fails at run time: it is refused at compile time instead. Functions are
 * collected wherever they are declared (top level, inside `if (!function_exists(...))`, inside other
 * functions) in files or `namespace { }` blocks without a namespace name; a named namespace declares
 * namespaced functions, which an unqualified global call never reaches. Built lazily, on the first
 * call to a function the packer's PHP does not know, and only from files that can declare one. */
function envelock_pack_by_ref_functions(array $files): array {
    $parser = (new PhpParser\ParserFactory)->createForNewestSupportedVersion();
    $finder = new PhpParser\NodeFinder();
    $byRef = [];
    $ampersand = defined('T_AMPERSAND_FOLLOWED_BY_VAR_OR_VARARG') ? T_AMPERSAND_FOLLOWED_BY_VAR_OR_VARARG : null;
    foreach ($files as $path => $source) {
        if (!is_string($source) || stripos($source, 'function') === false || strpos($source, '&') === false) {
            continue;
        }
        if ($ampersand !== null) {
            $tokens = @token_get_all($source);
            $hasByRef = false;
            foreach ($tokens as $token) {
                if (is_array($token) && $token[0] === $ampersand) { $hasByRef = true; break; }
            }
            if (!$hasByRef) continue;
        }
        try { $nodes = $parser->parse($source) ?? []; }
        catch (Throwable) { continue; }         /* not PHP the packer can read: nothing to learn */
        $scopes = [];
        $global = [];
        foreach ($nodes as $node) {
            if ($node instanceof PhpParser\Node\Stmt\Namespace_) {
                if ($node->name === null) $scopes[] = $node->stmts ?? [];
            } else {
                $global[] = $node;
            }
        }
        $scopes[] = $global;
        foreach ($scopes as $stmts) {
            foreach ($finder->findInstanceOf($stmts, PhpParser\Node\Stmt\Function_::class) as $function) {
                foreach ($function->params as $parameter) {
                    if ($parameter->byRef) {
                        $byRef[strtolower($function->name->toString())] = true;
                        break;
                    }
                }
            }
        }
    }
    return $byRef;
}

/* Locate actual top-level global declarations, not textual matches in comments, strings, classes,
 * namespaces or conditional bodies. The AST provides byte offsets; the tokenizer supplies the
 * real opening brace without being fooled by braces in comments or literals. */
function envelock_discover(array $files, array $marked): array {
    $lib = dirname(__DIR__) . '/third_party/php-parser/lib';
    if (!is_dir($lib . '/PhpParser')) envelock_fail('the vendored PHP parser is missing');
    spl_autoload_register(function ($class) use ($lib) {
        if (strncmp($class, 'PhpParser\\', 10) !== 0) return;
        $file = $lib . '/' . str_replace('\\', '/', $class) . '.php';
        if (is_file($file)) require $file;
    });
    $parser = (new PhpParser\ParserFactory)->createForNewestSupportedVersion();
    $requested = [];
    foreach ($marked as $name) {
        if (!is_string($name) || !preg_match('/^[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*$/D', $name)) {
            envelock_fail('a marked name is not an unqualified function identifier');
        }
        $key = strtolower($name);                     /* PHP folds ASCII function names */
        if (isset($requested[$key])) envelock_fail("marked function '$name' is duplicated");
        $requested[$key] = $name;
    }
    $found = [];
    $perFile = [];
    foreach ($files as $path => $source) {
        $raw = token_get_all($source);
        $candidate = false;
        foreach ($raw as $i => $token) {
            if (!is_array($token) || $token[0] !== T_FUNCTION) continue;
            $j = $i + 1;
            while (isset($raw[$j])) {
                $part = $raw[$j];
                if (is_array($part) && in_array($part[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    $j++; continue;
                }
                $text = is_array($part) ? $part[1] : $part;
                if ($text === '&') { $j++; continue; }
                if (is_array($part) && $part[0] === T_STRING && isset($requested[strtolower($text)])) {
                    $candidate = true;
                }
                break;
            }
            if ($candidate) break;
        }
        if (!$candidate) continue;
        try { $nodes = $parser->parse($source); }
        catch (Throwable $error) { envelock_fail("cannot parse '$path': " . $error->getMessage()); }
        $offsets = [];
        $offset = 0;
        foreach ($raw as $part) {
            $text = is_array($part) ? $part[1] : $part;
            if (!is_array($part) && $text === '{') $offsets[] = $offset;
            $offset += strlen($text);
        }
        $imports = envelock_imports($nodes ?? []);
        foreach ($nodes ?? [] as $node) {
            if (!$node instanceof PhpParser\Node\Stmt\Function_) continue;
            $key = strtolower($node->name->toString());
            if (!isset($requested[$key])) continue;
            $name = $requested[$key];
            if (isset($found[$key])) envelock_fail("marked function '$name' is defined more than once");
            if ($node->byRef) envelock_fail("'$name' returns by reference, outside the virtualized subset");
            if ($node->returnType instanceof PhpParser\Node\Identifier
                    && in_array(strtolower($node->returnType->toString()), ['void', 'never'], true)) {
                envelock_fail("'$name' has a void/never return type, outside the virtualized subset");
            }
            foreach ($node->params as $parameter) {
                if ($parameter->byRef || $parameter->variadic || $parameter->default !== null
                        || !$parameter->var instanceof PhpParser\Node\Expr\Variable
                        || !is_string($parameter->var->name)) {
                    envelock_fail("'$name' has a parameter form outside the virtualized subset");
                }
            }
            $anchor = $node->returnType ? $node->returnType->getEndFilePos() + 1
                : ($node->params ? end($node->params)->getEndFilePos() + 1 : $node->name->getEndFilePos() + 1);
            $body = null;
            foreach ($offsets as $pos) {
                if ($pos >= $anchor && $pos < $node->getEndFilePos()) { $body = $pos; break; }
            }
            $end = $node->getEndFilePos();
            if ($body === null || $end < $body || substr($source, $end, 1) !== '}') {
                envelock_fail("cannot identify the body of '$name' safely");
            }
            $found[$key] = $path;
            $perFile[$path][$name] = ['node' => $node, 'body' => $body, 'end' => $end,
                                      'imports' => $imports];
        }
    }
    foreach ($requested as $key => $name) {
        if (!isset($found[$key])) {
            envelock_fail("marked function '$name' was not found as a top-level global function");
        }
    }
    return $perFile;
}

function envelock_extract(string $source, array $targets, ?Closure $packByRef = null): array {
    $programs = [];
    $spans = [];
    foreach ($targets as $name => $target) {
        $node = $target['node'];
        $body = $target['body'];
        $end = $target['end'];
        $bodySource = substr($source, $body, $end - $body + 1);
        $tokens = new VmTokens("<?php " . $bodySource);
        $compiler = new VmCompiler($tokens);
        $compiler->callsAllowed = !preg_match('/\b(namespace|strict_types)\b/i', $source);
        $compiler->functionImports = $target['imports']['function'] ?? [];
        $compiler->constImports = $target['imports']['const'] ?? [];
        $compiler->packByRef = $packByRef;
        $compiler->program->constant('__envelock_self');
        foreach ($node->params as $parameter) {
            $compiler->program->local('$' . $parameter->var->name);
        }
        /* v2 reserves constant 1+i for local i's spelling. This lets the loader reproduce PHP's
         * undefined-variable warning, including its name, instead of quietly treating it as null.
         * Parameters must stay first because func_get_args() is positional. */
        foreach ($tokens->items as [$kind, $text]) {
            if ($kind === 'variable') $compiler->program->local($text);
        }
        foreach (array_keys($compiler->program->locals) as $local) {
            $compiler->program->constant($local);
        }
        $compiler->body();
        $compiler->program->emit(0x0E);                        /* implicit RETURN_NULL */
        $programs[$name] = base64_encode($compiler->program->bytes());
        $spans[$name] = [$body, $end];
    }
    return ['programs' => $programs, 'spans' => $spans];
}

/* ------------------------------------------------------------------ rewrite */

/* Replace each marked body with a single call that hands the program to the loader. Everything the
 * function computed is gone from the source and from the opcodes PHP generates for it: what PHP
 * compiles now is one function call. The signature is left alone; default, reference and variadic
 * parameters are refused above. The v2 entry point makes an obsolete loader fail rather than run
 * the corrected program with its old, incorrect operator semantics. */
function envelock_rewrite(string $source, array $marked, array $programs, array $spans,
                          array $paramCounts): string {
    /* Splice from the end backwards: every replacement changes the length, and working backwards
     * keeps the offsets of the functions not yet processed valid. */
    $order = $marked;
    usort($order, function ($a, $b) use ($spans) { return $spans[$b][0] <=> $spans[$a][0]; });
    foreach ($order as $name) {
        [$body, $end] = $spans[$name];
        /* Pass ONLY the declared parameters, never the raw \func_get_args(): PHP accepts extra
         * positional arguments on any call ("checkAdmin('guest', 1)"), and an unfiltered
         * func_get_args() would copy them straight into the function's private locals in the loader,
         * letting the caller seed variables the body only assigns conditionally (ENV-2026-26). The
         * closed slice [0, declared-param-count) drops anything beyond the signature. */
        $n = $paramCounts[$name] ?? 0;
        $args = $n === 0 ? "[]" : "\\array_slice(\\func_get_args(), 0, $n)";
        /* Preserve the line count: the original multi-line body is replaced by a one-line call, so
         * re-emit the same number of newlines inside the block, or __LINE__ and stack traces for the
         * rest of the file would shift (ENV-2026-26). */
        $newlines = substr_count(substr($source, $body, $end - $body + 1), "\n");
        $call = "{ return \\__envelock_vm_v2('" . $programs[$name] . "', $args);"
              . str_repeat("\n", $newlines) . "}";
        $source = substr($source, 0, $body) . $call . substr($source, $end + 1);
    }
    return $source;
}

/* ---------------------------------------------------------------------- main */

$payload = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
/* Sources travel base64, like every other pass in the packer: a PHP file is bytes, not UTF-8, and
 * a literal that is not valid UTF-8 would be replaced by json_encode on the way back out. */
$files = [];
foreach (($payload['files'] ?? []) as $path => $source) {
    $files[$path] = base64_decode($source, true);
}
$marked = $payload['marked'] ?? [];
$rewrite = (bool) ($payload['rewrite'] ?? false);

$perFile = envelock_discover($files, $marked);
/* Unmarked PHP files must survive the pass unchanged. Dropping them would produce a successfully
 * published but incomplete package whenever the source tree has more than one file. */
$out = $files;
$programs = [];
/* Every file of the pack is here, so calls to the pack's own by-reference functions are refused at
 * compile time; the files are parsed for that only if a marked function calls a user function. */
$packByRefFunctions = null;
$packByRef = static function () use (&$packByRefFunctions, $files): array {
    return $packByRefFunctions ??= envelock_pack_by_ref_functions($files);
};
foreach ($perFile as $path => $targets) {
    $extracted = envelock_extract($files[$path], $targets, $packByRef);
    $programs += $extracted['programs'];
    $paramCounts = [];
    foreach ($targets as $nm => $tg) { $paramCounts[$nm] = count($tg['node']->params); }
    $out[$path] = $rewrite
        ? envelock_rewrite($files[$path], array_keys($targets), $extracted['programs'],
                           $extracted['spans'], $paramCounts)
        : $files[$path];
}

$encoded = [];
foreach ($out as $path => $source) {
    $encoded[$path] = base64_encode($source);
}
echo json_encode(['programs' => $programs, 'files' => $encoded], JSON_THROW_ON_ERROR);
