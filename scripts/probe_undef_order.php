<?php
// Records the ordered event sequence (warnings, deprecations, and the final value or exception)
// the real PHP engine produces for one operand that is an undefined local variable. The error
// handler does not throw, so the full order is visible. Used to design the VM's deferred
// undefined-variable semantics; it is an oracle for measurement, not a runtime component.
$log = [];
set_error_handler(function ($no, $str) use (&$log) { $log[] = "W[$no]:$str"; return true; });
$ops = ['+', '-', '*', '/', '%', '.', '&', '|', '^', '<<', '>>', '<', '==', '<=>'];
$others = ['0' => 0, '1' => 1, 'x' => 'x', 'arr' => [1], 'null' => null, '-1' => -1, '1.5' => 1.5];
foreach ($ops as $op) {
    foreach (['L', 'R'] as $side) {
        foreach ($others as $oname => $other) {
            $code = $side === 'L' ? "return \$undef $op \$other;" : "return \$other $op \$undef;";
            $f = eval("return function(\$other) { $code };");
            $log = [];
            try { $r = $f($other); $log[] = 'VALUE:' . var_export($r, true); }
            catch (Throwable $e) { $log[] = get_class($e) . ':' . $e->getMessage(); }
            echo str_pad("$op $side $oname", 12), ' | ', implode(' ; ', $log), "\n";
        }
    }
}
