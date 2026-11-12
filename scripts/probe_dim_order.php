<?php
// Measures on the real PHP engine the warning order of chained dimension reads B[K1][K2]...
// Oracle for the VM: all keys are evaluated before the fetches; an undefined base is reported at
// its fetch, not before the keys. Not a runtime component.
$log = [];
set_error_handler(function ($n, $s) use (&$log) { $log[] = "W:$s"; return true; });
function run($label, $fn) { global $log; $log = []; try { $v = $fn(); $log[] = 'VALUE:' . var_export($v, true); } catch (Throwable $e) { $log[] = get_class($e) . ':' . $e->getMessage(); } echo str_pad($label, 40), ' | ', implode(' ; ', $log), "\n"; }
$arr = [7, 8]; $n = 1; $s = 'str';
run('$arr[$arr["x"]][$arr["y"]]', fn() => $arr[$arr['x']][$arr['y']]);
run('$n[$arr["x"]][$arr["y"]]', fn() => $n[$arr['x']][$arr['y']]);
run('$n[$arr["x"]]', fn() => $n[$arr['x']]);
run('$arr[$arr["x"]][0]', fn() => $arr[$arr['x']][0]);
run('$arr[1][$arr["y"]]', fn() => $arr[1][$arr['y']]);
run('$arr[$arr["x"]][$arr["y"]] (arr[1] base)', fn() => $arr[1][$arr['y']][$arr['z']]);
run('$n[1][$arr["y"]]', fn() => $n[1][$arr['y']]);
run('$undef[$arr["x"]][$arr["y"]]', fn() => $undef[$arr['x']][$arr['y']]);
run('(1)[$arr["x"]][$arr["y"]]', fn() => (1)[$arr['x']][$arr['y']]);
run('(1)[$arr["x"]]', fn() => (1)[$arr['x']]);
