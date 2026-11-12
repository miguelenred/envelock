<?php
declare(strict_types=1);
$first = require_once __DIR__ . '/lib/calculator.php';
$second = require_once __DIR__ . '/lib/calculator.php';
echo json_encode([
    'project' => 'A',
    'total' => \ExampleA\Calculator::total(100.0, 0.21),
    'first_include' => $first,
    'second_include' => $second,
    'filename' => basename(__FILE__),
    'included_files' => count(get_included_files()),
], JSON_THROW_ON_ERROR), "\n";
