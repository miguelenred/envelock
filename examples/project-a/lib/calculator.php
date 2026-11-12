<?php
declare(strict_types=1);
namespace ExampleA;
final class Calculator
{
    public static function total(float $net, float $tax): float
    {
        return round($net * (1 + $tax), 2);
    }
}
return 'library-loaded';
