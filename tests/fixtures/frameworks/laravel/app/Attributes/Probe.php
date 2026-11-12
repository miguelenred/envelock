<?php

namespace App\Attributes;

use Attribute;

#[Attribute(Attribute::TARGET_METHOD)]
final class Probe
{
    public function __construct(public string $name = 'probe') {}
}
