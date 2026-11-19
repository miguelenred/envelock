<?php

namespace App\Libraries;

use App\Models\ItemModel;
use ReflectionProperty;

final class Catalogue
{
    public function __construct(private readonly ItemModel $items) {}

    public function all(): array
    {
        return array_map(
            static fn (array $row): array => ['id' => (int) $row['id'], 'name' => $row['name']],
            $this->items->select('id, name')->orderBy('id')->findAll(),
        );
    }

    public function add(string $name): array
    {
        $id = $this->items->insert(['name' => $name]);

        return ['id' => (int) $id, 'name' => $name];
    }

    public function table(): string
    {
        // A protected property's default, read back by reflection off a protected class.
        return (new ReflectionProperty(ItemModel::class, 'table'))->getValue($this->items);
    }
}
