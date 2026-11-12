<?php

namespace App\Service;

final class Catalogue
{
    private function path(): string
    {
        return dirname(__DIR__, 2) . '/var/items.json';
    }

    public function all(): array
    {
        $path = $this->path();
        return is_file($path) ? json_decode(file_get_contents($path), true, 512, JSON_THROW_ON_ERROR) : [];
    }

    public function add(string $name): array
    {
        $items = $this->all();
        $item = ['id' => count($items) + 1, 'name' => $name];
        $items[] = $item;
        file_put_contents($this->path(), json_encode($items, JSON_THROW_ON_ERROR));
        return $item;
    }
}
