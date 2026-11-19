<?php

namespace App\Controllers;

use App\Attributes\Probe as ProbeAttribute;
use CodeIgniter\HTTP\ResponseInterface;
use ReflectionMethod;

final class Probe extends BaseController
{
    public function ping(): ResponseInterface
    {
        return $this->response->setJSON(['pong' => true, 'php' => PHP_VERSION]);
    }

    public function items(): ResponseInterface
    {
        return $this->response->setJSON(['items' => service('catalogue')->all()]);
    }

    public function create(): ResponseInterface
    {
        $data = $this->request->getJSON(true);
        if (! is_array($data) || ! $this->validateData($data, ['name' => 'required|string|max_length[32]'])) {
            $errors = $this->validator?->getErrors() ?: ['name' => 'invalid'];

            return $this->response->setStatusCode(422)->setJSON(['errors' => $errors]);
        }

        return $this->response->setStatusCode(201)->setJSON(service('catalogue')->add($data['name']));
    }

    #[ProbeAttribute('reflection')]
    public function reflect(): ResponseInterface
    {
        $attributes = (new ReflectionMethod(self::class, 'reflect'))->getAttributes(ProbeAttribute::class);
        $catalogue  = service('catalogue');

        return $this->response->setJSON([
            'service'        => $catalogue::class,
            'table'          => $catalogue->table(),
            'attributes'     => count($attributes),
            'attribute_name' => $attributes[0]->newInstance()->name,
        ]);
    }
}
