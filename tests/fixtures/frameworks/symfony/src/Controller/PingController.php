<?php

namespace App\Controller;

use App\Service\Catalogue;
use ReflectionMethod;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

final class PingController
{
    #[Route('/ping', name: 'ping', methods: ['GET'])]
    public function ping(Catalogue $catalogue): JsonResponse
    {
        return new JsonResponse(['pong' => true, 'php' => PHP_VERSION]);
    }

    #[Route('/items', name: 'items-list', methods: ['GET'])]
    public function items(Catalogue $catalogue): JsonResponse
    {
        return new JsonResponse(['items' => $catalogue->all()]);
    }

    #[Route('/items', name: 'items-create', methods: ['POST'])]
    public function create(Request $request, Catalogue $catalogue): JsonResponse
    {
        $name = trim($request->getContent());
        if ($name === '' || strlen($name) > 32) {
            return new JsonResponse(['errors' => ['name' => ['invalid length']]], 422);
        }
        return new JsonResponse($catalogue->add($name), 201);
    }

    #[Route('/reflect', name: 'reflect', methods: ['GET'])]
    public function reflect(Catalogue $catalogue): JsonResponse
    {
        $attributes = (new ReflectionMethod(self::class, 'ping'))->getAttributes(Route::class);
        $attribute = $attributes[0]->newInstance();
        return new JsonResponse([
            'service' => get_class($catalogue),
            'attributes' => count($attributes),
            'path' => $attribute->path,
        ]);
    }
}
