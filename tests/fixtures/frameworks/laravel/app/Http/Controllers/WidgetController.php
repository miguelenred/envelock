<?php

namespace App\Http\Controllers;

use App\Attributes\Probe;
use App\Models\Widget;
use App\Services\ProbeService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use ReflectionMethod;

final class WidgetController extends Controller
{
    public function index(): JsonResponse
    {
        return response()->json(['widgets' => Widget::query()->orderBy('id')->get(['id', 'name'])]);
    }

    public function store(Request $request): JsonResponse
    {
        $data = $request->validate(['name' => 'required|string|max:32']);
        $widget = Widget::create($data);
        return response()->json(['id' => $widget->id, 'name' => $widget->name], 201);
    }

    #[Probe('reflection')]
    public function reflect(ProbeService $service): JsonResponse
    {
        $attrs = (new ReflectionMethod(self::class, 'reflect'))->getAttributes(Probe::class);
        $attr = $attrs[0]->newInstance();
        return response()->json([
            'service' => get_class($service),
            'value' => $service->value(),
            'table' => (new Widget())->getTable(),
            'attributes' => count($attrs),
            'attribute_name' => $attr->name,
        ]);
    }
}
