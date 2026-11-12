<?php

use App\Http\Controllers\WidgetController;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Support\Facades\Route;

// Dedicated disposable test app only: no real form or user data is accepted here.
Route::get('/ping', fn () => response()->json(['pong' => true, 'php' => PHP_VERSION]));
Route::get('/widgets', [WidgetController::class, 'index']);
Route::post('/widgets', [WidgetController::class, 'store'])->withoutMiddleware(PreventRequestForgery::class);
Route::get('/reflect', [WidgetController::class, 'reflect']);
Route::get('/session/write', function () {
    request()->session()->put('envelock_probe', 'envelock-probe');
    return response()->json(['session' => 'stored']);
});
Route::get('/session/read', fn () => response()->json([
    'session' => request()->session()->get('envelock_probe'),
]));
