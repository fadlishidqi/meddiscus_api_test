<?php
// routes/api.php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return response()->json(['message' => 'API Root Working!']);
});

Route::get('/health', function () {
    return response()->json(['message' => 'Health Check OK!']);
});