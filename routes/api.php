<?php

use App\Http\Controllers\Api\AuthController;
use Illuminate\Support\Facades\Route;

// ===========================================
// HEALTH CHECK
// ===========================================
Route::get('/health', function () {
    return response()->json([
        'status' => 'success',
        'message' => 'Meddiscus API is running!',
        'timestamp' => now()->toDateTimeString(),
        'version' => '1.0.0'
    ]);
});

// ===========================================
// API VERSION 1 - AUTHENTICATION
// ===========================================
Route::prefix('v1/auth')->group(function () {
    
    // PUBLIC ROUTES (No Authentication Required)
    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/forgot-password', [AuthController::class, 'forgotPassword']);
    Route::post('/reset-password', [AuthController::class, 'resetPassword']);
    Route::post('/verify-reset-token', [AuthController::class, 'verifyResetToken']);

    // PROTECTED ROUTES (Authentication Required)
    Route::middleware(['auth:api'])->group(function () {
        Route::get('/me', [AuthController::class, 'me']); // Get current user info
        Route::put('/profile', [AuthController::class, 'updateProfile']); // Update profile
        Route::post('/change-password', [AuthController::class, 'changePassword']); // Change password
        Route::post('/logout', [AuthController::class, 'logout']); // Logout
        Route::get('/check-token', [AuthController::class, 'checkToken']); // Check if token valid
    });
});

// ===========================================
// FALLBACK
// ===========================================
Route::fallback(function () {
    return response()->json([
        'status' => 'error',
        'message' => 'API endpoint not found'
    ], 404);
});