<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Http\Requests\Auth\RegisterRequest;
use App\Http\Resources\UserResource;
use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthController extends Controller
{
    /**
     * Register a new user
     */
    public function register(RegisterRequest $request): JsonResponse
    {
        try {
            $user = User::create([
                'name' => $request->name,
                'username' => $request->username,
                'email' => $request->email,
                'university' => $request->university,
                'phone' => $request->phone,
                'role' => $request->role ?? 'user',
                'password' => Hash::make($request->password),
            ]);

            event(new Registered($user));

            $token = JWTAuth::fromUser($user);

            return response()->json([
                'status' => 'success',
                'message' => 'Registrasi berhasil',
                'data' => [
                    'user' => new UserResource($user),
                    'access_token' => $token,
                    'token_type' => 'bearer',
                    'expires_in' => $this->getJWTExpiresIn(),
                    'expires_at' => now()->addMinutes(config('jwt.ttl'))->toDateTimeString()
                ]
            ], 201)
            ->header('Content-Type', 'application/json');
            
        } catch (\Exception $e) {
            Log::error('Register error: ' . $e->getMessage());
            
            return response()->json([
                'status' => 'error',
                'message' => 'Registrasi gagal',
                'error' => $e->getMessage()
            ], 500)
            ->header('Content-Type', 'application/json');
        }
    }

    /**
     * Login user (support email atau username)
     */
    public function login(LoginRequest $request): JsonResponse
    {
        try {
            $loginField = $request->login;
            $password = $request->password;

            // Tentukan apakah login menggunakan email atau username
            $fieldType = filter_var($loginField, FILTER_VALIDATE_EMAIL) ? 'email' : 'username';
            
            $credentials = [
                $fieldType => $loginField,
                'password' => $password
            ];

            if (!$token = auth('api')->attempt($credentials)) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Email/Username atau password salah'
                ], 401)
                ->header('Content-Type', 'application/json');
            }

            $user = auth('api')->user();

            if (!$user->is_active) {
                auth('api')->logout();
                return response()->json([
                    'status' => 'error',
                    'message' => 'Akun Anda tidak aktif. Hubungi admin.',
                ], 403)
                ->header('Content-Type', 'application/json');
            }

            return response()->json([
                'status' => 'success',
                'message' => 'Login berhasil',
                'data' => [
                    'user' => new UserResource($user),
                    'access_token' => $token,
                    'token_type' => 'bearer',
                    'expires_in' => $this->getJWTExpiresIn(),
                    'expires_at' => now()->addMinutes(config('jwt.ttl'))->toDateTimeString()
                ]
            ], 200)
            ->header('Content-Type', 'application/json')
            ->header('X-API-Response', 'true');
            
        } catch (JWTException $e) {
            Log::error('Login JWT error: ' . $e->getMessage());
            
            return response()->json([
                'status' => 'error',
                'message' => 'Tidak dapat membuat token',
                'error' => $e->getMessage()
            ], 500)
            ->header('Content-Type', 'application/json');
            
        } catch (\Exception $e) {
            Log::error('Login error: ' . $e->getMessage());
            
            return response()->json([
                'status' => 'error',
                'message' => 'Login gagal',
                'error' => $e->getMessage()
            ], 500)
            ->header('Content-Type', 'application/json');
        }
    }

    /**
     * Get authenticated user profile
     */
    public function me(): JsonResponse
    {
        try {
            $user = auth('api')->user();
            
            return response()->json([
                'status' => 'success',
                'data' => [
                    'user' => new UserResource($user)
                ]
            ])
            ->header('Content-Type', 'application/json');
            
        } catch (\Exception $e) {
            Log::error('Get user profile error: ' . $e->getMessage());
            
            return response()->json([
                'status' => 'error',
                'message' => 'Tidak dapat mengambil profil user',
                'error' => $e->getMessage()
            ], 500)
            ->header('Content-Type', 'application/json');
        }
    }

    /**
     * Update user profile
     */
    public function updateProfile(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'name' => 'sometimes|string|max:255',
            'university' => 'sometimes|string|max:255',
            'phone' => 'sometimes|string|max:20',
            'profile_image' => 'sometimes|image|mimes:jpeg,png,jpg|max:2048',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Validasi gagal',
                'errors' => $validator->errors()
            ], 422)
            ->header('Content-Type', 'application/json');
        }

        try {
            $user = auth('api')->user();
            
            if ($request->hasFile('profile_image')) {
                // Delete old image if exists
                if ($user->profile_image && file_exists(storage_path('app/public/' . $user->profile_image))) {
                    unlink(storage_path('app/public/' . $user->profile_image));
                }
                
                $imagePath = $request->file('profile_image')->store('profile-images', 'public');
                $user->profile_image = $imagePath;
            }

            $user->fill($request->only(['name', 'university', 'phone']));
            $user->save();

            return response()->json([
                'status' => 'success',
                'message' => 'Profil berhasil diperbarui',
                'data' => [
                    'user' => new UserResource($user)
                ]
            ])
            ->header('Content-Type', 'application/json');
            
        } catch (\Exception $e) {
            Log::error('Update profile error: ' . $e->getMessage());
            
            return response()->json([
                'status' => 'error',
                'message' => 'Update profil gagal',
                'error' => $e->getMessage()
            ], 500)
            ->header('Content-Type', 'application/json');
        }
    }

    /**
     * Change password
     */
    public function changePassword(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'current_password' => 'required',
            'new_password' => 'required|string|min:8|confirmed',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Validasi gagal',
                'errors' => $validator->errors()
            ], 422)
            ->header('Content-Type', 'application/json');
        }

        try {
            $user = auth('api')->user();

            if (!Hash::check($request->current_password, $user->password)) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Password saat ini salah',
                ], 422)
                ->header('Content-Type', 'application/json');
            }

            $user->password = Hash::make($request->new_password);
            $user->save();

            return response()->json([
                'status' => 'success',
                'message' => 'Password berhasil diubah',
            ])
            ->header('Content-Type', 'application/json');
            
        } catch (\Exception $e) {
            Log::error('Change password error: ' . $e->getMessage());
            
            return response()->json([
                'status' => 'error',
                'message' => 'Ubah password gagal',
                'error' => $e->getMessage()
            ], 500)
            ->header('Content-Type', 'application/json');
        }
    }

    /**
     * Logout user
     */
    public function logout(): JsonResponse
    {
        try {
            auth('api')->logout();
            
            return response()->json([
                'status' => 'success',
                'message' => 'Berhasil logout'
            ])
            ->header('Content-Type', 'application/json');
            
        } catch (\Exception $e) {
            Log::error('Logout error: ' . $e->getMessage());
            
            return response()->json([
                'status' => 'error',
                'message' => 'Logout gagal',
                'error' => $e->getMessage()
            ], 500)
            ->header('Content-Type', 'application/json');
        }
    }

    /**
     * Check if token is valid
     */
    public function checkToken(): JsonResponse
    {
        try {
            $user = auth('api')->user();
            $payload = auth('api')->payload();
            
            return response()->json([
                'status' => 'success',
                'message' => 'Token valid',
                'data' => [
                    'valid' => true,
                    'user_id' => $user->id,
                    'role' => $user->role,
                    'token_expires_at' => date('Y-m-d H:i:s', $payload['exp'])
                ]
            ])
            ->header('Content-Type', 'application/json');
            
        } catch (\Exception $e) {
            Log::error('Check token error: ' . $e->getMessage());
            
            return response()->json([
                'status' => 'error',
                'message' => 'Token tidak valid',
                'data' => [
                    'valid' => false
                ]
            ], 401)
            ->header('Content-Type', 'application/json');
        }
    }


    /**
     * Get JWT expiration time in seconds
     */
    private function getJWTExpiresIn(): int
    {
        try {
            $ttlMinutes = config('jwt.ttl', 43200);
            return (int) $ttlMinutes * 60;
        } catch (\Exception $e) {
            return 2592000;
        }
    }
}