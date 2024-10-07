<?php

namespace App\Http\Controllers\Api;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\SignupRequest; // Ensure this import exists
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
class AuthController extends Controller
{
    public function login(LoginRequest $request)
    {
        $credentials = $request->validated();
        if (!Auth::attempt($credentials)) {
            return response([
                'message' => 'Provided email address or password is incorrect'
            ], status: 403);
        }

        $user = Auth::user();
        $token = $user->createToken('main')->plainTextToken;
        return response(compact('user', 'token'));
    }

    public function signup(SignupRequest $request)
    {
        $data = $request->validated();
        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => bcrypt($data['password'])
        ]);
        $token = $user->createToken('main')->plainTextToken;
        return response(compact(
            'user',
            'token'
        ));
    }
    public function logout(Request $request)
    {
        $user = $request->user();
        if (!$user) {
            return response([
                'message' => 'User not authenticated.'
            ], 401); // Unauthorized response
        }

        if ($user->currentAccessToken()) {
            $user->currentAccessToken()->delete();
            return response('', 204); // No Content response
        }

        return response([
            'message' => 'No token found.'
        ], 400); // Bad request if no token is found
    }
}
