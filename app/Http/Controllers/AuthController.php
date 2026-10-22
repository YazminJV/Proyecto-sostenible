<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $token = Auth::login($user);

        return response()->json([
            'status' => 'success',
            'message' => 'Usuario creado exitosamente',
            'user' => $user,
            'authorization' => [
                'token' => $token,
                'type' => 'bearer',
            ]
        ]);
    }

  
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        $credentials = $request->only('email', 'password');

        if (! $token = Auth::guard('api')->attempt($credentials)) {
            return response()->json([
                'status' => 'error',
                'message' => 'Credenciales no autorizadas',
            ], 401);
        }

        $user = Auth::guard('api')->user();

        return response()->json([
            'status' => 'success',
            'user' => $user,
            'authorization' => [
                'token' => $token,
                'type' => 'bearer',
            ]
        ]);
    }

    // Cerrar sesión (Invalida el token actual)
    public function logout()
    {
        Auth::guard('api')->logout();

        return response()->json([
            'status' => 'success',
            'message' => 'Cierre de sesión exitoso',
        ]);
    }

    // Refrescar el token expirado
    public function refresh()
    {
        return response()->json([
            'status' => 'success',
            'user' => Auth::guard('api')->user(),
            'authorization' => [
                'token' => Auth::guard('api')->refresh(),
                'type' => 'bearer',
            ]
        ]);
    }
    
}
