<?php

namespace App\Http\Controllers;

use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth; // Asegúrate de que esta línea esté presente
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    /**
     * Registra un nuevo usuario en la aplicación.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {
        try {
            // 1. Validar los datos de entrada
            $request->validate([
                'name' => ['required', 'string', 'max:255'],
                'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
                'password' => ['required', 'string', 'min:8', 'confirmed'],
            ]);
        } catch (ValidationException $e) {
            // Manejo de errores de validación (código 422 Unprocessable Entity)
            return response()->json([
                'message' => 'Los datos proporcionados son inválidos.',
                'errors' => $e->errors()
            ], 422);
        }

        try {
            // 2. Crear el usuario en la base de datos
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password), // Hashear la contraseña por seguridad
            ]);

            // 3. Enviar una respuesta de éxito
            return response()->json([
                'message' => 'Usuario registrado exitosamente.',
                // Opcional: Puedes devolver el usuario creado si el frontend lo necesita
                // 'user' => $user,
            ], 201); // Código de estado 201 Created para creación exitosa

        } catch (Exception $e) {
            // Manejo de errores inesperados durante la creación del usuario (ej. error de base de datos)
            // Es buena práctica registrar el error para depuración
            return response()->json([
                'message' => 'Ocurrió un error en el servidor al registrar el usuario. Inténtalo de nuevo más tarde.',
            ], 500); // Código de estado 500 Internal Server Error
        }
    }

    /**
     * Autentica a un usuario en la aplicación.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        // 1. Validar las credenciales de entrada
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
            // 'remember_me' => 'boolean', // Si vas a usar "recordarme", valida también
        ]);

        // 2. Intentar autenticar al usuario usando el guard 'web' (basado en sesiones/cookies)
        // Auth::attempt() intentará encontrar al usuario y verificar la contraseña.
        // Si tiene éxito, Laravel establecerá automáticamente la cookie de sesión.
        if (!Auth::attempt($request->only('email', 'password'), $request->boolean('remember_me'))) {
            // Si la autenticación falla, lanzar una excepción de validación
            throw ValidationException::withMessages([
                'email' => ['Las credenciales proporcionadas son incorrectas.'],
            ]);
        }

        // 3. Si la autenticación es exitosa
        // Sanctum manejará la sesión/cookies para SPAs automáticamente.
        // No necesitas crear un token explícitamente aquí si solo usas autenticación basada en cookies de SPA.
        // El usuario autenticado está disponible a través de Auth::user() o $request->user().

        return response()->json([
            'message' => 'Inicio de sesión exitoso.',
            'user' => Auth::user(), // Opcional: devolver los datos del usuario autenticado al frontend
        ]);
    }

    /**
     * Cierra la sesión del usuario autenticado.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout(Request $request)
    {
        // 1. Revocar el token API actual (si el usuario también tiene tokens de acceso personal, ej. para apps móviles)
        // Para SPAs que solo usan cookies de sesión, esta línea no es estrictamente necesaria
        // para el cierre de sesión de la SPA, pero es una buena práctica si usas HasApiTokens.
        // if ($request->user()) {
        //     $request->user()->currentAccessToken()->delete();
        // }

        // 2. Cerrar la sesión web (destruir la sesión en el servidor)
        Auth::guard('web')->logout();

        // 3. Invalidar la sesión actual y regenerar el token CSRF para seguridad
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        // 4. Enviar una respuesta de éxito
        return response()->json(['message' => 'Sesión cerrada exitosamente.']);
    }
}