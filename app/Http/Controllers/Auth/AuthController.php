<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        try {
            // 1. Validar los datos de entrada
            $request->validate([
                'name' => ['required', 'string', 'max:255'],
                'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
                'password' => ['required', 'string', 'min:8', 'confirmed'], // 'confirmed' busca un campo 'password_confirmation'
            ]);

            // 2. Crear el nuevo usuario
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password), // Hashear la contraseña antes de guardar
            ]);

            // 3. Generar un token de Sanctum para el usuario recién registrado
            // El 'tokenName' es un nombre descriptivo para el token, útil para la gestión.
            $token = $user->createToken('auth_token')->plainTextToken;

            // 4. Retornar una respuesta JSON exitosa
            return response()->json([
                'message' => 'User registered successfully!', // Mensaje de éxito
                'user' => $user, // Datos del usuario (sin contraseña)
                'access_token' => $token, // El token para futuras solicitudes autenticadas
                'token_type' => 'Bearer', // Indica el tipo de token
            ], 201); // Código de estado HTTP 201 Created

        } catch (ValidationException $e) {
            // Manejar errores de validación
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422); // Código de estado HTTP 422 Unprocessable Entity
        } catch (\Exception $e) {
            // Manejar cualquier otro error inesperado
            return response()->json([
                'message' => 'An error occurred during registration.',
                'error' => $e->getMessage(),
            ], 500); // Código de estado HTTP 500 Internal Server Error
        }
    }

    /**
     * Handle user login.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request) // <-- Nueva función de login
    {
        try {
            // 1. Validar los datos de entrada
            $request->validate([
                'email' => ['required', 'string', 'email'],
                'password' => ['required', 'string'],
            ]);

            // 2. Intentar autenticar al usuario
            // Auth::attempt verifica las credenciales y, si son correctas, establece la sesión del usuario.
            // Para APIs con Sanctum, no se usa directamente la sesión para la autenticación de cada request,
            // pero attempt() es útil para verificar las credenciales y obtener el usuario.
            if (!Auth::attempt($request->only('email', 'password'))) {
                // Si las credenciales son incorrectas, lanzar una excepción de validación o un error 401
                throw ValidationException::withMessages([
                    'email' => ['Las credenciales proporcionadas son incorrectas.'], // Mensaje genérico para seguridad
                ]);
                // Alternativa para 401:
                // return response()->json(['message' => 'Unauthorized. Invalid credentials.'], 401);
            }

            // 3. Obtener el usuario autenticado
            $user = $request->user(); // O Auth::user();

            // 4. Generar un token de Sanctum para el usuario
            // Asegurarse de que los tokens anteriores para este nombre sean eliminados si no se desean múltiples sesiones.
            // $user->tokens()->where('name', 'auth_token')->delete(); // Opcional: para una sola sesión por tokenName
            $token = $user->createToken('auth_token')->plainTextToken;

            // 5. Retornar una respuesta JSON exitosa
            return response()->json([
                'message' => 'Login successful!',
                'user' => $user, // Datos del usuario (sin contraseña)
                'access_token' => $token,
                'token_type' => 'Bearer',
            ], 200); // Código de estado HTTP 200 OK

        } catch (ValidationException $e) {
            // Manejar errores de validación (incluyendo credenciales inválidas aquí)
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $e->errors(),
            ], 422);
        } catch (\Exception $e) {
            // Manejar cualquier otro error inesperado
            return response()->json([
                'message' => 'An error occurred during login.',
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Handle user logout.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout(Request $request) // <-- Nueva función de logout
    {
        // 1. Revocar el token actual del usuario autenticado
        // Esto invalida el token que fue usado para autenticar la solicitud actual.
        // Asegúrate de que esta ruta esté protegida por el middleware 'auth:sanctum'.
        $request->user()->currentAccessToken()->delete();

        // 2. Retornar una respuesta JSON de éxito
        return response()->json([
            'message' => 'Logged out successfully.'
        ], 200);
    }
}
