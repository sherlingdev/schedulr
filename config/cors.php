<?php

return [

    /*
    |--------------------------------------------------------------------------
    | CORS Sane Defaults
    |--------------------------------------------------------------------------
    |
    | You can enable CORS for your entire app or by specific routes.
    |
    */

    // Las rutas a las que se aplicarán las reglas CORS.
    // Es CRUCIAL que incluya 'api/*' para tus rutas de API y 'sanctum/csrf-cookie' para Sanctum.
    'paths' => ['api/*', 'sanctum/csrf-cookie', 'login', 'logout', 'register'],

    // Métodos HTTP permitidos (GET, POST, PUT, DELETE, OPTIONS, etc.). '*' permite todos.
    'allowed_methods' => ['*'],

    // Orígenes permitidos (URL de tu frontend). Deben ser exactos.
    // ES FUNDAMENTAL que incluyan http://127.0.0.1:5173 que es el origen que está generando el error.
    'allowed_origins' => [
        'http://localhost:5173',
        'http://127.0.0.1:5173',
        'http://localhost:8000',
        'http://127.0.0.1:8000',
        // Agrega aquí cualquier otro dominio donde tu frontend se vaya a ejecutar (ej. en producción 'https://tudominio.com')
    ],

    'allowed_origins_patterns' => [], // Deja esto vacío a menos que necesites patrones Regex

    // Cabeceras HTTP permitidas. '*' permite todas.
    'allowed_headers' => ['*'],

    // Cabeceras HTTP que el navegador puede exponer al cliente (útil si envías cabeceras personalizadas).
    'exposed_headers' => [],

    // Duración máxima (en segundos) que la respuesta preflight (OPTIONS) puede ser almacenada en caché.
    'max_age' => 0,

    // Si se permiten credenciales (cookies, encabezados de autorización).
    // ¡DEBE SER TRUE para que Sanctum pueda enviar y recibir cookies!
    'supports_credentials' => true,
];