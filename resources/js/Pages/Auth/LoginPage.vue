<template>
  <div class="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
    <div class="sm:mx-auto sm:w-full sm:max-w-md">
      <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
        Iniciar Sesión
      </h2>
      <p class="mt-2 text-center text-sm text-gray-600">
        ¡Bienvenido de nuevo! Por favor, ingresa tus datos.
      </p>
    </div>

    <div class="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
      <div class="bg-white py-8 px-4 shadow-sm sm:rounded-lg sm:px-10">
        <form @submit.prevent="handleLogin" class="space-y-6">
          <div>
            <label for="email" class="block text-sm font-medium text-gray-700">
              Correo Electrónico
            </label>
            <div class="mt-1">
              <input
                id="email"
                name="email"
                type="email"
                autocomplete="email"
                required
                placeholder="Ingresa tu correo electrónico"
                class="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm"
                v-model="form.email"
              />
            </div>
          </div>

          <div>
            <label for="password" class="block text-sm font-medium text-gray-700">
              Contraseña
            </label>
            <div class="mt-1">
              <input
                id="password"
                name="password"
                type="password"
                autocomplete="current-password"
                required
                placeholder="Contraseña"
                class="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm"
                v-model="form.password"
              />
            </div>
          </div>

          <div class="flex items-center justify-between">
            <div class="flex items-center">
              <input
                id="remember-me"
                name="remember-me"
                type="checkbox"
                class="h-4 w-4 text-gray-800 focus:ring-gray-700 border-gray-300 rounded"
              />
              <label for="remember-me" class="ml-2 block text-sm text-gray-900">
                Recordarme
              </label>
            </div>

            <div class="text-sm">
              <router-link to="/forgot-password" class="font-medium text-gray-700 hover:text-gray-900">
                ¿Olvidaste tu contraseña?
              </router-link>
            </div>
          </div>

          <div>
            <button
              type="submit"
              class="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-gray-800 hover:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-700"
            >
              Iniciar Sesión
            </button>
          </div>
        </form>

        <div class="mt-6">
          <div class="relative">
            <div class="absolute inset-0 flex items-center">
              <div class="w-full border-t border-gray-200"></div> </div>
            <div class="relative flex justify-center text-sm">
              <span class="px-2 bg-white text-gray-400"> O
              </span>
            </div>
          </div>

          <div class="mt-6 text-center"> <router-link to="/register" class="font-medium text-gray-700 hover:text-gray-900">
              ¿No tienes una cuenta? Regístrate
            </router-link>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref } from 'vue';

export default {
  name: 'LoginPage',
  setup() {
    console.log('LoginPage setup() function is running.');
    const form = ref({
      email: '',
      password: '',
    });
    console.log('Form ref initialized:', form.value);

    const handleLogin = () => {
      console.log('Intentando iniciar sesión con:', form.value);
      // Aquí integrarías la lógica de autenticación real y la redirección.
      // Por ejemplo, después de una autenticación exitosa:
      // router.push('/dashboard'); // Asegúrate de tener 'router' disponible en este scope
    };

    return {
      form,
      handleLogin,
    };
  },
};
</script>

<style scoped></style>