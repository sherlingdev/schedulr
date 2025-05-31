<template>
  <div class="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
    <div class="sm:mx-auto sm:w-full sm:max-w-md">
      <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
        ¿Olvidaste tu Contraseña?
      </h2>
      <p class="mt-2 text-center text-sm text-gray-600">
        Ingresa tu correo electrónico para restablecerla.
      </p>
    </div>

    <div class="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
      <div class="bg-white py-8 px-4 shadow-sm sm:rounded-lg sm:px-10">
        <form @submit.prevent="handleForgotPassword" class="space-y-6">
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
            <button
              type="submit"
              class="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-gray-800 hover:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-700"
            >
              Enviar Enlace de Restablecimiento
            </button>
          </div>
        </form>

        <div class="mt-6 text-center">
          <router-link to="/login" class="font-medium text-gray-700 hover:text-gray-900">
            Volver al inicio de sesión
          </router-link>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref } from 'vue';

export default {
  name: 'ForgotPasswordPage',
  setup() {
    const form = ref({
      email: '',
    });

    const handleForgotPassword = () => {
      console.log('Solicitando restablecimiento de contraseña para:', form.value.email);
      // Aquí integrarías la lógica real para enviar el correo de restablecimiento:
      // - Hacer una llamada API a tu backend de Laravel
      // - Manejar la respuesta (éxito/error, mostrar mensaje al usuario)
    };

    return {
      form,
      handleForgotPassword,
    };
  },
};
</script>

<style scoped></style>
