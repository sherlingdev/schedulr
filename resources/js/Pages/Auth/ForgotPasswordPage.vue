<template>
  <div class="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
    <div class="sm:mx-auto sm:w-full sm:max-w-md">
      <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
        ¿Olvidaste tu contraseña?
      </h2>
      <p class="mt-2 text-center text-sm text-gray-600">
        Ingresa tu correo electrónico para restablecerla.
      </p>
    </div>

    <div class="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
      <div class="bg-white py-8 px-4 shadow-sm sm:rounded-lg sm:px-10">
        <div v-if="errors.general" class="bg-red-100 border border-red-300 text-red-600 px-4 py-3 rounded relative mb-4" role="alert">
          <span class="block sm:inline">{{ errors.general }}</span>
        </div>

        <form @submit.prevent="handleForgotPassword" class="space-y-6">
          <div>
            <label for="email" class="block text-sm font-medium text-gray-700">
              Correo electrónico
            </label>
            <div class="mt-1">
              <input
                id="email"
                name="email"
                type="email"
                autocomplete="email"
                required
                placeholder="Ingresa tu correo electrónico"
                :class="[
                  'appearance-none block w-full px-3 py-2 border rounded-md shadow-sm placeholder-gray-400 focus:outline-none sm:text-sm',
                  errors.email ? 'border-red-300 focus:ring-red-300 focus:border-red-300' : 'border-gray-300 focus:ring-blue-500 focus:border-blue-500'
                ]"
                v-model="form.email"
                @input="validateField('email', form.email)"
                @blur="validateField('email', form.email)"
                :aria-invalid="errors.email ? 'true' : null"
                :aria-describedby="errors.email ? 'email-error' : null"
              />
            </div>
            <p v-if="errors.email" id="email-error" class="mt-2 text-sm text-red-400">{{ errors.email }}</p>
          </div>

          <div>
            <button
              type="submit"
              :disabled="!isFormValid || isSubmitting"
              :class="[
                'w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white transition ease-in-out duration-150',
                !isFormValid || isSubmitting
                  ? 'bg-gray-600 cursor-not-allowed'
                  : 'bg-gray-800 hover:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-700 cursor-pointer'
              ]"
            >
              <svg v-if="isSubmitting" class="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              {{ isSubmitting ? 'Enviando...' : 'Enviar enlace de restablecimiento' }}
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
import { ref, computed } from 'vue';

export default {
  name: 'ForgotPasswordPage',
  setup() {
    const form = ref({
      email: '',
    });

    const isSubmitting = ref(false);

    const errors = ref({
      email: '',
      general: ''
    });

    // Propiedad computada para verificar si el formulario es válido
    const isFormValid = computed(() => {
      // Primero, asegura que todos los campos del formulario tienen un valor (no están vacíos)
      const allFieldsFilled = Object.values(form.value).every(value => value.trim() !== '');

      // Luego, verifica que NO haya mensajes de error en el objeto errors
      const noErrors = Object.values(errors.value).every(errorMsg => errorMsg === '');

      return allFieldsFilled && noErrors;
    });

    const validateField = (field, value) => {
      // Limpia errores previos para este campo
      errors.value[field] = '';
      errors.value.general = ''; // Siempre limpiar el error general al validar campos individuales

      if (field === 'email') {
        if (!value.trim()) {
          errors.value.email = 'El correo electrónico es requerido.';
        } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
          errors.value.email = 'Formato de correo electrónico inválido.';
        }
      }

      // Importante: Para una ForgotPasswordPage, probablemente solo necesitas la validación del email.
      // Puedes eliminar o comentar los bloques de validación para 'name', 'password' y 'password_confirmation'
      // si no son relevantes para el formulario de este componente específico.
    };

    const handleForgotPassword = async () => {
      // Activa la validación para el campo de email antes de intentar enviar
      validateField('email', form.value.email);

      // Si después de la validación hay errores en el email o el formulario no es válido
      if (!isFormValid.value || errors.value.email) {
          console.log('Formulario de restablecimiento no válido. Deteniendo solicitud.');
          return; // Detiene la ejecución si la validación falla
      }

      isSubmitting.value = true;
      errors.value.general = ''; // Limpia cualquier error general previo

      try {
        console.log('Intentando solicitar restablecimiento de contraseña para:', form.value.email);

        // *** Aquí integrarías tu lógica de llamada a la API real con tu backend ***
        // Recuerda importar axios al inicio si lo vas a usar aquí: `import axios from 'axios';`
        // await axios.post('/api/forgot-password', { email: form.value.email });

        // Simulación de un retraso y respuesta exitosa
        await new Promise(resolve => setTimeout(resolve, 2000)); // Simula un retraso de 2 segundos
        console.log('Solicitud de restablecimiento de contraseña exitosa simulada!');
        alert('¡Enlace de restablecimiento enviado! Revisa tu correo electrónico.');
        // Si usas Vue Router y quieres redirigir después de un éxito:
        // import { useRouter } from 'vue-router';
        // const router = useRouter();
        // router.push('/login'); 

      } catch (apiError) {
        console.error('Error durante la solicitud de restablecimiento de contraseña:', apiError);
        // Manejar errores de la API (ej. email no encontrado)
        if (apiError.response && apiError.response.data && apiError.response.data.message) {
          errors.value.general = apiError.response.data.message; // Mensaje de error general del backend
        } else {
          errors.value.general = 'Ocurrió un error inesperado al solicitar el restablecimiento. Inténtalo de nuevo más tarde.';
        }
      } finally {
        isSubmitting.value = false; // Siempre restablece el estado de envío
      }
    };

    return {
      errors,
      form,
      handleForgotPassword,
      validateField,
      isFormValid,
      // === ¡SOLUCIÓN AQUÍ! ===
      isSubmitting, // Asegúrate de retornar esta variable para que el template la pueda usar
    };
  },
};
</script>

<style scoped></style>
