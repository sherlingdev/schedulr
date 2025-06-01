<template>
  <div class="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
    <div class="mx-auto w-full max-w-md px-4">
      <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
        Iniciar sesión
      </h2>
      <p class="mt-2 text-center text-sm text-gray-600">
        ¡Bienvenido de nuevo! Por favor, ingresa tus datos.
      </p>
    </div>

    <div class="mt-8 mx-auto w-full max-w-md px-4">
      <div class="bg-white py-8 px-4 shadow-sm sm:rounded-lg sm:px-10">
        <div v-if="errors.general" class="bg-red-100 border border-red-300 text-red-600 px-4 py-3 rounded relative mb-4" role="alert">
          <span class="block sm:inline">{{ errors.general }}</span>
        </div>

        <form @submit.prevent="handleLogin" class="space-y-6">
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
            <label for="password" class="block text-sm font-medium text-gray-700">
              Contraseña
            </label>
            <div class="mt-1 relative">
              <input
                id="password"
                name="password"
                :type="passwordFieldType"
                autocomplete="current-password"
                required
                placeholder="Ingresa tu contraseña"
                :class="[
                  'appearance-none block w-full px-3 py-2 border rounded-md shadow-sm placeholder-gray-400 focus:outline-none sm:text-sm pr-10',
                  errors.password ? 'border-red-300 focus:ring-red-300 focus:border-red-300' : 'border-gray-300 focus:ring-blue-500 focus:border-blue-500'
                ]"
                v-model="form.password"
                @input="validateField('password', form.password)"
                @blur="validateField('password', form.password)"
                :aria-invalid="errors.password ? 'true' : null"
                :aria-describedby="errors.password ? 'password-error' : null"
              />
              <button type="button" @click="togglePasswordVisibility" class="absolute inset-y-0 right-0 pr-3 flex items-center text-sm leading-5">
                <svg v-if="passwordFieldType === 'password'" class="h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  <path stroke-linecap="round" stroke-linejoin="round" d="M2.458 12.025a.75.75 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.432 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
                </svg>
                <svg v-else class="h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M3.988 5.89L10.5 12.404m7.126-7.126L13.5 12.404m-7.126 7.126L13.5 12.404M12 12a3 3 0 100-6 3 3 0 000 6z" />
                  <path stroke-linecap="round" stroke-linejoin="round" d="M2.458 12.025a.75.75 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.432 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
                </svg>
              </button>
            </div>
            <p v-if="errors.password" id="password-error" class="mt-2 text-sm text-red-400">{{ errors.password }}</p>

            <!-- <div class="mt-2" v-if="form.password.length > 0">
              <div class="w-full bg-gray-200 rounded-full h-2.5">
                <div :class="['h-2.5 rounded-full transition-all duration-300 ease-in-out', passwordStrength.color]"
                     :style="{ width: (passwordStrength.text === '' ? '0%' : (passwordStrength.text === 'Muy débil' ? '20%' : passwordStrength.text === 'Débil' ? '40%' : passwordStrength.text === 'Regular' ? '60%' : passwordStrength.text === 'Buena' ? '80%' : '100%')) }">
                </div>
              </div>
              <p :class="['mt-1 text-xs font-medium', passwordStrength.color.replace('bg-', 'text-')]">
                {{ passwordStrength.text }}
              </p>
              <ul class="mt-2 text-xs text-gray-500 list-disc list-inside">
                <li>Mínimo 8 caracteres</li>
                <li>Al menos una mayúscula y una minúscula</li>
                <li>Al menos un número</li>
                <li>Al menos un símbolo (opcional)</li>
              </ul>
            </div> -->
          </div>

          <div class="flex items-start justify-between">
            <div class="flex items-center">
              <input
                id="remember-me"
                name="remember-me"
                type="checkbox"
                class="h-4 w-4 text-gray-800 focus:ring-gray-700 border-gray-300 rounded cursor-pointer custom-checkbox"
                v-model="form.rememberMe"
              />
              <label for="remember-me" class="ml-2 block text-sm text-gray-900 cursor-pointer">
                Recordarme
              </label>
            </div>

            <div class="text-sm text-right">
              <router-link to="/forgot-password" class="font-medium text-gray-700 hover:text-gray-900">
                ¿Olvidaste tu contraseña?
              </router-link>
            </div>
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
              {{ isSubmitting ? 'Iniciando sesión...' : 'Iniciar sesión' }}
            </button>
          </div>
        </form>

        <div class="mt-6">
          <div class="relative">
            <div class="absolute inset-0 flex items-center">
              <div class="w-full border-t border-gray-200"></div>
            </div>
            <div class="relative flex justify-center text-sm">
              <span class="px-2 bg-white text-gray-400"> O </span>
            </div>
          </div>

          <div class="mt-6 text-center">
            <router-link to="/register" class="font-medium text-gray-700 hover:text-gray-900">
              ¿No tienes una cuenta? Regístrate
            </router-link>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, computed } from 'vue';
import { useAuthStore } from '../../stores/auth'; // Importa tu store de autenticación
import { useRouter } from 'vue-router'; // Necesitas useRouter para obtener la instancia del router

export default {
  name: 'LoginPage',
  setup() {
    // Instancia del store de autenticación
    const authStore = useAuthStore();
    // Instancia del router
    const router = useRouter(); // Aunque el store redirija, es buena práctica tenerlo aquí si lo necesitas para otras cosas.

    const passwordFieldType = ref('password');
    const isSubmitting = ref(false);

    const form = ref({
      email: '',
      password: '',
      rememberMe: false, // Asegúrate de que esta propiedad se maneje en el backend si es necesaria
    });

    const errors = ref({
      email: '',
      password: '',
      general: ''
    });

    const togglePasswordVisibility = () => {
      passwordFieldType.value = passwordFieldType.value === 'password' ? 'text' : 'password';
    };

    // Función para validar un campo individualmente
    const validateField = (field, value) => {
      errors.value[field] = ''; // Limpiar el error específico del campo
      errors.value.general = ''; // Limpiar errores generales al interactuar

      if (field === 'email') {
        if (!value.trim()) {
          errors.value.email = 'El correo electrónico es requerido.';
        } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
          errors.value.email = 'Formato de correo electrónico inválido.';
        }
      }

      if (field === 'password') {
        if (!value) {
          errors.value.password = 'La contraseña es requerida.';
        } else if (value.length < 6) { // Para login, a menudo es menos estricta
          errors.value.password = 'La contraseña debe tener al menos 6 caracteres.';
        }
        // No necesitas la validación completa de mayúsculas/minúsculas/números/símbolos aquí
        // porque esa es una regla de registro, no de login.
        // Si el backend es más estricto y da error, el catch lo manejará.
      }
    };

    // Función para validar todo el formulario antes del envío
    const validateForm = () => {
      let isValid = true;
      // Reinicia todos los errores específicos
      errors.value.email = '';
      errors.value.password = '';
      errors.value.general = ''; // También limpia el error general antes de validar

      // Validación del correo electrónico
      if (!form.value.email) {
        errors.value.email = 'El correo electrónico es requerido.';
        isValid = false;
      } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.value.email)) {
        errors.value.email = 'Ingresa un correo electrónico válido.';
        isValid = false;
      }

      // Validación de la contraseña
      if (!form.value.password) {
        errors.value.password = 'La contraseña es requerida.';
        isValid = false;
      } else if (form.value.password.length < 6) {
        errors.value.password = 'La contraseña debe tener al menos 6 caracteres.';
        isValid = false;
      }

      return isValid;
    };


    const handleLogin = async () => {
      // 1. Validar el formulario en el cliente antes de enviar
      if (!validateForm()) {
        console.log('Formulario no válido. Deteniendo inicio de sesión.');
        return;
      }

      isSubmitting.value = true;
      errors.value.general = ''; // Limpia cualquier error general previo

      try {
        // 2. Llama a la acción `login` de tu store de autenticación
        // El store se encargará de la llamada a Axios, el manejo de cookies CSRF,
        // la actualización del estado de autenticación y la redirección.
        await authStore.login({
          email: form.value.email,
          password: form.value.password,
          remember_me: form.value.rememberMe
        });

      } catch (apiError) {
        console.error('Error durante el inicio de sesión en el componente:', apiError);

        // 3. Manejo de errores de la API (capturados desde el store)
        if (apiError.response) {
          // Errores de validación del backend (ej. 422 Unprocessable Entity)
          if (apiError.response.status === 422 && apiError.response.data.errors) {
            Object.keys(apiError.response.data.errors).forEach(key => {
              if (errors.value[key] !== undefined) { // Solo si el campo existe en nuestro 'errors' local
                 errors.value[key] = apiError.response.data.errors[key][0];
              }
            });
            errors.value.general = apiError.response.data.message || 'Por favor, corrige los errores del formulario.';
          }
          // Credenciales incorrectas (ej. 401 Unauthorized)
          else if (apiError.response.status === 401) {
            errors.value.general = apiError.response.data.message || 'Credenciales inválidas. Por favor, inténtalo de nuevo.';
          }
          // Otros errores del servidor (ej. 500 Internal Server Error)
          else {
            errors.value.general = apiError.response.data.message || 'Ocurrió un error inesperado. Inténtalo de nuevo.';
          }
        } else if (apiError.request) {
          // La solicitud fue hecha pero no se recibió respuesta (problema de red/servidor caído)
          errors.value.general = 'No se pudo conectar con el servidor. Por favor, verifica tu conexión a internet o inténtalo más tarde.';
        } else {
          // Algo más pasó al configurar la solicitud
          errors.value.general = 'Ocurrió un error inesperado. Por favor, inténtalo de nuevo.';
        }

      } finally {
        isSubmitting.value = false;
      }
    };


    // La lógica de fuerza de contraseña es más relevante para el registro,
    // pero la mantengo si decides usarla también para el login.
    const passwordStrength = computed(() => {
      const p = form.value.password;
      let strength = 0;
      if (p.length > 7) strength++;
      if (/[A-Z]/.test(p)) strength++;
      if (/[a-z]/.test(p)) strength++;
      if (/[0-9]/.test(p)) strength++;
      if (/[^A-Za-z0-9\s]/.test(p)) strength++;

      switch (strength) {
        case 0: return { text: '', color: 'bg-transparent' };
        case 1: return { text: 'Muy débil', color: 'bg-red-400' };
        case 2: return { text: 'Débil', color: 'bg-orange-500' };
        case 3: return { text: 'Regular', color: 'bg-yellow-500' };
        case 4: return { text: 'Buena', color: 'bg-blue-500' };
        case 5: return { text: 'Fuerte', color: 'bg-green-500' };
        default: return { text: '', color: 'bg-transparent' };
      }
    });

    const isFormValid = computed(() => {
        // Valida los campos básicos y que no haya errores específicos de campo
        const isEmailValid = form.value.email.trim() !== '' && errors.value.email === '';
        const isPasswordValid = form.value.password.trim() !== '' && errors.value.password === '';

        return isEmailValid && isPasswordValid;
    });


    return {
      form,
      errors,
      handleLogin,
      passwordFieldType,
      togglePasswordVisibility,
      validateField,
      passwordStrength,
      isSubmitting,
      isFormValid,
    };
  },
};
</script>

<style scoped>
.custom-checkbox {
  accent-color: oklch(0.278 0.033 256.848);
}
</style>