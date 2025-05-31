<template>
  <div class="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
    <div class="sm:mx-auto sm:w-full sm:max-w-md">
      <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
        Iniciar sesión
      </h2>
      <p class="mt-2 text-center text-sm text-gray-600">
        ¡Bienvenido de nuevo! Por favor, ingresa tus datos.
      </p>
    </div>

    <div class="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
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
                autocomplete="new-password"
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

            <div class="mt-2" v-if="form.password.length > 0">
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
            </div>
          </div>

          <div class="flex items-center justify-between">
            <div class="flex items-center">
              <input
                id="remember-me"
                name="remember-me"
                type="checkbox"
                class="h-4 w-4 text-gray-800 focus:ring-gray-700 border-gray-300 rounded cursor-pointer"
                v-model="form.rememberMe"
              />
              <label for="remember-me" class="ml-2 block text-sm text-gray-900 cursor-pointer">
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
      :disabled="!isFormValid || isSubmitting" :class="[
        'w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white transition ease-in-out duration-150',
        !isFormValid || isSubmitting
          ? 'bg-gray-600 cursor-not-allowed' // <--- Clases para cuando está deshabilitado
          : 'bg-gray-800 hover:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-700 cursor-pointer' // <--- Clases normales
      ]"
    >
      <svg v-if="isSubmitting" class="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
      </svg>
      {{ isSubmitting ? 'Iniciando sesión...' : 'Iniciar sesión' }} </button>
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
// import PasswordInput from '../../components/PasswordInput.vue';

export default {
  name: 'LoginPage',
  components: {
    // PasswordInput // Registra el componente
  },
  setup() {
    const passwordFieldType = ref('password');

    const isSubmitting = ref(false);

    const form = ref({
      email: '',
      password: '',
      rememberMe: false,
    });

    // Objeto reactivo para almacenar los errores de validación
    const errors = ref({
      email: '',
      password: '',
      general: ''
    });

    const togglePasswordVisibility = () => {
      passwordFieldType.value = passwordFieldType.value === 'password' ? 'text' : 'password';
    };

    const handleLogin = async () => {
      // Primero, valida el formulario completamente
      if (!validateForm()) { // Llama a la función validateForm para una validación completa
        console.log('Formulario no válido. Deteniendo inicio de sesión.');
        return;
      }

      isSubmitting.value = true;

      errors.value.general = '';

      try {
        console.log('Intentando iniciar sesión con:', form.value);

        // *** Aquí integrarías tu lógica de autenticación real con tu backend ***
        // Ejemplo con una simulación de llamada API:
        await new Promise(resolve => setTimeout(resolve, 2000)); // Simula un retraso de 2 segundos

        // Simulación de respuesta exitosa
        console.log('Inicio de sesión exitoso simulado!');
        alert('¡Inicio de sesión exitoso! Redirigiendo...');
        // Si usas Vue Router, podrías redirigir:
        // router.push('/dashboard');

      } catch (apiError) {
        console.error('Error durante el inicio de sesión:', apiError);
        // Manejar errores de la API (ej. credenciales incorrectas)
        if (apiError.response && apiError.response.data && apiError.response.data.message) {
          errors.value.general = apiError.response.data.message; // Mensaje de error general del backend
        } else {
          errors.value.general = 'Ocurrió un error inesperado al iniciar sesión. Inténtalo de nuevo más tarde.';
        }
      } finally {
        isSubmitting.value = false;
      }
    };

    // En tu sección <script> de LoginPage.vue:
const isFormValid = computed(() => {
    // Asegura que email y password no estén vacíos y que no tengan errores de validación
    const isEmailValid = form.value.email.trim() !== '' && errors.value.email === '';
    const isPasswordValid = form.value.password.trim() !== '' && errors.value.password === '';

    // No necesitas validar 'rememberMe' para la validez general del formulario
    // a menos que sea un requisito específico.
    // También verifica que no haya errores generales.
    const noGeneralError = errors.value.general === '';

    return isEmailValid && isPasswordValid && noGeneralError;
});

    const validateField = (field, value) => {
      errors.value[field] = '';
      errors.value.general = '';

      if (field === 'name') {
        if (!value.trim()) {
          errors.value.name = 'El nombre completo es requerido.';
        }
      }

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
        } else if (value.length < 8) {
          errors.value.password = 'La contraseña debe tener al menos 8 caracteres.';
        } else if (!/[A-Z]/.test(value) || !/[a-z]/.test(value) || !/[0-9]/.test(value)) {
          errors.value.password = 'La contraseña debe contener mayúsculas, minúsculas y números.';
        } else if (value.length > 0 && !/[^A-Za-z0-9\s]/.test(value)) { // Sugerencia de símbolo (opcional para la validación obligatoria)
          // Puedes quitar esta línea si el símbolo es solo una sugerencia y no una regla obligatoria para el error.
          // errors.value.password = 'La contraseña debe contener al menos un símbolo.';
        }


        // Si la confirmación de contraseña ya tiene un valor, validarla también
        if (form.value.password_confirmation && value !== form.value.password_confirmation) {
          errors.value.password_confirmation = 'Las contraseñas no coinciden.';
        } else if (form.value.password_confirmation && value === form.value.password_confirmation) {
          errors.value.password_confirmation = ''; // Limpiar si ahora coinciden
        }
      }

      if (field === 'password_confirmation') {
        if (!value) {
          errors.value.password_confirmation = 'Debes confirmar tu contraseña.';
        } else if (value !== form.value.password) {
          errors.value.password_confirmation = 'Las contraseñas no coinciden.';
        }
      }
    };

    const passwordStrength = computed(() => {
      const p = form.value.password;
      let strength = 0;
      if (p.length > 7) strength++; // Longitud mínima
      if (/[A-Z]/.test(p)) strength++; // Mayúsculas
      if (/[a-z]/.test(p)) strength++; // Minúsculas
      if (/[0-9]/.test(p)) strength++; // Números
      if (/[^A-Za-z0-9\s]/.test(p)) strength++; // Símbolos (excluyendo espacios)

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

    // Función para validar el formulario
    const validateForm = () => {
      let isValid = true;

      // Validación del correo electrónico
      if (!form.value.email) {
        errors.email = 'El correo electrónico es requerido.';
        isValid = false;
      } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.value.email)) {
        errors.email = 'Ingresa un correo electrónico válido.';
        isValid = false;
      } else {
        errors.email = '';
      }

      // Validación de la contraseña (similar a la de registro, pero quizás menos estricta para login)
      if (!form.value.password) {
        errors.password = 'La contraseña es requerida.';
        isValid = false;
      } else if (form.value.password.length < 6) { // Por ejemplo, mínimo 6 caracteres para login
        errors.password = 'La contraseña debe tener al menos 6 caracteres.';
        isValid = false;
      } else {
        errors.password = '';
      }

      return isValid;
    };

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
/* Puedes añadir estilos específicos si no usas Tailwind CSS para todo */
/* .your-input-styles { ... } */
</style>