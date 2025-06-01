<template>
  <div class="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
    <div class="mx-auto w-full max-w-md px-4">
      <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
        Crear una cuenta
      </h2>
      <p class="mt-2 text-center text-sm text-gray-600">
        Regístrate para empezar a usar Schedulr.
      </p>
    </div>

    <div class="mt-8 mx-auto w-full max-w-md px-4">
      <div class="bg-white py-8 px-4 shadow-sm sm:rounded-lg sm:px-10">
        <div v-if="errors.general" class="bg-red-100 border border-red-300 text-red-600 px-4 py-3 rounded relative mb-4" role="alert">
          <span class="block sm:inline">{{ errors.general }}</span>
        </div>

        <!-- <div v-if="successMessage" class="bg-green-100 border border-green-300 text-green-600 px-4 py-3 rounded relative mb-4" role="alert">
          <span class="block sm:inline">{{ successMessage }}</span>
        </div> -->

        <form @submit.prevent="handleRegister" class="space-y-6">
          <div>
            <label for="name" class="block text-sm font-medium text-gray-700">
              Nombre completo
            </label>
            <div class="mt-1">
              <input
                id="name"
                name="name"
                type="text"
                autocomplete="name"
                required
                placeholder="Ingresa tu nombre"
                :class="[
                  'appearance-none block w-full px-3 py-2 border rounded-md shadow-sm placeholder-gray-400 focus:outline-none sm:text-sm',
                  errors.name ? 'border-red-300 focus:ring-red-300 focus:border-red-300' : 'border-gray-300 focus:ring-blue-500 focus:border-blue-500'
                ]"
                v-model="form.name"
                @input="validateField('name', form.name)"
                @blur="validateField('name', form.name)"
                :aria-invalid="errors.name ? 'true' : null"
                :aria-describedby="errors.name ? 'name-error' : null"
              />
            </div>
            <p v-if="errors.name" id="name-error" class="mt-2 text-sm text-red-400">{{ errors.name }}</p>
          </div>

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
                placeholder="Crea una contraseña"
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

          <div>
            <label for="password_confirmation" class="block text-sm font-medium text-gray-700">
              Confirmar contraseña
            </label>
            <div class="mt-1 relative">
              <input
                id="password_confirmation"
                name="password_confirmation"
                :type="password_confirmationFieldType" autocomplete="new-password"
                required
                placeholder="Confirma tu contraseña"
                :class="[
                  'appearance-none block w-full px-3 py-2 border rounded-md shadow-sm placeholder-gray-400 focus:outline-none sm:text-sm pr-10',
                  errors.password_confirmation ? 'border-red-300 focus:ring-red-300 focus:border-red-300' : 'border-gray-300 focus:ring-blue-500 focus:border-blue-500'
                ]"
                v-model="form.password_confirmation"
                @input="validateField('password_confirmation', form.password_confirmation)"
                @blur="validateField('password_confirmation', form.password_confirmation)"
                :aria-invalid="errors.password_confirmation ? 'true' : null"
                :aria-describedby="errors.password_confirmation ? 'password-confirmation-error' : null"
              />
              <button type="button" @click="togglePasswordConfirmationVisibility" class="absolute inset-y-0 right-0 pr-3 flex items-center text-sm leading-5"> <svg v-if="password_confirmationFieldType === 'password'" class="h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  <path stroke-linecap="round" stroke-linejoin="round" d="M2.458 12.025a.75.75 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.432 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
                </svg>
                <svg v-else class="h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M3.988 5.89L10.5 12.404m7.126-7.126L13.5 12.404m-7.126 7.126L13.5 12.404M12 12a3 3 0 100-6 3 3 0 000 6z" />
                  <path stroke-linecap="round" stroke-linejoin="round" d="M2.458 12.025a.75.75 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.432 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
                </svg>
              </button>
            </div>
            <p v-if="errors.password_confirmation" id="password-confirmation-error" class="mt-2 text-sm text-red-400">{{ errors.password_confirmation }}</p>
          </div>

          <div>
            <button
              type="submit"
              :disabled="!isFormValid || isSubmitting"
              :class="[
                'w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white transition ease-in-out duration-150',
                !isFormValid || isSubmitting
                  ? 'bg-gray-600 cursor-not-allowed'
                  : 'bg-gray-800 hover:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-700 cursor-pointer'
              ]"
            >
              <svg v-if="isSubmitting" class="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              {{ isSubmitting ? 'Registrando...' : 'Registrarse' }}
            </button>
          </div>
        </form>

        <div class="mt-6 text-center">
          <router-link to="/login" class="font-medium text-gray-700 hover:text-gray-900">
            ¿Ya tienes una cuenta? Iniciar sesión
          </router-link>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, computed } from 'vue';

import { useRouter } from 'vue-router';

export default {
  name: 'RegisterPage',
  setup() {
    const router = useRouter();

    const form = ref({
      name: '',
      email: '',
      password: '',
      password_confirmation: '',
    });

    const errors = ref({
      name: '',
      email: '',
      password: '',
      password_confirmation: '',
      general: ''
    });

    const successMessage = ref(null);

    const isSubmitting = ref(false);
    
    const passwordFieldType = ref('password');

    const password_confirmationFieldType = ref('password');

    const togglePasswordVisibility = () => {
      passwordFieldType.value = passwordFieldType.value === 'password' ? 'text' : 'password';
    };

    const togglePasswordConfirmationVisibility = () => {
      password_confirmationFieldType.value = password_confirmationFieldType.value === 'password' ? 'text' : 'password';
    };

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

    const handleRegister = async () => {
      // 1. Limpiar mensajes de éxito y errores anteriores
      errors.value = {};
      successMessage.value = null;

      // 2. Ejecutar validaciones del frontend justo antes de enviar
      validateField('name', form.value.name);
      validateField('email', form.value.email);
      validateField('password', form.value.password);
      validateField('password_confirmation', form.value.password_confirmation);

      // 3. Si el formulario no es válido o ya se está enviando, detener el proceso
      if (!isFormValid.value || isSubmitting.value) {
        console.log('Frontend Validation Failed or Already Submitting. Aborting.');
        isSubmitting.value = false; // Deshabilitar el estado de envío si la validación del frontend falla
        return;
      }

      isSubmitting.value = true;

      try {
        const response = await axios.post('/api/register', {
          name: form.value.name,
          email: form.value.email,
          password: form.value.password,
          password_confirmation: form.value.password_confirmation,
        });

        successMessage.value = response.data.message || '¡Registro exitoso! Ahora puedes iniciar sesión.';

        // alert(successMessage.value); // Considera reemplazar alert() por un modal o toast más amigable

        form.value = {
          name: '',
          email: '',
          password: '',
          password_confirmation: '',
        };

        router.push('/login');

      } catch (apiError) {
        if (apiError.response) {
          if (apiError.response.status === 422 && apiError.response.data.errors) {
            Object.keys(apiError.response.data.errors).forEach(key => {
              errors.value[key] = apiError.response.data.errors[key][0];
            });

            errors.value.general = apiError.response.data.message || 'Por favor, corrige los errores del formulario.';
          } else if (apiError.response.data && apiError.response.data.message) {
            // Otros errores del servidor con un mensaje específico (ej. 409 Conflict, 500 Internal Server Error)
            errors.value.general = apiError.response.data.message;
          } else {
            // Error genérico del servidor sin mensaje específico en data.message
            errors.value.general = 'Ocurrió un error inesperado al registrar. Inténtalo de nuevo más tarde.';
          }
        } else if (apiError.request) {
          // La solicitud fue hecha pero no se recibió respuesta
          // Esto puede ser un problema de red, el servidor no está respondiendo,
          // o un fallo en la solicitud OPTIONS de CORS (preflight request).
          errors.value.general = 'No se pudo conectar con el servidor. Verifica tu conexión a internet o el estado del servidor.';
        } else {
          // Algo sucedió al configurar la solicitud que provocó un Error
          // (ej. URL mal formada en Axios, error en la configuración de Axios)
          errors.value.general = 'Error al configurar la solicitud. Por favor, intenta de nuevo.';
        }
      } finally {
        isSubmitting.value = false;
      }
    };

    return {
      form,
      errors,
      isSubmitting,
      passwordFieldType,
      password_confirmationFieldType,
      passwordStrength,
      isFormValid,
      togglePasswordVisibility,
      togglePasswordConfirmationVisibility,
      validateField,
      handleRegister,
      successMessage,
    };
  },
};
</script>

<style scoped>
.error-message {
  color: red;
  font-size: 0.85em;
  margin-top: 5px;
  display: block;
}

.success-message {
  color: green;
  text-align: center;
  margin-top: 15px;
  font-weight: bold;
}
</style>