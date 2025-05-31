<template>
  <div class="relative">
    <label v-if="label" :for="id" class="block text-sm font-medium text-gray-700">
      {{ label }}
    </label>

    <div class="mt-1 relative rounded-md shadow-sm">
      <input
        :id="id"
        :type="passwordFieldType"
        :name="name"
        :placeholder="placeholder"
        :value="modelValue"
        @input="$emit('update:modelValue', $event.target.value)"
        class="block w-full pr-10 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
        :class="{ 'border-red-500': hasError }"
      >

      <button
        type="button"
        @click="togglePasswordVisibility"
        class="absolute inset-y-0 right-0 pr-3 flex items-center text-sm leading-5 focus:outline-none"
      >
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

    <p v-if="errorMessage" class="mt-2 text-sm text-red-600">
      {{ errorMessage }}
    </p>
  </div>
</template>

<script>
export default {
  // `modelValue` es para v-model en Vue 3. En Vue 2 sería `value`.
  // `update:modelValue` es para v-model en Vue 3. En Vue 2 sería `input`.
  props: {
    id: {
      type: String,
      required: true
    },
    name: {
      type: String,
      default: ''
    },
    label: {
      type: String,
      default: ''
    },
    placeholder: {
      type: String,
      default: 'Ingresa tu contraseña'
    },
    modelValue: { // Para usar con v-model
      type: String,
      default: ''
    },
    errorMessage: { // Para mostrar errores de validación
      type: String,
      default: ''
    }
  },
  emits: ['update:modelValue'], // Declara el evento para v-model
  data() {
    return {
      passwordFieldType: 'password' // Inicia el campo como tipo 'password' (oculto)
    };
  },
  computed: {
    hasError() {
      return !!this.errorMessage; // Booleano para aplicar clases de error
    }
  },
  methods: {
    togglePasswordVisibility() {
      // Cambia el tipo del campo de entrada entre 'password' y 'text'
      this.passwordFieldType = this.passwordFieldType === 'password' ? 'text' : 'password';
    }
  }
};
</script>

<style scoped>
/*
  Si usas Tailwind CSS en tu proyecto globalmente,
  muchas de las clases aplicadas en el template
  ya proporcionarán el estilo necesario.

  Puedes añadir estilos específicos aquí si necesitas
  sobrescribir o añadir algo que Tailwind no cubra,
  o si no estás usando Tailwind globalmente para
  todos los elementos.

  Por ejemplo:
  .block { display: block; }
  .w-full { width: 100%; }
  .pr-10 { padding-right: 2.5rem; } // 40px
  .py-2 { padding-top: 0.5rem; padding-bottom: 0.5rem; } // 8px
  .border { border-width: 1px; }
  .border-gray-300 { border-color: #d1d5db; }
  .rounded-md { border-radius: 0.375rem; } // 6px
  .shadow-sm { box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05); }
  .placeholder-gray-400::placeholder { color: #9ca3af; }
  .focus:outline-none:focus { outline: 0; }
  .focus:ring-indigo-500:focus { --tw-ring-color: #6366f1; }
  .focus:border-indigo-500:focus { border-color: #6366f1; }
  .sm:text-sm { font-size: 0.875rem; line-height: 1.25rem; } // 14px, 20px
  .border-red-500 { border-color: #ef4444; }
  .relative { position: relative; }
  .absolute { position: absolute; }
  .inset-y-0 { top: 0; bottom: 0; }
  .right-0 { right: 0; }
  .pr-3 { padding-right: 0.75rem; } // 12px
  .flex { display: flex; }
  .items-center { align-items: center; }
  .leading-5 { line-height: 1.25rem; } // 20px
  .text-gray-400 { color: #9ca3af; }
  .h-5 { height: 1.25rem; } // 20px
  .w-5 { width: 1.25rem; } // 20px
  .text-red-600 { color: #dc2626; }
*/
</style>